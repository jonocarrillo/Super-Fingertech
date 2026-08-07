#!/usr/bin/env python3
"""Employee clock-in terminal - zero-dependency Python (stdlib only).

Runs alongside weighbridge-data-entry (Node) on its own port. Debian ships
Python 3 out of the box, so this needed no separate runtime install -
unlike Node, whose node:sqlite module requires a newer version than
Debian's own apt package provides.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from datetime import date, datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from zoneinfo import ZoneInfo

import db

PORT = int(os.environ.get("PORT") or os.environ.get("CLOCK_DASHBOARD_PORT") or 5050)
HOST = os.environ.get("CLOCK_DASHBOARD_HOST", "0.0.0.0")
PROJECT_ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = PROJECT_ROOT / "public"
VIEWS_DIR = PROJECT_ROOT / "views"
MAX_JSON_BYTES = 200_000
EMPLOYEE_NUMBER_RE = re.compile(r"^\d{1,8}$")
# Business-day timezone for daily / biweekly reports (TCMS-style attendance).
try:
    BIZ_TZ = ZoneInfo(os.environ.get("CLOCK_TZ", "America/Los_Angeles"))
except Exception:
    BIZ_TZ = timezone(timedelta(hours=-7))

# ---------- Admin login (cookie session) ----------
# Same pattern as weighbridge-data-entry: one password -> cookie session for the
# admin screens. The kiosk clock screen itself stays open on the LAN (employees
# identify themselves with their own PIN when clocking in/out).
#
# Env:
#   CLOCK_DASHBOARD_USER       default admin
#   CLOCK_DASHBOARD_PASSWORD   required for admin login (default clock)
#   CLOCK_SESSION_HOURS        default 168 (7 days)
#   CLOCK_AUTH_DISABLED=1      open admin access, no login
AUTH_DISABLED = os.environ.get("CLOCK_AUTH_DISABLED", "").lower() in ("1", "true", "yes")
AUTH_USER = (os.environ.get("CLOCK_DASHBOARD_USER") or "admin").strip() or "admin"
AUTH_PASSWORD = os.environ.get("CLOCK_DASHBOARD_PASSWORD") or ("" if AUTH_DISABLED else "clock")
AUTH_ENABLED = not AUTH_DISABLED and len(AUTH_PASSWORD) > 0
SESSION_TTL_MS = max(3600_000, int(float(os.environ.get("CLOCK_SESSION_HOURS", "168")) * 3600_000))
SESSION_COOKIE = "clock_session"
SESSION_SECRET = hashlib.sha256(f"clock-session|{AUTH_USER}|{AUTH_PASSWORD}|v1".encode()).digest()

# Friendly hostnames (map these in /etc/hosts or DNS to the server IP).
#   clock        → kiosk home page
#   admin        → admin dashboard home page
# Also matches clock.local / admin.local (mDNS-style) and short first labels
# of longer names (e.g. clock.tailnet.ts.net if you add those later).
CLOCK_HOSTS = frozenset({"clock", "kiosk", "clock.local", "kiosk.local"})
ADMIN_HOSTS = frozenset({"admin", "clock-admin", "admin.local", "clock-admin.local"})


def host_label(host_header: str) -> str:
    """Return lowercase hostname without port."""
    return (host_header or "").split(":")[0].strip().lower()


def is_admin_host(host: str) -> bool:
    if host in ADMIN_HOSTS:
        return True
    first = host.split(".")[0]
    return first in ("admin", "clock-admin")


def is_clock_host(host: str) -> bool:
    if host in CLOCK_HOSTS:
        return True
    first = host.split(".")[0]
    return first in ("clock", "kiosk")

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}


# ---------- base64url + session tokens ----------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def create_session_token(user: str) -> str:
    exp = int(time.time() * 1000) + SESSION_TTL_MS
    payload = f"{user}|{exp}"
    sig = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).digest()
    raw = f"{payload}|{b64url_encode(sig)}"
    return b64url_encode(raw.encode())


def verify_session_token(token: str):
    if not token:
        return None
    try:
        raw = b64url_decode(token).decode()
    except Exception:
        return None
    parts = raw.split("|")
    if len(parts) != 3:
        return None
    user, exp_str, sig_b64 = parts
    try:
        exp = int(exp_str)
    except ValueError:
        return None
    if not user or exp <= int(time.time() * 1000):
        return None
    payload = f"{user}|{exp}"
    expected_sig = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(b64url_encode(expected_sig), sig_b64):
        return None
    return {"user": user, "expires": exp, "auth": True}


def clean_text(value):
    if value is None:
        return None
    trimmed = str(value).strip()
    return trimmed or None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_iso(value):
    if not value:
        return None
    s = str(value)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def hours_between(start_iso: str, end_iso: str) -> float:
    try:
        start = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    if end < start:
        return 0.0
    return round((end - start).total_seconds() / 3600, 2)


def worked_hours(clock_in, lunch_out, lunch_in, clock_out):
    """Net hours worked, excluding lunch.

    Four-punch day:  IN → LUNCH OUT → LUNCH IN → OUT
      morning = IN → LUNCH OUT
      afternoon = LUNCH IN → OUT

    Legacy two-punch rows (no lunch fields): IN → OUT.
    """
    total = 0.0
    has_segment = False
    if clock_in and lunch_out:
        total += hours_between(clock_in, lunch_out)
        has_segment = True
    if lunch_in and clock_out:
        total += hours_between(lunch_in, clock_out)
        has_segment = True
    # Legacy / no lunch taken: single block IN → OUT
    if clock_in and clock_out and not lunch_out and not lunch_in:
        total = hours_between(clock_in, clock_out)
        has_segment = True
    if not has_segment:
        return None
    return round(total, 2)


def next_punch_action(entry) -> str:
    """Return the next punch for an open (or missing) day entry."""
    if entry is None:
        return "in"
    # sqlite3.Row supports dict-style keys
    if not entry["lunch_out_utc"]:
        return "lunch_out"
    if not entry["lunch_in_utc"]:
        return "lunch_in"
    if not entry["clock_out_utc"]:
        return "out"
    return "in"


def csv_escape(value) -> str:
    s = "" if value is None else str(value)
    if any(c in s for c in (",", '"', "\n")):
        return '"' + s.replace('"', '""') + '"'
    return s


# ---------- Employee + time entry helpers (operate on db.get_db(), caller holds db.lock()) ----------
def list_all_employees(conn):
    rows = conn.execute(
        "SELECT id, name, employee_number AS employeeNumber, active, created_at_utc AS createdAt "
        "FROM employees ORDER BY name COLLATE NOCASE;"
    ).fetchall()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "employeeNumber": r["employeeNumber"],
            "active": bool(r["active"]),
            "createdAt": r["createdAt"],
        }
        for r in rows
    ]


def find_employee(conn, employee_id):
    return conn.execute("SELECT * FROM employees WHERE id = ?;", (employee_id,)).fetchone()


def find_employee_by_number(conn, employee_number):
    return conn.execute("SELECT * FROM employees WHERE employee_number = ?;", (employee_number,)).fetchone()


def next_employee_number(conn) -> str:
    """Auto-assign the next free punch code (not managed as a separate admin field)."""
    row = conn.execute(
        "SELECT employee_number FROM employees WHERE employee_number GLOB '[0-9]*' "
        "ORDER BY CAST(employee_number AS INTEGER) DESC LIMIT 1;"
    ).fetchone()
    n = int(row["employee_number"]) + 1 if row else 1
    # skip collisions if any non-numeric gaps
    while find_employee_by_number(conn, str(n)):
        n += 1
    if n > 99_999_999:
        raise ValueError("no free employee numbers left")
    return str(n)


def open_entry_for(conn, employee_id):
    return conn.execute(
        "SELECT * FROM time_entries WHERE employee_id = ? AND clock_out_utc IS NULL "
        "ORDER BY clock_in_utc DESC LIMIT 1;",
        (employee_id,),
    ).fetchone()


def entry_to_dict(r, employee_name=None):
    clock_in = r["clockIn"] if "clockIn" in r.keys() else r["clock_in_utc"]
    lunch_out = r["lunchOut"] if "lunchOut" in r.keys() else r["lunch_out_utc"]
    lunch_in = r["lunchIn"] if "lunchIn" in r.keys() else r["lunch_in_utc"]
    clock_out = r["clockOut"] if "clockOut" in r.keys() else r["clock_out_utc"]
    name = employee_name if employee_name is not None else (r["employeeName"] if "employeeName" in r.keys() else None)
    hours = worked_hours(clock_in, lunch_out, lunch_in, clock_out)
    return {
        "id": r["id"],
        "employeeId": r["employeeId"] if "employeeId" in r.keys() else r["employee_id"],
        "employeeName": name,
        "clockIn": clock_in,
        "lunchOut": lunch_out,
        "lunchIn": lunch_in,
        "clockOut": clock_out,
        "note": r["note"] if "note" in r.keys() else None,
        "edited": bool(r["edited"]) if "edited" in r.keys() else False,
        "hours": hours,
        "status": (
            "complete"
            if clock_out
            else "at_lunch"
            if lunch_out and not lunch_in
            else "after_lunch"
            if lunch_in and not clock_out
            else "working"
            if clock_in
            else "unknown"
        ),
    }


def list_entries(conn, employee_id=None, date_from=None, date_to=None):
    clauses, params = [], []
    if employee_id:
        clauses.append("t.employee_id = ?")
        params.append(int(employee_id))
    if date_from:
        iso = to_iso(date_from)
        if iso:
            clauses.append("t.clock_in_utc >= ?")
            params.append(iso)
    if date_to:
        iso = to_iso(date_to)
        if iso:
            clauses.append("t.clock_in_utc <= ?")
            params.append(iso)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""
        SELECT t.id, t.employee_id AS employeeId, e.name AS employeeName,
               t.clock_in_utc AS clockIn, t.lunch_out_utc AS lunchOut,
               t.lunch_in_utc AS lunchIn, t.clock_out_utc AS clockOut,
               t.note AS note, t.edited AS edited
        FROM time_entries t
        JOIN employees e ON e.id = t.employee_id
        {where}
        ORDER BY t.clock_in_utc DESC;
        """,
        params,
    ).fetchall()
    return [entry_to_dict(r) for r in rows]


def summarize(entries):
    by_employee = {}
    for e in entries:
        if e["hours"] is None:
            continue
        cur = by_employee.setdefault(
            e["employeeId"], {"employeeId": e["employeeId"], "employeeName": e["employeeName"], "hours": 0.0, "shifts": 0}
        )
        cur["hours"] = round(cur["hours"] + e["hours"], 2)
        cur["shifts"] += 1
    return sorted(by_employee.values(), key=lambda s: s["employeeName"].lower())


def parse_date_param(value):
    """Parse YYYY-MM-DD to date, or None."""
    if not value:
        return None
    try:
        return date.fromisoformat(str(value).strip()[:10])
    except ValueError:
        return None


def iso_to_local_dt(iso: str):
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(BIZ_TZ)


def iso_to_local_date(iso: str):
    dt = iso_to_local_dt(iso)
    return dt.date() if dt else None


def fmt_local_time(iso: str) -> str:
    dt = iso_to_local_dt(iso)
    if not dt:
        return ""
    return dt.strftime("%I:%M %p").lstrip("0")


def fmt_local_datetime(iso: str) -> str:
    dt = iso_to_local_dt(iso)
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %I:%M %p").lstrip("0").replace(" 0", " ")


def day_bounds_utc(day: date):
    """Return (start_iso, end_iso) covering local business day in UTC Z form."""
    start = datetime(day.year, day.month, day.day, 0, 0, 0, tzinfo=BIZ_TZ)
    end = start + timedelta(days=1)
    start_utc = start.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    end_utc = end.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return start_utc, end_utc


def biweekly_range(period_end: date | None = None):
    """14-day pay window ending on period_end (default: today local)."""
    end = period_end or datetime.now(BIZ_TZ).date()
    start = end - timedelta(days=13)
    return start, end


def status_label(entry: dict) -> str:
    if entry.get("clockOut"):
        return "Complete"
    if entry.get("lunchOut") and not entry.get("lunchIn"):
        return "At lunch"
    if entry.get("lunchIn") and not entry.get("clockOut"):
        return "After lunch"
    if entry.get("clockIn"):
        return "Working"
    return "Incomplete"


def list_entries_for_local_range(conn, start_day: date, end_day: date, employee_id=None):
    """Entries whose clock-in falls on a local business day in [start_day, end_day]."""
    start_utc, _ = day_bounds_utc(start_day)
    _, end_utc = day_bounds_utc(end_day)
    # end_utc is midnight after end_day, so use < end_utc
    clauses = ["t.clock_in_utc >= ?", "t.clock_in_utc < ?"]
    params = [start_utc, end_utc]
    if employee_id:
        clauses.append("t.employee_id = ?")
        params.append(int(employee_id))
    where = "WHERE " + " AND ".join(clauses)
    rows = conn.execute(
        f"""
        SELECT t.id, t.employee_id AS employeeId, e.name AS employeeName,
               e.employee_number AS employeeNumber,
               t.clock_in_utc AS clockIn, t.lunch_out_utc AS lunchOut,
               t.lunch_in_utc AS lunchIn, t.clock_out_utc AS clockOut,
               t.note AS note, t.edited AS edited
        FROM time_entries t
        JOIN employees e ON e.id = t.employee_id
        {where}
        ORDER BY e.name COLLATE NOCASE, t.clock_in_utc;
        """,
        params,
    ).fetchall()
    result = []
    for r in rows:
        d = entry_to_dict(r)
        d["employeeNumber"] = r["employeeNumber"]
        d["workDate"] = (iso_to_local_date(d["clockIn"]) or start_day).isoformat()
        d["statusLabel"] = status_label(d)
        result.append(d)
    return result


def build_daily_report(conn, day: date, employee_id=None):
    """TCMS-style daily attendance detail for one business day."""
    entries = list_entries_for_local_range(conn, day, day, employee_id=employee_id)
    rows = []
    for e in entries:
        rows.append(
            {
                "date": e["workDate"],
                "employeeId": e["employeeId"],
                "employeeNumber": e.get("employeeNumber") or "",
                "employeeName": e["employeeName"],
                "clockIn": e["clockIn"],
                "lunchOut": e["lunchOut"],
                "lunchIn": e["lunchIn"],
                "clockOut": e["clockOut"],
                "clockInLocal": fmt_local_time(e["clockIn"]),
                "lunchOutLocal": fmt_local_time(e["lunchOut"]),
                "lunchInLocal": fmt_local_time(e["lunchIn"]),
                "clockOutLocal": fmt_local_time(e["clockOut"]),
                "hours": e["hours"],
                "status": e["statusLabel"],
                "note": e.get("note") or "",
                "edited": e.get("edited", False),
            }
        )
    total_hours = round(sum(r["hours"] or 0 for r in rows), 2)
    incomplete = sum(1 for r in rows if r["status"] != "Complete")
    return {
        "report": "daily",
        "title": "Daily Attendance Report",
        "date": day.isoformat(),
        "timezone": str(getattr(BIZ_TZ, "key", BIZ_TZ)),
        "rowCount": len(rows),
        "totalHours": total_hours,
        "incompleteCount": incomplete,
        "rows": rows,
    }


def build_biweekly_report(conn, period_end: date | None = None, employee_id=None):
    """Biweekly report: same row format as daily (In / Lunch out / Lunch in / Out)."""
    start, end = biweekly_range(period_end)
    entries = list_entries_for_local_range(conn, start, end, employee_id=employee_id)

    # Day-by-day rows — same columns as daily attendance
    rows = []
    for e in entries:
        rows.append(
            {
                "date": e["workDate"],
                "employeeId": e["employeeId"],
                "employeeNumber": e.get("employeeNumber") or "",
                "employeeName": e["employeeName"],
                "clockIn": e["clockIn"],
                "lunchOut": e["lunchOut"],
                "lunchIn": e["lunchIn"],
                "clockOut": e["clockOut"],
                "clockInLocal": fmt_local_time(e["clockIn"]),
                "lunchOutLocal": fmt_local_time(e["lunchOut"]),
                "lunchInLocal": fmt_local_time(e["lunchIn"]),
                "clockOutLocal": fmt_local_time(e["clockOut"]),
                "hours": e["hours"],
                "status": e["statusLabel"],
                "note": e.get("note") or "",
                "edited": e.get("edited", False),
            }
        )

    # Per-employee totals (footer / summary strip)
    by_emp = {}
    for r in rows:
        key = r["employeeId"]
        cur = by_emp.setdefault(
            key,
            {
                "employeeId": r["employeeId"],
                "employeeNumber": r["employeeNumber"],
                "employeeName": r["employeeName"],
                "daysWorked": 0,
                "completeDays": 0,
                "incompleteDays": 0,
                "hours": 0.0,
            },
        )
        cur["daysWorked"] += 1
        if r["status"] == "Complete":
            cur["completeDays"] += 1
        else:
            cur["incompleteDays"] += 1
        if r["hours"] is not None:
            cur["hours"] = round(cur["hours"] + r["hours"], 2)
    totals = sorted(by_emp.values(), key=lambda x: x["employeeName"].lower())
    total_hours = round(sum(t["hours"] for t in totals), 2)
    incomplete = sum(1 for r in rows if r["status"] != "Complete")
    return {
        "report": "biweekly",
        "title": "Biweekly Attendance Report",
        "periodStart": start.isoformat(),
        "periodEnd": end.isoformat(),
        "timezone": str(getattr(BIZ_TZ, "key", BIZ_TZ)),
        "rowCount": len(rows),
        "employeeCount": len(totals),
        "totalHours": total_hours,
        "incompleteCount": incomplete,
        "rows": rows,
        "totals": totals,
    }


def daily_report_csv(report: dict) -> str:
    lines = [
        f"# {report['title']}",
        f"# Date,{report['date']}",
        f"# Timezone,{report['timezone']}",
        f"# Total hours,{report['totalHours']}",
        "Date,Employee,In,Lunch Out,Lunch In,Out,Hours,Status,Note",
    ]
    for r in report["rows"]:
        emp_label = r["employeeName"]
        if r.get("employeeNumber"):
            emp_label = f"{r['employeeName']} (#{r['employeeNumber']})"
        lines.append(
            ",".join(
                csv_escape(v)
                for v in (
                    r["date"],
                    emp_label,
                    r["clockInLocal"],
                    r["lunchOutLocal"],
                    r["lunchInLocal"],
                    r["clockOutLocal"],
                    r["hours"] if r["hours"] is not None else "",
                    r["status"],
                    r["note"],
                )
            )
        )
    return "\n".join(lines) + "\n"


def biweekly_report_csv(report: dict, detail: bool = False) -> str:
    """Same punch columns as daily: Date, Employee, In, Lunch Out, Lunch In, Out, Hours, Status.

    detail=False still exports the day-by-day punch grid (consistent formatting).
    detail=True also appends a per-employee totals section at the bottom.
    """
    lines = [
        f"# {report['title']}",
        f"# Period,{report['periodStart']} to {report['periodEnd']}",
        f"# Timezone,{report['timezone']}",
        f"# Total hours,{report['totalHours']}",
        "Date,Employee,In,Lunch Out,Lunch In,Out,Hours,Status",
    ]
    for r in report["rows"]:
        emp_label = r["employeeName"]
        if r.get("employeeNumber"):
            emp_label = f"{r['employeeName']} (#{r['employeeNumber']})"
        lines.append(
            ",".join(
                csv_escape(v)
                for v in (
                    r["date"],
                    emp_label,
                    r["clockInLocal"],
                    r["lunchOutLocal"],
                    r["lunchInLocal"],
                    r["clockOutLocal"],
                    r["hours"] if r["hours"] is not None else "",
                    r["status"],
                )
            )
        )
    if detail and report.get("totals"):
        lines.append("")
        lines.append("# Employee totals")
        lines.append("Employee,Days Worked,Complete Days,Incomplete Days,Total Hours")
        for t in report["totals"]:
            emp_label = t["employeeName"]
            if t.get("employeeNumber"):
                emp_label = f"{t['employeeName']} (#{t['employeeNumber']})"
            lines.append(
                ",".join(
                    csv_escape(v)
                    for v in (
                        emp_label,
                        t["daysWorked"],
                        t["completeDays"],
                        t["incompleteDays"],
                        t["hours"],
                    )
                )
            )
    return "\n".join(lines) + "\n"


def send_csv_response(handler, filename: str, body: str):
    data = body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/csv; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.end_headers()
    handler.wfile.write(data)


class Handler(BaseHTTPRequestHandler):
    server_version = "ClockTerminal/1.0"

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    # ---------- low-level helpers ----------
    def send_json(self, status, obj, extra_headers=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                if v is not None:
                    self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status, message):
        self.send_json(status, {"error": message})

    def send_text(self, status, body: str, content_type="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_JSON_BYTES:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def get_session(self):
        if hasattr(self, "_session"):
            return self._session
        if not AUTH_ENABLED:
            self._session = {"user": "open", "auth": True}
            return self._session
        cookie_header = self.headers.get("Cookie")
        token = ""
        if cookie_header:
            jar = cookies.SimpleCookie()
            try:
                jar.load(cookie_header)
                if SESSION_COOKIE in jar:
                    token = jar[SESSION_COOKIE].value
            except Exception:
                token = ""
        self._session = verify_session_token(token)
        return self._session

    def is_logged_in(self):
        session = self.get_session()
        return bool(session and session.get("auth"))

    def session_cookie_header(self, token: str) -> str:
        max_age = SESSION_TTL_MS // 1000
        return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"

    def clear_session_cookie_header(self) -> str:
        return f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"

    def request_host(self) -> str:
        return host_label(self.headers.get("Host", ""))

    def is_public_path(self, path, method):
        if path == "/api/login" and method == "POST":
            return True
        if path == "/api/auth/status" and method == "GET":
            return True
        if path == "/api/status" and method == "GET":
            return True
        if path == "/api/clock" and method == "POST":
            return True
        if method == "GET":
            # Admin-named hosts treat "/" as the dashboard (requires login).
            if path == "/" and is_admin_host(self.request_host()):
                return False
            if path in ("/", "/clock.html", "/login", "/login.html", "/style.css"):
                return True
            if path.startswith("/public/"):
                return True
        return False

    def require_login(self, path, method):
        if not AUTH_ENABLED:
            return True
        if self.is_public_path(path, method):
            return True
        if self.is_logged_in():
            return True
        if method == "GET" and not path.startswith("/api/"):
            # Always send people back to the real dashboard path after login.
            # Using next=/ on the admin hostname used to look "broken" (blank /
            # vs /admin.html) and is easy to confuse with the kiosk.
            if path in ("/", "/admin", "/admin.html") or is_admin_host(self.request_host()):
                next_path = "/admin.html"
            else:
                next_path = path or "/admin.html"
            self.send_response(302)
            self.send_header("Location", "/login.html?next=" + next_path.replace(" ", "%20"))
            self.end_headers()
            return False
        self.send_error_json(401, "login required")
        return False

    def serve_file(self, file_path: Path):
        try:
            data = file_path.read_bytes()
        except OSError:
            self.send_error_json(404, "not found")
            return
        content_type = MIME.get(file_path.suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---------- dispatch ----------
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")

    def route(self, method):
        split = urlsplit(self.path)
        path = split.path
        query = parse_qs(split.query)

        if not self.require_login(path, method):
            return

        try:
            self.handle_route(method, path, query)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as err:  # noqa: BLE001 - surface as 500 instead of crashing the thread
            print(f"[error] {err}")
            try:
                self.send_error_json(500, str(err) or "internal error")
            except Exception:
                pass

    def handle_route(self, method, path, query):
        def qp(name):
            values = query.get(name)
            return values[0] if values else None

        with db.lock():
            conn = db.get_db()

            # ---- Auth ----
            if method == "GET" and path == "/api/auth/status":
                session = self.get_session()
                self.send_json(
                    200,
                    {"enabled": AUTH_ENABLED, "authenticated": bool(session and session.get("auth")), "user": session.get("user") if session else None},
                )
                return
            if method == "POST" and path == "/api/login":
                body = self.read_json_body()
                username = clean_text(body.get("username")) or AUTH_USER
                password = str(body.get("password") or "")
                if not AUTH_ENABLED:
                    self.send_json(200, {"ok": True})
                    return
                if not hmac.compare_digest(username, AUTH_USER) or not hmac.compare_digest(password, AUTH_PASSWORD):
                    self.send_error_json(401, "Invalid username or password")
                    return
                token = create_session_token(username)
                self.send_json(200, {"ok": True}, {"Set-Cookie": self.session_cookie_header(token)})
                return
            if method == "POST" and path == "/api/logout":
                self.send_json(200, {"ok": True}, {"Set-Cookie": self.clear_session_cookie_header()})
                return

            # ---- Status ----
            if method == "GET" and path == "/api/status":
                self.send_json(200, {"ok": True, "time": now_iso(), "db": db.db_stats(conn)})
                return

            # ---- Kiosk (public): 4 punches — IN → LUNCH OUT → LUNCH IN → OUT ----
            if method == "POST" and path == "/api/clock":
                body = self.read_json_body()
                employee_number = str(body.get("employeeNumber") or "").strip()
                if not EMPLOYEE_NUMBER_RE.fullmatch(employee_number):
                    self.send_error_json(400, "employeeNumber must be 1-8 digits")
                    return
                employee = find_employee_by_number(conn, employee_number)
                if not employee or not employee["active"]:
                    self.send_error_json(404, "employee number not recognized")
                    return
                open_entry = open_entry_for(conn, employee["id"])
                action = next_punch_action(open_entry)
                now = now_iso()
                labels = {
                    "in": "IN",
                    "lunch_out": "LUNCH OUT",
                    "lunch_in": "LUNCH IN",
                    "out": "OUT",
                }

                if action == "in":
                    cur = conn.execute(
                        "INSERT INTO time_entries (employee_id, clock_in_utc) VALUES (?, ?);",
                        (employee["id"], now),
                    )
                    conn.commit()
                    self.send_json(
                        200,
                        {
                            "action": "in",
                            "label": labels["in"],
                            "employeeName": employee["name"],
                            "clockIn": now,
                            "nextAction": "lunch_out",
                            "hours": None,
                        },
                    )
                    return

                entry_id = open_entry["id"]
                if action == "lunch_out":
                    conn.execute(
                        "UPDATE time_entries SET lunch_out_utc = ?, "
                        "updated_at_utc = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?;",
                        (now, entry_id),
                    )
                    conn.commit()
                    hours = worked_hours(open_entry["clock_in_utc"], now, None, None)
                    self.send_json(
                        200,
                        {
                            "action": "lunch_out",
                            "label": labels["lunch_out"],
                            "employeeName": employee["name"],
                            "clockIn": open_entry["clock_in_utc"],
                            "lunchOut": now,
                            "nextAction": "lunch_in",
                            "hours": hours,
                        },
                    )
                    return

                if action == "lunch_in":
                    conn.execute(
                        "UPDATE time_entries SET lunch_in_utc = ?, "
                        "updated_at_utc = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?;",
                        (now, entry_id),
                    )
                    conn.commit()
                    hours = worked_hours(
                        open_entry["clock_in_utc"], open_entry["lunch_out_utc"], now, None
                    )
                    self.send_json(
                        200,
                        {
                            "action": "lunch_in",
                            "label": labels["lunch_in"],
                            "employeeName": employee["name"],
                            "clockIn": open_entry["clock_in_utc"],
                            "lunchOut": open_entry["lunch_out_utc"],
                            "lunchIn": now,
                            "nextAction": "out",
                            "hours": hours,
                        },
                    )
                    return

                # action == "out"
                conn.execute(
                    "UPDATE time_entries SET clock_out_utc = ?, "
                    "updated_at_utc = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?;",
                    (now, entry_id),
                )
                conn.commit()
                hours = worked_hours(
                    open_entry["clock_in_utc"],
                    open_entry["lunch_out_utc"],
                    open_entry["lunch_in_utc"],
                    now,
                )
                self.send_json(
                    200,
                    {
                        "action": "out",
                        "label": labels["out"],
                        "employeeName": employee["name"],
                        "clockIn": open_entry["clock_in_utc"],
                        "lunchOut": open_entry["lunch_out_utc"],
                        "lunchIn": open_entry["lunch_in_utc"],
                        "clockOut": now,
                        "nextAction": "in",
                        "hours": hours,
                    },
                )
                return

            # ---- Admin: employees ----
            if method == "GET" and path == "/api/admin/employees":
                self.send_json(200, {"employees": list_all_employees(conn)})
                return
            if method == "POST" and path == "/api/admin/employees":
                body = self.read_json_body()
                name = clean_text(body.get("name"))
                if not name:
                    self.send_error_json(400, "name is required")
                    return
                # Punch code is auto-assigned; optional override only if client sends one.
                raw_num = str(body.get("employeeNumber") or "").strip()
                if raw_num:
                    if not EMPLOYEE_NUMBER_RE.fullmatch(raw_num):
                        self.send_error_json(400, "employee number must be 1-8 digits")
                        return
                    employee_number = raw_num
                else:
                    try:
                        employee_number = next_employee_number(conn)
                    except ValueError as err:
                        self.send_error_json(400, str(err))
                        return
                try:
                    cur = conn.execute(
                        "INSERT INTO employees (name, employee_number) VALUES (?, ?);", (name, employee_number)
                    )
                    conn.commit()
                except sqlite3.IntegrityError:
                    self.send_error_json(400, "that employee number is already in use")
                    return
                self.send_json(200, {"id": cur.lastrowid, "employeeNumber": employee_number, "name": name})
                return

            employee_match = re.fullmatch(r"/api/admin/employees/(\d+)", path)
            if employee_match and method == "PUT":
                employee_id = int(employee_match.group(1))
                employee = find_employee(conn, employee_id)
                if not employee:
                    self.send_error_json(404, "employee not found")
                    return
                body = self.read_json_body()
                name = clean_text(body.get("name")) or employee["name"]
                active = employee["active"] if body.get("active") is None else (1 if body.get("active") else 0)
                # Keep existing punch code unless explicitly changed (not shown as a separate admin field).
                employee_number = employee["employee_number"]
                if body.get("employeeNumber") is not None and str(body.get("employeeNumber")).strip() != "":
                    employee_number = str(body.get("employeeNumber")).strip()
                    if not EMPLOYEE_NUMBER_RE.fullmatch(employee_number):
                        self.send_error_json(400, "employee number must be 1-8 digits")
                        return
                try:
                    conn.execute(
                        "UPDATE employees SET name = ?, active = ?, employee_number = ?, "
                        "updated_at_utc = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?;",
                        (name, active, employee_number, employee_id),
                    )
                    conn.commit()
                except sqlite3.IntegrityError:
                    self.send_error_json(400, "that employee number is already in use")
                    return
                self.send_json(200, {"ok": True, "employeeNumber": employee_number})
                return
            if employee_match and method == "DELETE":
                employee_id = int(employee_match.group(1))
                conn.execute(
                    "UPDATE employees SET active = 0, updated_at_utc = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?;",
                    (employee_id,),
                )
                conn.commit()
                self.send_json(200, {"ok": True})
                return

            # ---- Admin: time entries ----
            if method == "GET" and path == "/api/admin/entries":
                entries = list_entries(conn, employee_id=qp("employeeId"), date_from=qp("from"), date_to=qp("to"))
                self.send_json(200, {"entries": entries, "summary": summarize(entries)})
                return

            entry_match = re.fullmatch(r"/api/admin/entries/(\d+)", path)
            if entry_match and method == "PUT":
                entry_id = int(entry_match.group(1))
                body = self.read_json_body()
                clock_in = to_iso(body.get("clockIn"))
                lunch_out = to_iso(body.get("lunchOut"))
                lunch_in = to_iso(body.get("lunchIn"))
                clock_out = to_iso(body.get("clockOut"))
                note = clean_text(body.get("note"))
                if not clock_in:
                    self.send_error_json(400, "clockIn is required")
                    return
                conn.execute(
                    """
                    UPDATE time_entries SET
                        clock_in_utc = ?, lunch_out_utc = ?, lunch_in_utc = ?, clock_out_utc = ?,
                        note = ?, edited = 1,
                        updated_at_utc = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                    WHERE id = ?;
                    """,
                    (clock_in, lunch_out, lunch_in, clock_out, note, entry_id),
                )
                conn.commit()
                self.send_json(200, {"ok": True})
                return
            if entry_match and method == "DELETE":
                entry_id = int(entry_match.group(1))
                conn.execute("DELETE FROM time_entries WHERE id = ?;", (entry_id,))
                conn.commit()
                self.send_json(200, {"ok": True})
                return

            if method == "GET" and path == "/api/admin/export.csv":
                entries = list_entries(conn, employee_id=qp("employeeId"), date_from=qp("from"), date_to=qp("to"))
                lines = ["Employee,In,Lunch Out,Lunch In,Out,Hours,Edited,Note"]
                for e in entries:
                    lines.append(
                        ",".join(
                            csv_escape(v)
                            for v in (
                                e["employeeName"],
                                e["clockIn"],
                                e["lunchOut"] or "",
                                e["lunchIn"] or "",
                                e["clockOut"] or "",
                                e["hours"] if e["hours"] is not None else "",
                                "yes" if e["edited"] else "",
                                e["note"] or "",
                            )
                        )
                    )
                body = "\n".join(lines)
                data = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Disposition", 'attachment; filename="time-entries.csv"')
                self.end_headers()
                self.wfile.write(data)
                return

            if method == "POST" and path == "/api/admin/backups/run":
                self.send_json(200, db.run_db_backup(force=True))
                return

            # ---- Admin: TCMS-style reports ----
            if method == "GET" and path in ("/api/admin/reports/daily", "/api/admin/reports/daily.csv"):
                day = parse_date_param(qp("date")) or datetime.now(BIZ_TZ).date()
                emp = qp("employeeId")
                report = build_daily_report(conn, day, employee_id=emp)
                if path.endswith(".csv"):
                    send_csv_response(
                        self,
                        f"daily-attendance-{day.isoformat()}.csv",
                        daily_report_csv(report),
                    )
                    return
                self.send_json(200, report)
                return

            if method == "GET" and path in (
                "/api/admin/reports/biweekly",
                "/api/admin/reports/biweekly.csv",
                "/api/admin/reports/biweekly-detail.csv",
            ):
                period_end = parse_date_param(qp("periodEnd") or qp("end") or qp("date"))
                emp = qp("employeeId")
                report = build_biweekly_report(conn, period_end=period_end, employee_id=emp)
                # Both CSV routes use the same In/Lunch out/Lunch in/Out grid;
                # *-detail.csv also appends employee totals at the bottom.
                if path.endswith(".csv"):
                    with_totals = path.endswith("biweekly-detail.csv")
                    kind = "detail" if with_totals else "report"
                    send_csv_response(
                        self,
                        f"biweekly-{kind}-{report['periodStart']}_to_{report['periodEnd']}.csv",
                        biweekly_report_csv(report, detail=with_totals),
                    )
                    return
                self.send_json(200, report)
                return

        # ---- Static views/assets (outside the db lock) ----
        if method == "GET":
            host = self.request_host()
            # Friendly hostname http://admin/ → real dashboard path
            if path == "/" and is_admin_host(host):
                self.send_response(302)
                self.send_header("Location", "/admin.html")
                self.end_headers()
                return
            if path in ("/", "/clock.html"):
                self.serve_file(VIEWS_DIR / "clock.html")
                return
            if path in ("/admin.html", "/admin"):
                self.serve_file(VIEWS_DIR / "admin.html")
                return
            if path in ("/login.html", "/login"):
                self.serve_file(VIEWS_DIR / "login.html")
                return
            if path == "/style.css":
                self.serve_file(PUBLIC_DIR / "style.css")
                return
            if path.startswith("/public/"):
                rel = path[len("/public/"):]
                file_path = (PUBLIC_DIR / rel).resolve()
                if PUBLIC_DIR.resolve() not in file_path.parents and file_path != PUBLIC_DIR.resolve():
                    self.send_error_json(403, "forbidden")
                    return
                self.serve_file(file_path)
                return

        self.send_error_json(404, "not found")


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Employee clock-in terminal listening on http://{HOST}:{PORT}")
    print(f"Friendly names (set in /etc/hosts or DNS):")
    print(f"  http://clock:{PORT}/       → kiosk")
    print(f"  http://admin:{PORT}/       → admin dashboard")
    print(f"Database: {db.resolve_database_path()}")
    print(f"Admin login: {'user=' + AUTH_USER if AUTH_ENABLED else 'DISABLED (open access)'}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
