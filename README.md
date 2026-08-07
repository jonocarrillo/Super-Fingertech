# Super Fingertech

Employee clock-in terminal for the LAN. Pure Python 3 stdlib (no pip install) — SQLite backend, cookie-based admin login, PIN-based kiosk clock-in/out.

## Features

- **Kiosk clock screen** (`/`) — employees punch with employee number in order:
  **In → Lunch out → Lunch in → Out** (hours exclude lunch)
- **Admin dashboard** (`/admin.html`) — manage employees, view/edit hours (password protected)
- **SQLite** with WAL mode and automatic daily backups
- **systemd unit** for 24/7 deployment

## Quick start

```bash
cd "~/Super Fingertech"
./start-lan.sh
```

Then open:

| Screen | URL |
|--------|-----|
| Clock kiosk | http://127.0.0.1:5050 |
| Admin | http://127.0.0.1:5050/admin.html |

### Friendly names (no IP typing)

On each PC that should use short names, add to `/etc/hosts` (Tailscale IP of banana):

```text
100.112.2.13   clock admin
```

Then open:

| Screen | URL |
|--------|-----|
| Clock kiosk | http://clock:5050/ |
| Admin | http://admin:5050/ |

(If port 80 is redirected to 5050 on the server, you can use `http://clock/` and `http://admin/` with no port.)

Default admin credentials (change these):

- User: `admin`
- Password: `clock`

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` / `CLOCK_DASHBOARD_PORT` | `5050` | HTTP port |
| `CLOCK_DASHBOARD_HOST` | `0.0.0.0` | Bind address |
| `CLOCK_DASHBOARD_USER` | `admin` | Admin username |
| `CLOCK_DASHBOARD_PASSWORD` | `clock` | Admin password |
| `CLOCK_SESSION_HOURS` | `168` | Admin session TTL (hours) |
| `CLOCK_AUTH_DISABLED` | off | Set `1` to disable admin login |
| `CLOCK_DASHBOARD_DB` | `data/timeclock.db` | SQLite path |
| `CLOCK_BACKUP_KEEP_DAYS` | `14` | Daily backup retention |

Example with a stronger password:

```bash
export CLOCK_DASHBOARD_PASSWORD='your-strong-password'
./start-lan.sh
```

## systemd (24/7)

```bash
sudo cp deploy/clock-terminal.service /etc/systemd/system/
# Edit User, WorkingDirectory, ReadWritePaths, and password env if needed
sudo systemctl daemon-reload
sudo systemctl enable --now clock-terminal
journalctl -u clock-terminal -f
```

## Layout

```
server.py          HTTP server + API
db.py              SQLite schema, queries, backups
start-lan.sh       Foreground launcher for this machine
views/             clock.html, admin.html, login.html
public/            style.css
data/              SQLite DB (created at runtime)
deploy/            systemd unit
```

## Notes

- Designed to run alongside a weighbridge data-entry app on a different port (default 5050 vs 5000).
- The kiosk is open on the LAN; only admin screens require login. Employees use their own PIN at the kiosk.
