#!/usr/bin/env bash
# Run the employee clock-in terminal in THIS terminal (foreground).
# Uses a different port than weighbridge-data-entry (5000) so both can run
# on the same machine at the same time. Pure Python stdlib - no install needed.
#
#   cd "~/Super Fingertech"
#   ./start-lan.sh

set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-${CLOCK_DASHBOARD_PORT:-5050}}"

# Admin login (protects employee management + hours editing). Employees clocking
# in/out at the kiosk use their own 4-digit PIN instead — no admin login needed there.
export CLOCK_DASHBOARD_USER="${CLOCK_DASHBOARD_USER:-admin}"
export CLOCK_DASHBOARD_PASSWORD="${CLOCK_DASHBOARD_PASSWORD:-clock}"
export CLOCK_SESSION_HOURS="${CLOCK_SESSION_HOURS:-168}"
# CLOCK_AUTH_DISABLED=1  → no admin login

PYTHON_BIN="$(command -v python3 || true)"
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "ERROR: python3 not found."
  exit 1
fi

if [[ ! -f server.py ]]; then
  echo "ERROR: server.py not found in $(pwd)"
  exit 1
fi

stop_old_servers() {
  local p cmd
  for p in $(pgrep -f "Super Fingertech.*server.py" 2>/dev/null || true); do
    kill "$p" 2>/dev/null || true
  done
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true
  elif command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(lsof -tiTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null || true)"
    if [[ -n "${pids}" ]]; then
      # shellcheck disable=SC2086
      kill ${pids} 2>/dev/null || true
    fi
  fi
}

port_in_use() {
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | grep -qE ":${PORT}\\s"
  else
    return 1
  fi
}

stop_old_servers
for _ in 1 2 3 4 5 6; do
  port_in_use || break
  sleep 0.5
  stop_old_servers
done
if port_in_use; then
  echo "ERROR: port ${PORT} is still in use after stopping old servers."
  echo "  Try:  ss -tlnp | grep ${PORT}"
  exit 1
fi

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "=============================================="
echo "  Employee clock-in terminal — HOST TERMINAL"
echo "  Keep this window open. Ctrl+C to stop."
echo "----------------------------------------------"
echo "  This PC:  http://127.0.0.1:${PORT}"
if [ -n "${LAN_IP}" ]; then
  echo "  LAN:      http://${LAN_IP}:${PORT}"
fi
echo "  Admin:    http://127.0.0.1:${PORT}/admin.html"
echo "  Python:   ${PYTHON_BIN} ($(${PYTHON_BIN} --version 2>&1))"
echo "  Folder:   $(pwd)"
echo "=============================================="
echo

exec "${PYTHON_BIN}" server.py
