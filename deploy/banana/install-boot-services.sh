#!/bin/bash
# Install / refresh banana boot services so clock + weighbridge + names
# come back after reboot or power loss.
#
# Run on banana as americanindustrial (passwordless sudo):
#   bash ~/Super-Fingertech/deploy/banana/install-boot-services.sh
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Run as americanindustrial (script uses sudo), not as root." >&2
  exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== install boot services from $DIR ==="
echo "host=$(hostname) user=$(whoami) $(date -Is)"

need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
need systemctl
need sudo
need python3
[[ -x /home/americanindustrial/.local/node/bin/node ]] || { echo "missing node binary" >&2; exit 1; }
[[ -f /home/americanindustrial/Super-Fingertech/server.py ]] || { echo "missing Super-Fingertech" >&2; exit 1; }
[[ -f /home/americanindustrial/weighbridge-data-entry/server.js ]] || { echo "missing weighbridge" >&2; exit 1; }

echo "=== install unit files ==="
sudo cp "$DIR/clock-terminal.service" /etc/systemd/system/clock-terminal.service
sudo cp "$DIR/weighbridge.service" /etc/systemd/system/weighbridge.service
sudo cp "$DIR/mdns-name@.service" /etc/systemd/system/mdns-name@.service
sudo cp "$DIR/banana-apps.target" /etc/systemd/system/banana-apps.target

echo "=== nginx drop-in (start after backends) ==="
sudo mkdir -p /etc/systemd/system/nginx.service.d
sudo cp "$DIR/nginx-banana-apps.conf" /etc/systemd/system/nginx.service.d/banana-apps.conf

echo "=== disable obsolete socat port-80 proxy (nginx owns :80) ==="
sudo systemctl disable --now clock-http-proxy.service 2>/dev/null || true
sudo systemctl mask clock-http-proxy.service 2>/dev/null || true

echo "=== retire old one-off mDNS units (replaced by mdns-name@.service) ==="
for u in clock-mdns.service admin-mdns.service supercluster-mdns.service; do
  sudo systemctl disable --now "$u" 2>/dev/null || true
done

echo "=== daemon-reload ==="
sudo systemctl daemon-reload

echo "=== enable core stack for multi-user boot ==="
# Network / remote access
sudo systemctl enable NetworkManager.service NetworkManager-wait-online.service
sudo systemctl enable ssh.service
sudo systemctl enable tailscaled.service
sudo systemctl enable avahi-daemon.service

# Apps + reverse proxy
sudo systemctl enable clock-terminal.service
sudo systemctl enable weighbridge.service
sudo systemctl enable nginx.service
sudo systemctl enable mdns-name@clock.service
sudo systemctl enable mdns-name@admin.service
sudo systemctl enable mdns-name@supercluster.service
sudo systemctl enable banana-apps.target

echo "=== start / restart stack now ==="
sudo systemctl restart avahi-daemon.service
sudo systemctl restart clock-terminal.service
sudo systemctl restart weighbridge.service
sudo systemctl restart mdns-name@clock.service mdns-name@admin.service mdns-name@supercluster.service
sudo systemctl restart nginx.service
sudo systemctl start banana-apps.target

echo
echo "=== status ==="
ok=0
fail=0
for u in \
  ssh.service tailscaled.service NetworkManager.service avahi-daemon.service \
  clock-terminal.service weighbridge.service nginx.service \
  mdns-name@clock.service mdns-name@admin.service mdns-name@supercluster.service \
  banana-apps.target
do
  en=$(systemctl is-enabled "$u" 2>/dev/null || echo unknown)
  ac=$(systemctl is-active "$u" 2>/dev/null || echo unknown)
  printf "  %-36s enabled=%-10s active=%s\n" "$u" "$en" "$ac"
  if [[ "$ac" == "active" || "$ac" == "active" ]]; then
    ok=$((ok+1))
  else
    # targets report active when reached
    if [[ "$u" == *.target && "$ac" == "active" ]]; then ok=$((ok+1)); else fail=$((fail+1)); fi
  fi
done

echo
echo "=== quick HTTP checks (localhost) ==="
curl -sS -m 3 -o /dev/null -w "clock  :5050 -> %{http_code}\n" http://127.0.0.1:5050/ || echo "clock :5050 FAIL"
curl -sS -m 3 -o /dev/null -w "weigh  :5000 -> %{http_code}\n" http://127.0.0.1:5000/ || echo "weigh :5000 FAIL"
curl -sS -m 3 -H 'Host: clock.local' -o /dev/null -w "nginx clock.local -> %{http_code}\n" http://127.0.0.1/ || echo "nginx FAIL"
curl -sS -m 3 -H 'Host: supercluster.local' -o /dev/null -w "nginx supercluster.local -> %{http_code}\n" http://127.0.0.1/ || echo "nginx supercluster FAIL"

echo
echo "=== boot default ==="
systemctl get-default
echo
echo "DONE. All listed units are enabled for multi-user boot."
echo "After power loss: machine must also be set in BIOS to 'Power On' after AC restore"
echo "(Lenovo ThinkCentre: Startup / Power / Automatic Power On / After Power Loss = Power On)."
echo
echo "Optional reboot test:  sudo reboot"
