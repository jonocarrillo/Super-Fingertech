# Banana boot deploy (power-loss safe)

These systemd units make the **active LAN apps** start automatically whenever
banana boots — including after a power outage (once the PC turns itself back on).

## Apps covered

| Name | URL / port | Unit |
|------|------------|------|
| Time clock | `http://clock.local` → `:5050` | `clock-terminal.service` |
| Clock admin | `http://admin.local` → same app | (same) + `mdns-name@admin` |
| Weighbridge | `http://supercluster.local` → `:5000` | `weighbridge.service` |
| Reverse proxy | LAN port **80** | `nginx.service` |
| mDNS names | `*.local` | `mdns-name@*.service` |
| Remote access | SSH + Tailscale | `ssh`, `tailscaled` |

Meta unit: **`banana-apps.target`** (enabled; pulls the stack in on boot).

## Install / refresh on banana

```bash
cd ~/Super-Fingertech
# copy latest deploy files, then:
bash deploy/banana/install-boot-services.sh
```

## After power loss checklist

1. **BIOS / UEFI** (one-time): set **After Power Loss / AC Recovery = Power On**
   so the ThinkCentre actually turns back on when electricity returns.
2. **systemd** (this deploy): services are `enabled` + `Restart=always`.
3. Wait ~30–60s after boot for network + mDNS + nginx.

## Status commands

```bash
systemctl status banana-apps.target
systemctl is-enabled clock-terminal weighbridge nginx 'mdns-name@clock'
journalctl -u clock-terminal -u weighbridge -u nginx -b --no-pager | tail -50
```
