# 🛡️ Auto-Monitoring System

### ❕ A lightweight, zero-dependency, anti-spam monitoring agent for Linux servers.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![Systemd](https://img.shields.io/badge/systemd-integrated-brightgreen.svg)
![Zero Dependency](https://img.shields.io/badge/dependencies-0-success.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

Designed for DevOps engineers who hate alert fatigue. Auto-Monitoring tracks critical host metrics and operational events, utilizing smart persistence and cooldown logic to ensure you only get notified when something is actually broken. It monitors itself too: a blind probe or a hung daemon is alerted or restarted, never silent.

> **Supported platforms:** any Linux distribution running systemd as PID 1 (Debian/Ubuntu, RHEL/CentOS/Alma/Rocky/Fedora, openSUSE). Alpine Linux is not supported (no systemd). On Arch, dependencies must be installed manually — the agent never runs `pacman -Sy` to avoid partial upgrades.

---

## 🚀 Quick Start

Run the interactive installer. It takes less than 60 seconds.

```bash
sudo python3 Auto-Monitoring.py install
```

*The installer checks prerequisites, configures thresholds, creates the `systemd` service with a hardened sandbox, and applies least-privilege permissions.*

**All CLI commands:**

| Command | Purpose |
| :--- | :--- |
| `install` | Interactive installation (systemd unit, user, config) |
| `uninstall` | Remove the service and `/opt` copy (keeps config and state for review) |
| `run` | Start the monitoring daemon (used by the systemd unit) |
| `check` | Run one monitoring cycle and exit (auto-drops to the service user when run as root) |
| `test-alert` | Send one test alert through the configured backend |
| `selftest` | Run the built-in deterministic test suite (no root/network needed) |

**Installer flags:**

| Flag | Purpose |
| :--- | :--- |
| `-y`, `--non-interactive` | Install with existing or default settings, no prompts |
| `--auto-install-deps` | Explicitly consent to installing missing packages (apt/dnf/zypper only) |
| `--force` | Continue even if the test alert fails or the backend is `stdout` |
| `--version` | Show agent version and state schema version |

---

## 📱 Visual Proof: What You See

*Clean, actionable, and visually clear alerts delivered directly to your Telegram or Webhook.*

**🔥 Resource Alert (Threshold Breached)**
> [WARNING] CPU ALERT
> Host: production-web-01
> Time: 2026-10-12T15:30:00Z
>
> cpu reached 92.5% above threshold 80%

**✅ Service Recovery**
> [INFO] CPU RESOLVED
> Host: production-web-01
> Time: 2026-10-12T15:45:00Z
>
> cpu recovered below 80%

**💀 Event Detection**
> [CRITICAL] 💀 OOM Detected
> Host: database-primary
> Time: 2026-10-12T02:14:12Z
>
> kernel: Out of memory: Killed process 1234 (python3) total-vm...

---

## 🧠 The Mental Model: Anti-Spam Logic

We built this agent to respect your sleep. It uses stateful tracking to filter out temporary spikes.

*   **Persistence (The Delay):** A CPU spike to 100% for 5 seconds isn't an emergency. The system requires multiple consecutive bad samples (e.g., 3 cycles = 6 minutes) before elevating an incident to `Active`. This debounce also applies to systemd failed units and NTP desynchronization.
*   **Suppression (The Silence):** Once an incident is `Active`, duplicate alerts are suppressed. You get one notification, not a flood.
*   **Recovery (The All-Clear):** An issue is only marked `Resolved` when the resource stays continuously healthy for a full Recovery Window (e.g., 10 continuous minutes).
*   **Boot Grace:** After a reboot, NTP checks wait 5 minutes before judging time synchronization — a normal boot never emits a "Problem + Restored" pair.

---

## ⚙️ Capabilities & Default Configurations

All settings are interactively configured during setup and saved to `/etc/auto-monitoring/config.ini`. The file is re-read **every monitoring cycle** — edits apply without restarting the service.

### Resource Thresholds
| Feature | Default | Description |
| :--- | :--- | :--- |
| 🧠 **CPU / Load** | `80%` | Monitors sustained high CPU utilization and load averages. |
| 💾 **RAM** | `80%` | Detects memory starvation. |
| 🔄 **Swap** | `80%` | Alerts on high swap space usage. |
| 🔁 **Swap Activity** | `500 pages/s` | Alerts on real swap thrashing (pswpin/pswpout rate), separate from sticky swap usage. |
| 💽 **Disk Space** | `80%` | Tracks filesystem capacity across standard mounts. |
| 📁 **Inodes** | `80%` | Prevents "No space left on device" errors due to inode exhaustion. |

*   *Polling Interval:* `120s` | *Persistence:* `3 samples` | *Recovery:* `10 mins`

### Aggregation & Events
| Feature | Default Logic | Description |
| :--- | :--- | :--- |
| 📊 **Network Traffic** | `300 GB / day` | Daily RX/TX quotas — **physical interfaces only by default** (see migration note below). |
| 🌐 **Net Errors** | `12h window`, min 10 events | Aggregates packet errors and drops; single-packet noise is suppressed (`network_error_min`). |
| 🔐 **SSH Failures** | `12h window` | Failed logins and top 5 source IPs; counts each attempt once and is resistant to spoofed usernames in sshd logs. |
| 💀 **OOM Killer** | `Immediate` | Instantly detects Linux Out-Of-Memory events via journald. |
| ⚙️ **Systemd** | `Debounced` | Flags services that remain in a `failed` state (3 samples). |
| 🕐 **Time Sync** | `Debounced` | Alerts if NTP synchronization drops (3 samples + boot grace). |
| 🔌 **Ports** | `Immediate` | Identifies newly opened/closed TCP/UDP listening ports; ignore list configurable (`port_ignore_patterns`). |

### Monitoring Options (new in 1.1.x)
| Key | Default | Description |
| :--- | :--- | :--- |
| `traffic_physical_only` | `true` | Count traffic only on interfaces with a physical device (bonds, VLANs, WireGuard, tailscale, libvirt bridges are virtual layers over a parent NIC — summing both double-counts). |
| `port_ignore_patterns` | *(empty)* | Comma-separated fnmatch patterns for port keys, e.g. `tcp *:5432,udp *:5353`. |
| `network_error_min` | `10` | Minimum total errors/drops per window before a report is sent. |
| `ignore_interfaces` | `lo,docker*,veth*,br-*` | Interfaces excluded from all network accounting. |
| `udp_ephemeral_port_min` | `0` (auto) | UDP ports above this are treated as ephemeral; `65536` tracks all UDP (e.g. WireGuard). |

---

## 🔐 Security & Hardening

* **Least privilege:** the `auto-monitoring` system user has no shell and only the `systemd-journal` supplementary group — it reads journals, not `/var/log/*`.
* **Immutable config:** `/etc/auto-monitoring/` is `root:root 0755` and `config.ini` is `root:auto-monitoring 0640`. A compromised service can read its config but never rewrite it. `state.json` stays service-owned in `/var/lib/auto-monitoring/` (mode 0750).
* **Symlink-proof state handling:** lock files, state, and config are opened with `O_NOFOLLOW` and ownership changes never follow symlinks; a root-run `check` drops privileges to the service user before touching state files.
* **Credential safety:** a webhook bearer token requires `https://`; HTTP redirects are refused so credentials are never forwarded cross-host; tokens are redacted from logs and hidden during prompting (`getpass`).
* **Sandboxed systemd unit:** `NoNewPrivileges`, `ProtectSystem=full`, `ProtectKernel*`, `ProtectClock/Hostname`, `PrivateTmp/PrivateDevices`, `CapabilityBoundingSet=` (empty), `RestrictAddressFamilies` (netlink kept for `ss`), `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, and `WatchdogSec=15min` — the daemon pings the watchdog; if it ever hangs, systemd restarts it instead of leaving a blind "active" unit.
* **Self-monitoring:** after N consecutive probe failures the agent alerts that it is blind (and again when it recovers); a hung mount is skipped with a warning instead of blocking the cycle.

---

## ⚠️ Upgrading from pre-1.1.0

* **Traffic accounting changed:** traffic is now counted on physical interfaces only. On your first post-upgrade day the totals will look smaller — that is the fix for double-counting, not data loss. Set `traffic_physical_only = false` in `[monitoring]` to restore the legacy behavior.
* **Port keys normalized:** wildcard listeners (`0.0.0.0:22`, `[::]:443`) are stored as `*:22` / `*:443`; existing state is migrated automatically and no bogus "port changed" alert fires.
* **Installer permissions:** re-running `install` repairs older layouts (removes the `adm` group membership and re-owns `/etc/auto-monitoring` to root).
* **New installer behavior:** missing packages are *reported* and abort the install unless you pass `--auto-install-deps`; the post-install test alert must succeed (or use `--force`).

---

## 🛠️ Troubleshooting Cheatsheet

Need to debug? Copy and paste these commands.

**Check service health:**
```bash
systemctl status auto-monitoring
```

**View live monitoring logs (follow mode):**
```bash
journalctl -u auto-monitoring -f
```

**Force a manual health check cycle:**
```bash
sudo /usr/bin/python3 /opt/auto-monitoring/Auto-Monitoring.py check
```

**Test your Telegram/Webhook integration:**
```bash
sudo /usr/bin/python3 /opt/auto-monitoring/Auto-Monitoring.py test-alert
```

**Verify the agent's own test suite passes on this host:**
```bash
/usr/bin/python3 /opt/auto-monitoring/Auto-Monitoring.py selftest
```

**Restart the agent (e.g., after a config edit):**
```bash
sudo systemctl restart auto-monitoring
```
*Config edits do not strictly require a restart — the daemon re-reads the config every cycle. A restart only guarantees an immediate reload.*

**Remove everything (service + /opt copy):**
```bash
sudo python3 Auto-Monitoring.py uninstall
```
*Keeps `/etc/auto-monitoring/config.ini` and `/var/lib/auto-monitoring/` for review; remove them manually if no longer needed.*
