# Changelog

All notable changes to Auto-Monitoring are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and versions follow semver.

## [1.1.1] - 2026-10-21

### Changed
- **Hardened systemd unit** (behavior-preserving): added `PrivateDevices`, `ProtectKernelTunables`,
  `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`,
  `ProtectHostname`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`,
  `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`, `CapabilityBoundingSet=` (empty),
  `SystemCallFilter=@system-service`, `SystemCallArchitectures=native`. `AF_NETLINK` is
  intentionally allowed so the `ss` child process keeps working; all directives were checked
  against the agent's real probe paths (read-only /proc and /sys, outbound HTTPS, journal files).

### Removed
- `compute_systemd_state()` — dead code since failed units moved to the debounced incident
  tracker in 1.1.0.
- 32-bit counter wrap handling (`COUNTER_WRAP_32`) — all supported targets are 64-bit where
  interface counters never wrap; a backwards counter is now always treated as a reset
  (selftest updated).

## [1.1.0] - 2026-10-21

Security and correctness revision (P0–P4). Full details in `REVISION-REPORT.md`.

### Security
- Symlink attacks on state/config paths blocked: `O_NOFOLLOW` lock open, lstat-verified
  no-follow chown, symlink refusal in `load_state`/`load_config`/`state_lock`, and root
  `check` drops privileges to the service user.
- Webhook bearer tokens require `https://`; HTTP redirects are refused (credentials are
  never forwarded to a redirect target); Telegram token redaction retained.
- Least privilege: service user no longer joins `adm` (systemd-journal only);
  `/etc/auto-monitoring` is root-owned, `config.ini` `root:auto-monitoring 0640`; installer
  repairs older layouts.
- Token prompts hidden via `getpass`; secrets redacted from error logs.

### Fixed (data loss / correctness)
- Per-probe exception isolation; state saved in `finally` (a mid-cycle crash can no longer
  discard window/cursor/outbox updates); alert delivery catches all exceptions.
- `load_state`: transient `OSError` (EIO/EMFILE) skips the cycle without touching the file;
  only true corruption (JSON/schema) triggers backup-and-reset.
- SSH counting: one count per attempt (preauth "Invalid user" and "max auth attempts" lines
  excluded); source IP taken from the LAST `from <ip> port <N>` occurrence — spoofed
  usernames can no longer mis-attribute attacks.
- Traffic counted on physical interfaces only by default (`traffic_physical_only`), fixing
  double-counting on bonds/VLANs/WireGuard/libvirt.
- Listening-port keys normalized between `ss` and the /proc/net fallback (`*:22` form);
  legacy state re-normalized on load; no bogus "port changed" alerts.
- `cpu_usage_percent` returns None on negative idle deltas instead of a false 100%.
- statvfs on hung mounts runs with a hard timeout; failed mounts stay listed (no silent
  incident pruning) and count as probe failures.
- Journal re-anchor no longer silent: a "Journal Gap" alert fires; all external commands
  run with `LC_ALL=C`.

### Added
- Self-monitoring: "probe blind" / "probe recovered" alerts after N consecutive failures.
- systemd watchdog (`WatchdogSec=15min`) fed via raw-socket sd_notify, chunked pings in the
  sleep loop.
- Container awareness (Docker/Podman/LXC/K8s detection, lxcfs check, cgroup quota-aware
  load%).
- Swap thrashing detection via pswpin/pswpout rate (`swap_rate_pages_per_s`).
- Debounces: NTP desync (3 samples + 300s boot grace) and systemd failed units.
- Port ignore patterns (`port_ignore_patterns`) and network error threshold
  (`network_error_min`).
- Installer: `uninstall` command, rollback on failure, `--auto-install-deps` consent gate,
  `--force`, `--version`, Python ≥3.8 and systemd-PID-1 checks, feature-aware prerequisite
  checks, loud warning for `stdout` backend in non-interactive installs, non-zero exit when
  the post-install test alert fails.

### Removed
- Automatic package installation without consent; pacman/apk auto-install support (manual
  instructions instead); Alpine from the supported list (no systemd).

## [1.0.0] - 2026-10-16

Initial single-file agent: resource monitoring (CPU/load/RAM/swap/disk/inode) with debounced
incidents, daily traffic accounting, network error windows, SSH failure summaries with bounded
state, OOM detection, systemd failed-unit tracking, reboot detection, NTP checks, listening-port
change detection (`ss` + /proc fallback), crash-safe state persistence with flock, persistent
alert outbox with exponential backoff (stdout/Telegram/webhook), and an interactive systemd
installer with dedicated service user.
