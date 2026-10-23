#!/usr/bin/env python3
"""Lightweight Linux host monitor and alerting agent.

This module intentionally stays free of third-party Python packages and focuses
on Linux host health. It provides:
  - Resource monitoring (CPU tick deltas, per-core load average, RAM, swap,
    filesystem block usage, and inode usage) with debounced incident tracking.
  - Network traffic daily accounting and error/drop window aggregation.
  - Journal-cursor based SSH authentication failure summaries and kernel OOM
    detection with bounded memory and state size.
  - Systemd failed-unit tracking, reboot detection, NTP synchronization checks,
    and listening TCP/UDP port change detection (via `ss` with a pure-Python
    `/proc/net/*` fallback).
  - Crash-safe atomic JSON state persistence (including parent directory fsync),
    exclusive flock synchronization, and a persistent alert outbox with
    exponential backoff retry.
  - Automated prerequisite verification for major Linux distributions running
    systemd (Debian/Ubuntu, RHEL/CentOS/Alma/Rocky/Fedora, and openSUSE), with
    optional consent-gated package installation. Arch/pacman is detected but
    never auto-installed (partial-upgrade risk); Alpine is unsupported because
    it does not ship systemd.
  - Hardened against symlink attacks on state/config paths (O_NOFOLLOW, lstat
    verification, no-follow chown), systemd watchdog integration (sd_notify),
    and per-probe blindness alerts so a failed probe is never silent.
"""
from __future__ import annotations

import argparse
import configparser
import errno
import fcntl
import fnmatch
import functools
import getpass
import grp
import ipaddress
import json
import logging
import os
import pwd
import re
import shutil
import signal
import socket
import ssl
import stat as stat_module
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, NamedTuple, Sequence

# --------------------------------------------------------------------------
# Global paths and constants
# --------------------------------------------------------------------------
NAME = "auto-monitoring"
AGENT_VERSION = "1.1.1"
SERVICE_NAME = f"{NAME}.service"
INSTALL_ROOT = Path("/opt/auto-monitoring")
ETC_ROOT = Path("/etc/auto-monitoring")
CONFIG_PATH = ETC_ROOT / "config.ini"
STATE_DIR = Path("/var/lib/auto-monitoring")
STATE_PATH = STATE_DIR / "state.json"
LOCK_PATH = STATE_DIR / "state.lock"

STATE_SCHEMA_VERSION = 2
LOCK_TIMEOUT_SECONDS = 60

# systemd watchdog: the unit sets WatchdogSec=15min and the daemon pings
# WATCHDOG=1 at least every WATCHDOG_PING_SECONDS while alive. A hung cycle
# (e.g. blocked statvfs) makes systemd kill and restart the service instead of
# leaving a blind "active" unit.
WATCHDOG_SEC_TEXT = "15min"
WATCHDOG_PING_SECONDS = 300

# Grace period after boot before NTP-desynchronization alerts fire, so a
# normal boot does not emit a "not synchronized" + "restored" alert pair while
# chronyd/systemd-timesyncd is still converging.
NTP_BOOT_GRACE_SECONDS = 300

# Hard timeout for statvfs on a single mount: hung network filesystems must
# not block the whole monitoring cycle.
MOUNT_PROBE_TIMEOUT_SECONDS = 10.0

# Standard system binary directories to ensure tools like `ss`, `useradd`, and
# `systemctl` are discoverable even under restricted `su` or `sudo` PATHs.
STANDARD_SBIN_PATHS = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)


def ensure_standard_path() -> None:
    """Ensure standard Linux bin/sbin directories are present in PATH.

    Called from `main()` and `ensure_dependencies()` rather than at import time
    to avoid global environment side effects when the module is imported by tests.
    """
    current = os.environ.get("PATH", "")
    parts = [p for p in current.split(os.pathsep) if p]
    for directory in STANDARD_SBIN_PATHS:
        if directory not in parts:
            parts.append(directory)
    os.environ["PATH"] = os.pathsep.join(parts)


def get_cpu_count() -> int:
    """Return the current number of usable CPU cores (respecting dynamic cgroup/affinity)."""
    try:
        if hasattr(os, "sched_getaffinity"):
            affinity_count = len(os.sched_getaffinity(0))
            if affinity_count > 0:
                return affinity_count
    except OSError:
        pass
    return os.cpu_count() or 1


# Alert outbox limits and exponential backoff parameters.
OUTBOX_MAX_ITEMS = 100
OUTBOX_MAX_AGE_SECONDS = 24 * 3600
OUTBOX_BACKOFF_BASE_SECONDS = 30
OUTBOX_BACKOFF_MAX_SECONDS = 1800
ALERT_MAX_CHARS = 4000

# SSH aggregation: bound the number of distinct source IPs stored in state.json
# so a distributed brute-force attack cannot bloat disk or memory.
SSH_MAX_TRACKED_SOURCES = 2000
SSH_TOP_SOURCES = 5

# Maximum journal entries read in a single cycle to prevent memory exhaustion
# or repeated timeouts after long downtime or log floods.
JOURNAL_MAX_ENTRIES_PER_CYCLE = 10000

DEFAULT_EPHEMERAL_PORT_START = 32768
NETWORK_ERROR_KEYS = ("rx_errors", "tx_errors", "rx_drops", "tx_drops")

# Only canonical per-attempt sshd failure lines are counted. The "Invalid user
# <u> from <ip>" preauth line and the trailing "maximum authentication attempts
# exceeded" line accompany the same attempt and would double-count it.
SSH_FAILURE_LINE_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?|none) for (?:invalid user )?\S+ from"
)
# sshd logs usernames verbatim (no escaping/quotes), so a crafted username like
# "x from 8.8.8.8 port 22" injects a fake "from <ip> port <N>" earlier in the
# line. The genuine source is always the LAST occurrence, emitted by sshd
# itself, so anchor on "from <ip> port <digits>" and take the final match.
SSH_FROM_PORT_RE = re.compile(r"\bfrom\s+([0-9a-fA-F:.]+)\s+port\s+\d+")
MOUNT_ESCAPE_RE = re.compile(r"\\([0-7]{3})")
TELEGRAM_TOKEN_REDACT_RE = re.compile(r"(https://api\.telegram\.org/bot)[^/\s]+")

# Filesystems that are pseudo, read-only images, per-container, or network
# mounts that may block indefinitely inside statvfs() when the remote hangs.
# Note: `overlay` is allowed when mounted on `/` (see `parse_mounts`) so hosts
# or containers with an overlayfs root filesystem still get root disk checks.
EXCLUDED_FSTYPES = frozenset(
    {
        "9p", "afs", "autofs", "bpf", "binfmt_misc", "ceph", "cephfs", "cgroup",
        "cgroup2", "cifs", "configfs", "debugfs", "devpts", "devtmpfs", "efivarfs",
        "erofs", "fusectl", "glusterfs", "hugetlbfs", "iso9660", "lustre",
        "mqueue", "nfs", "nfs4", "nsfs", "overlay", "aufs", "proc", "pstore",
        "ramfs", "rpc_pipefs", "securityfs", "selinuxfs", "smb3", "smbfs",
        "squashfs", "sysfs", "tmpfs", "tracefs", "udf", "virtiofs",
    }
)

# journalctl filter matches: kernel messages (for OOM) OR sshd messages (including
# OpenSSH 9.8+ split binaries `sshd-session` and `sshd-auth` and syslog tag `sshd`).
JOURNAL_MATCHES = [
    "_TRANSPORT=kernel",
    "+",
    "_COMM=sshd",
    "+",
    "_COMM=sshd-session",
    "+",
    "_COMM=sshd-auth",
    "+",
    "SYSLOG_IDENTIFIER=sshd",
]

SSHD_COMM_NAMES = frozenset({"sshd", "sshd-session", "sshd-auth"})

# Configure module logger.
LOGGER = logging.getLogger(NAME)
LOGGER.setLevel(logging.INFO)
if not LOGGER.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s " + NAME + ": %(message)s"))
    LOGGER.addHandler(_handler)


class AgentError(RuntimeError):
    """Raised for recoverable configuration, locking, or operational errors."""


class TransientStateError(AgentError):
    """Raised when state files cannot be read right now (e.g. EIO/EMFILE).

    Unlike corruption, a transient read failure must NOT rename or reset the
    state file: the cycle is skipped and retried with baselines intact.
    """


# --------------------------------------------------------------------------
# Default configuration schema and validation ranges
# --------------------------------------------------------------------------
FEATURE_DEFAULTS: dict[str, bool] = {
    "cpu": True,
    "load": False,
    "ram": True,
    "swap": True,
    "disk": True,
    "inode": True,
    "traffic": True,
    "network_errors": True,
    "ssh_failures": True,
    "oom": True,
    "systemd_services": True,
    "reboot": True,
    "time_sync": True,
    "listening_ports": True,
}

THRESHOLD_DEFAULTS: dict[str, int] = {
    "cpu": 80,
    "load_percent": 150,
    "ram": 80,
    "swap": 80,
    "swap_rate_pages_per_s": 500,
    "disk": 80,
    "inode": 80,
    "traffic_gb_daily": 300,
}

# `udp_ephemeral_port_min` controls the UDP port threshold above which unconnected
# sockets are treated as ephemeral client ports. Setting it to 65536 disables
# high-port UDP filtering so services like WireGuard (51820) are also tracked.
# Setting it to 0 uses the kernel's `/proc/sys/net/ipv4/ip_local_port_range`.
#
# `traffic_physical_only=true` counts traffic only for physical interfaces
# (those with a /sys/class/net/<if>/device link). Bonds, VLANs, bridges,
# WireGuard, tailscale0, and libvirt bridges are virtual layers over a parent
# NIC; summing them together with the physical NIC double-counts traffic. Set
# to false to track every interface not matched by `ignore_interfaces` (legacy
# behavior, correct only when virtual interfaces carry no duplicate traffic).
#
# `port_ignore_patterns` is a comma-separated fnmatch list matched against
# normalized listening-port keys ("tcp 0.0.0.0:5432", "udp *:51820", ...).
#
# `network_error_min` suppresses per-window network error reports below this
# total count so a single dropped packet does not produce a report.
MONITORING_DEFAULTS: dict[str, Any] = {
    "check_interval_seconds": 120,
    "persistence_samples": 3,
    "recovery_minutes": 10,
    "aggregation_window_hours": 12,
    "ignore_interfaces": "lo,docker*,veth*,br-*",
    "udp_ephemeral_port_min": 0,
    "traffic_physical_only": True,
    "port_ignore_patterns": "",
    "network_error_min": 10,
}

MONITORING_RANGES: dict[str, tuple[int, int]] = {
    "check_interval_seconds": (10, 3600),
    "persistence_samples": (1, 20),
    "recovery_minutes": (1, 10080),
    "aggregation_window_hours": (1, 168),
    "udp_ephemeral_port_min": (0, 65536),
    "network_error_min": (0, 1_000_000_000),
}

ALERT_DEFAULTS: dict[str, str] = {
    "backend": "stdout",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "webhook_url": "",
    "webhook_bearer_token": "",
}

TRUE_STRINGS = frozenset({"1", "true", "yes", "y", "on"})
FALSE_STRINGS = frozenset({"0", "false", "no", "n", "off"})


# --------------------------------------------------------------------------
# Configuration management
# --------------------------------------------------------------------------
def default_config() -> dict[str, Any]:
    """Return a fresh deep copy of the default configuration dictionary."""
    return {
        "features": dict(FEATURE_DEFAULTS),
        "thresholds": dict(THRESHOLD_DEFAULTS),
        "monitoring": dict(MONITORING_DEFAULTS),
        "alerts": dict(ALERT_DEFAULTS),
    }


def merge_config(base: dict[str, Any], override: dict[str, Any] | None) -> dict[str, Any]:
    """Deep-merge `override` into `base` without mutating either input."""
    merged = {
        "features": dict(base.get("features", FEATURE_DEFAULTS)),
        "thresholds": dict(base.get("thresholds", THRESHOLD_DEFAULTS)),
        "monitoring": dict(base.get("monitoring", MONITORING_DEFAULTS)),
        "alerts": dict(base.get("alerts", ALERT_DEFAULTS)),
    }
    if not isinstance(override, dict):
        return merged
    for section in ("features", "thresholds", "monitoring", "alerts"):
        section_override = override.get(section)
        if isinstance(section_override, dict):
            merged[section].update(section_override)
    return merged


@functools.lru_cache(maxsize=1)
def host() -> str:
    """Resolve and cache the host name without blocking on reverse DNS lookups.

    `socket.getfqdn()` performs a reverse PTR lookup via NSS/DNS, which can hang
    for 30+ seconds during network or resolver outages. `socket.gethostname()`
    reads the kernel utsname directly in memory with zero network I/O.
    """
    try:
        name = socket.gethostname().strip()
        if name:
            return name
    except OSError:
        pass
    try:
        name = os.uname().nodename.strip()
        if name:
            return name
    except OSError:
        pass
    return "localhost"


def stamp() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_command(
    args: list[str],
    timeout: int = 20,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute an external command safely with a timeout, never raising on failure."""
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        LOGGER.warning("command failed (%s): %s", " ".join(args), exc)
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def configparser_from_dict(cfg: dict[str, Any]) -> configparser.ConfigParser:
    """Serialize a configuration dictionary into a ConfigParser instance."""
    parser = configparser.ConfigParser(interpolation=None)
    parser["features"] = {k: str(bool(v)).lower() for k, v in cfg["features"].items()}
    parser["thresholds"] = {k: str(v) for k, v in cfg["thresholds"].items()}
    parser["monitoring"] = {k: str(v) for k, v in cfg["monitoring"].items()}
    parser["alerts"] = {k: str(v) for k, v in cfg["alerts"].items()}
    return parser


def _parse_bool(section: str, key: str, value: str) -> bool:
    """Parse a boolean string strictly so typos in config.ini do not silently disable checks."""
    normalized = value.strip().lower()
    if normalized in TRUE_STRINGS:
        return True
    if normalized in FALSE_STRINGS:
        return False
    raise ValueError(f"[{section}] {key}: expected a boolean (true/false/yes/no/1/0), got {value!r}")


def _parse_int(value: Any, label: str) -> int:
    """Convert `value` to int while rejecting booleans (since isinstance(True, int) is True)."""
    if isinstance(value, bool):
        raise ValueError(f"{label}: expected an integer, got boolean {value!r}")
    try:
        return int(str(value).strip() if isinstance(value, str) else value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label}: expected an integer, got {value!r}") from exc


def _parse_config_value(section: str, key: str, value: str) -> Any:
    """Convert a raw config.ini string value to the type expected by its section/key."""
    if section == "features":
        return _parse_bool(section, key, value)
    if section == "alerts":
        return value.strip()
    if section == "monitoring":
        default = MONITORING_DEFAULTS.get(key)
        if isinstance(default, bool):
            return _parse_bool(section, key, value)
        if isinstance(default, str):
            return value.strip()
    return _parse_int(value, f"[{section}] {key}")


def dict_from_parser(parser: configparser.ConfigParser) -> dict[str, Any]:
    """Build a configuration dictionary from an INI parser, filling in defaults."""
    cfg = default_config()
    for section in ("features", "thresholds", "monitoring", "alerts"):
        if not parser.has_section(section):
            continue
        for key, value in parser.items(section):
            cfg[section][key] = _parse_config_value(section, key, value)
    return cfg


def validate_config(cfg: dict[str, Any]) -> None:
    """Validate all sections, keys, ranges, and backend-specific settings in `cfg`."""
    if not isinstance(cfg, dict):
        raise ValueError("configuration must be a dict")

    for section in ("features", "thresholds", "monitoring", "alerts"):
        if not isinstance(cfg.get(section), dict):
            raise ValueError(f"missing or invalid configuration section: [{section}]")

    # Validate features section.
    for feature_name, enabled in cfg["features"].items():
        if feature_name not in FEATURE_DEFAULTS:
            raise ValueError(f"unknown feature: {feature_name}")
        if not isinstance(enabled, bool):
            raise ValueError(f"feature {feature_name} must be boolean")

    # Validate thresholds section.
    for threshold_name, threshold in cfg["thresholds"].items():
        if threshold_name not in THRESHOLD_DEFAULTS:
            raise ValueError(f"unknown threshold: {threshold_name}")
        value = _parse_int(threshold, f"thresholds.{threshold_name}")
        if threshold_name in {"cpu", "ram", "swap", "disk", "inode"}:
            if not 1 <= value <= 100:
                raise ValueError(f"threshold {threshold_name} must be between 1 and 100")
        elif threshold_name == "load_percent":
            if not 1 <= value <= 1000:
                raise ValueError("threshold load_percent must be between 1 and 1000")
        elif threshold_name == "swap_rate_pages_per_s":
            if value <= 0:
                raise ValueError("swap_rate_pages_per_s must be positive")
        elif threshold_name == "traffic_gb_daily":
            if value <= 0:
                raise ValueError("traffic_gb_daily must be positive")

    # Validate monitoring section.
    for key in cfg["monitoring"]:
        if key not in MONITORING_DEFAULTS:
            raise ValueError(f"unknown monitoring key: {key}")
    for key, default in MONITORING_DEFAULTS.items():
        if isinstance(default, bool) and not isinstance(cfg["monitoring"].get(key, default), bool):
            raise ValueError(f"monitoring.{key} must be a boolean")
    for key, (low, high) in MONITORING_RANGES.items():
        raw_val = cfg["monitoring"].get(key, MONITORING_DEFAULTS[key])
        value = _parse_int(raw_val, f"monitoring.{key}")
        if not low <= value <= high:
            raise ValueError(f"monitoring.{key} must be between {low} and {high}")
    ignore_ifaces = cfg["monitoring"].get("ignore_interfaces", MONITORING_DEFAULTS["ignore_interfaces"])
    if not isinstance(ignore_ifaces, str):
        raise ValueError("monitoring.ignore_interfaces must be a comma-separated string")

    # Validate alerts section.
    for key in cfg["alerts"]:
        if key not in ALERT_DEFAULTS:
            raise ValueError(f"unknown alerts key: {key}")
    backend = str(cfg["alerts"].get("backend", "stdout")).strip().lower()
    if backend not in {"stdout", "telegram", "webhook"}:
        raise ValueError("alerts.backend must be stdout, telegram, or webhook")
    if backend == "telegram":
        token = str(cfg["alerts"].get("telegram_bot_token", "")).strip()
        chat_id = str(cfg["alerts"].get("telegram_chat_id", "")).strip()
        if not token or not chat_id:
            raise ValueError("Telegram backend requires bot token and chat ID")
    elif backend == "webhook":
        webhook_url = str(cfg["alerts"].get("webhook_url", "")).strip()
        if not webhook_url:
            raise ValueError("Webhook backend requires webhook_url")
        parsed_url = urllib.parse.urlparse(webhook_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise ValueError("webhook_url must be a valid http:// or https:// URL")
        bearer = str(cfg["alerts"].get("webhook_bearer_token", "")).strip()
        if bearer and parsed_url.scheme != "https":
            # The Bearer credential must never travel over plaintext http://.
            raise ValueError("webhook_bearer_token requires an https:// webhook_url")


def _fsync_dir(directory: Path) -> None:
    """Flush directory metadata to disk after atomic file rename (`replace`).

    Required on POSIX filesystems (ext4, XFS, Btrfs) to guarantee that a newly
    renamed directory entry survives an immediate power loss.
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        dir_fd = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def _enforce_config_ownership(path: Path) -> None:
    """Keep /etc/auto-monitoring files root-owned but service-group-readable.

    The service user must read config.ini but never write it: a compromised
    agent could otherwise point webhook_url at an attacker endpoint and harvest
    the bearer token. The directory stays root:root 0755 and config.ini
    root:<service-group> 0640.
    """
    if path != ETC_ROOT and ETC_ROOT not in path.parents:
        return
    try:
        if path.is_symlink():
            return
    except OSError:
        return
    try:
        gid = _lookup_service_uid_gid(NAME)[1]
        os.chown(path, 0, gid, follow_symlinks=False)
        os.chmod(path, 0o640)
    except (KeyError, OSError):
        LOGGER.debug("could not enforce config ownership on %s", path)


def write_config(cfg: dict[str, Any], path: Path = CONFIG_PATH) -> None:
    """Atomically write `cfg` to `path` with 0640 permissions and parent directory fsync."""
    full_cfg = merge_config(default_config(), cfg)
    validate_config(full_cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    parser = configparser_from_dict(full_cfg)

    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf8") as handle:
            parser.write(handle)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
        _enforce_config_ownership(path)
        _fsync_dir(path.parent)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load and validate configuration from `path`, or return default config if absent."""
    if path.is_symlink():
        # A root-run installer/daemon must never read config through a symlink
        # planted by the service user (config poisoning).
        raise AgentError(f"refusing to load configuration through a symlink: {path}")
    if not path.exists():
        return default_config()
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path, encoding="utf8")
    cfg = dict_from_parser(parser)
    validate_config(cfg)
    return cfg


def ensure_dirs() -> None:
    """Create state and configuration directories with least-privilege ownership.

    STATE_DIR is owned by the service user (it must write state.json there).
    ETC_ROOT stays root:root 0755 with config.ini root:<service-group> 0640 so a
    compromised service user can read, but never rewrite, its own configuration.
    Also repairs permissions on pre-existing installations.
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ETC_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(STATE_DIR, 0o750)
    except OSError:
        pass
    _set_service_ownership(STATE_DIR)
    if os.geteuid() == 0:
        try:
            os.chmod(ETC_ROOT, 0o755)
            os.chown(ETC_ROOT, 0, 0, follow_symlinks=False)
        except OSError as exc:
            LOGGER.warning("could not harden %s ownership: %s", ETC_ROOT, exc)
        if CONFIG_PATH.exists():
            _enforce_config_ownership(CONFIG_PATH)


@functools.lru_cache(maxsize=1)
def _lookup_service_uid_gid(username: str = NAME) -> tuple[int, int]:
    """Cached lookup of `(pw_uid, pw_gid)` for `username` to avoid repeated NSS/passwd queries.

    Raises `KeyError` when the user does not exist yet (which `lru_cache` does
    not cache in Python's standard library), so subsequent calls after user
    creation automatically succeed and cache the result.
    """
    entry = pwd.getpwnam(username)
    return entry.pw_uid, entry.pw_gid


def _safe_chown(path: Path, uid: int, gid: int) -> bool:
    """Chown `path` without ever following symlinks; refuses symlinks outright.

    `os.chown()` follows symlinks by default: a compromised service user could
    plant a symlink (e.g. state.lock -> /etc/shadow) and let a root-run command
    chown an arbitrary file. We lstat first and skip anything not a regular
    file or directory.
    """
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return False
    if not (stat_module.S_ISREG(mode) or stat_module.S_ISDIR(mode)):
        LOGGER.warning("refusing to chown non-regular path %s", path)
        return False
    try:
        os.chown(path, uid, gid, follow_symlinks=False)
        return True
    except OSError as exc:
        LOGGER.debug("cannot change ownership of %s: %s", path, exc)
        return False


def _set_service_ownership(path: Path) -> None:
    """Assign ownership of managed paths under the state directory to the service user."""
    if path != STATE_DIR and STATE_DIR not in path.parents:
        return
    try:
        uid, gid = _lookup_service_uid_gid(NAME)
    except KeyError:
        LOGGER.debug("service account %s is not yet available to own %s", NAME, path)
        return
    _safe_chown(path, uid, gid)


# --------------------------------------------------------------------------
# State persistence, exclusive locking, and schema migration
# --------------------------------------------------------------------------
def _json_compatible(value: Any) -> Any:
    """Recursively convert sets and tuples into JSON-serializable lists."""
    if isinstance(value, set):
        return sorted((_json_compatible(item) for item in value), key=str)
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return value


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write JSON to `path` with file + directory fsync to survive sudden reboots."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _set_service_ownership(path.parent)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf8") as handle:
            json.dump(_json_compatible(payload), handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        _set_service_ownership(temp_path)
        temp_path.replace(path)
        _fsync_dir(path.parent)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def migrate_state_v1(payload: dict[str, Any]) -> dict[str, Any]:
    """Upgrade a schema v1 state dictionary to v2.

    v1 stored traffic/network counters using wrong /proc/net/dev column indexes,
    so those windows are discarded. The SSH window is converted from an unbounded
    list of IP strings into a bounded frequency map; ports and dedup sets are
    rebuilt on the next cycle.
    """
    for key in ("oom_events", "ssh_processed_events", "traffic_window", "network_window", "ports"):
        payload.pop(key, None)
    old_ssh = payload.pop("ssh_window", None)
    if isinstance(old_ssh, dict) and isinstance(old_ssh.get("failures"), list):
        counts = Counter(str(item) for item in old_ssh["failures"])
        payload["ssh_window"] = {
            "started": float(old_ssh.get("started", time.time())),
            "total": len(old_ssh["failures"]),
            "sources": dict(counts.most_common(SSH_MAX_TRACKED_SOURCES)),
        }
    payload["schema_version"] = STATE_SCHEMA_VERSION
    return payload


def _backup_corrupt_state(path: Path) -> None:
    """Preserve a corrupted or incompatible state file as `<name>.corrupt`."""
    backup = path.with_name(path.name + ".corrupt")
    try:
        if path.exists():
            path.replace(backup)
            _fsync_dir(path.parent)
    except OSError:
        LOGGER.warning("could not preserve corrupted state %s", path)


def load_state(path: Path | None = None) -> dict[str, Any]:
    """Load persisted agent state from disk, migrating v1 or recovering from corruption.

    Only JSON decode errors / schema mismatches are treated as corruption (file
    is backed up and reset). Transient OSErrors (EIO, EMFILE, EAGAIN) raise
    `TransientStateError` so the caller skips the cycle WITHOUT touching the
    file, preserving baselines, journal cursor, and the alert outbox.
    """
    path = path or STATE_PATH
    default: dict[str, Any] = {"schema_version": STATE_SCHEMA_VERSION}
    if path.is_symlink():
        raise AgentError(f"refusing to load state through a symlink: {path}")
    try:
        raw = path.read_text(encoding="utf8")
    except FileNotFoundError:
        return default
    except OSError as exc:
        raise TransientStateError(f"state file {path} temporarily unreadable: {exc}") from exc
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("state root is not an object")
        version = payload.get("schema_version")
        if version == 1:
            payload = migrate_state_v1(payload)
        elif version != STATE_SCHEMA_VERSION:
            LOGGER.warning("state schema mismatch, creating default state for %s", path)
            _backup_corrupt_state(path)
            return default
        for key in ("failed_systemd_services", "ports"):
            if isinstance(payload.get(key), list):
                payload[key] = set(str(item) for item in payload[key])
        if isinstance(payload.get("ports"), set):
            # Re-normalize wildcard forms persisted by older versions so the
            # first post-upgrade cycle does not emit a bogus port-change alert.
            payload["ports"] = normalize_port_keys(payload["ports"])
        return payload
    except (json.JSONDecodeError, ValueError) as exc:
        LOGGER.warning("corrupted state at %s: %s; creating safe fallback", path, exc)
        _backup_corrupt_state(path)
        return default


def save_state(state: dict[str, Any], path: Path | None = None) -> None:
    """Persist `state` atomically with the current schema version."""
    state_copy = dict(state)
    state_copy.setdefault("schema_version", STATE_SCHEMA_VERSION)
    atomic_write_json(path or STATE_PATH, state_copy)


def _refuse_symlinked_path(path: Path) -> None:
    """Refuse to operate on any path with a symlinked component.

    Protects root-run `install`/`check` from symlink-planting by the service
    user inside STATE_DIR (e.g. /var/lib/auto-monitoring -> /etc).
    """
    for component in (path, *path.parents):
        try:
            if component.is_symlink():
                raise AgentError(f"refusing symlinked path component: {component}")
        except OSError:
            continue


@contextmanager
def state_lock(path: Path | None = None, timeout: float = LOCK_TIMEOUT_SECONDS) -> Iterator[None]:
    """Hold an exclusive flock so manual `check` runs and the daemon never overlap."""
    path = path or LOCK_PATH
    _refuse_symlinked_path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AgentError(f"cannot create state directory {path.parent}: {exc}") from exc

    fd: int | None = None
    try:
        try:
            # O_NOFOLLOW: never open (or create through) a symlink planted at the
            # lock path; a symlink yields ELOOP which fails loudly below.
            fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o640)
        except PermissionError:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise AgentError(f"cannot open state lock {path}: {exc}") from exc

    _set_service_ownership(path)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, InterruptedError):
                if time.monotonic() >= deadline:
                    raise AgentError(f"could not acquire state lock {path}; another run is active") from None
                time.sleep(0.2)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN) and time.monotonic() < deadline:
                    time.sleep(0.2)
                    continue
                raise AgentError(f"failed to lock {path}: {exc}") from exc
        yield
    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)


# --------------------------------------------------------------------------
# Counters and pure parsing helpers
# --------------------------------------------------------------------------
def build_traffic_snapshot(rx_bytes: int, tx_bytes: int) -> dict[str, float | int]:
    """Convert raw RX/TX byte counts into a summary dict with decimal GB values."""
    rx_val = max(0, int(rx_bytes))
    tx_val = max(0, int(tx_bytes))
    total = rx_val + tx_val
    return {
        "rx_bytes": rx_val,
        "tx_bytes": tx_val,
        "total_bytes": total,
        "rx_gb_decimal": float(rx_val / 1_000_000_000),
        "tx_gb_decimal": float(tx_val / 1_000_000_000),
        "total_gb_decimal": float(total / 1_000_000_000),
    }


class IfaceCounters(NamedTuple):
    """Per-interface network counters extracted from /proc/net/dev."""

    rx_bytes: int
    rx_packets: int
    rx_errs: int
    rx_drop: int
    tx_bytes: int
    tx_packets: int
    tx_errs: int
    tx_drop: int


def parse_net_dev(text: str) -> dict[str, IfaceCounters]:
    """Parse `/proc/net/dev` content into per-interface counter tuples.

    After the colon, `/proc/net/dev` exposes 16 whitespace-separated columns:
      - RX [0..7]:  bytes, packets, errs, drop, fifo, frame, compressed, multicast
      - TX [8..15]: bytes, packets, errs, drop, fifo, colls, carrier, compressed
    """
    result: dict[str, IfaceCounters] = {}
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        fields = rest.split()
        if len(fields) < 16:
            continue
        try:
            v = [int(item) for item in fields[:16]]
        except ValueError:
            continue
        iface = name.strip()
        if iface:
            result[iface] = IfaceCounters(v[0], v[1], v[2], v[3], v[8], v[9], v[10], v[11])
    return result


def parse_ignore_patterns(raw: str) -> list[str]:
    """Split a comma-separated glob list (e.g. 'lo,docker*,veth*') into patterns."""
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def is_ignored_interface(name: str, patterns: Sequence[str]) -> bool:
    """Return True if interface `name` matches any configured ignore glob pattern."""
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def counter_delta(prev: int, cur: int) -> int:
    """Return the increase of a monotonic counter, treating any decrease as a reset.

    Linux exposes 64-bit interface counters on every supported 64-bit target;
    a counter going backwards means a reboot or a re-created interface, and
    counting forward from zero avoids inventing traffic data.
    """
    if cur < 0:
        return 0
    if cur >= prev:
        return cur - prev
    return cur  # Counter reset (reboot or interface recreated): count from zero


def update_traffic_state(traffic: dict[str, Any], counters: dict[str, IfaceCounters], day: str) -> dict[str, Any]:
    """Accumulate per-interface RX/TX byte deltas for the current UTC day.

    The previous-counter snapshot is stored separately from daily `totals`,
    so a midnight UTC rollover resets `totals` without losing the delta from
    the cycle that spans midnight.
    """
    if traffic.get("day") != day or not isinstance(traffic.get("totals"), dict):
        traffic["day"] = day
        traffic["totals"] = {}
        traffic["alerted"] = False
    totals: dict[str, list[int]] = traffic["totals"]
    previous = traffic.get("snapshot")
    if not isinstance(previous, dict):
        previous = {}
    snapshot: dict[str, list[int]] = {}
    for iface, current in counters.items():
        snapshot[iface] = [current.rx_bytes, current.tx_bytes]
        before = previous.get(iface)
        if not isinstance(before, (list, tuple)) or len(before) < 2:
            continue  # Newly discovered interface: record baseline first
        entry = totals.get(iface)
        if not isinstance(entry, list) or len(entry) < 2:
            entry = [0, 0]
            totals[iface] = entry
        entry[0] = int(entry[0]) + counter_delta(int(before[0]), current.rx_bytes)
        entry[1] = int(entry[1]) + counter_delta(int(before[1]), current.tx_bytes)
    traffic["snapshot"] = snapshot
    return traffic


def new_network_window(now: float) -> dict[str, Any]:
    """Create a fresh network error/drop aggregation window."""
    return {"started": float(now), "counts": {key: 0 for key in NETWORK_ERROR_KEYS}}


def accumulate_network_errors(window: dict[str, Any], counters: dict[str, IfaceCounters]) -> None:
    """Add interface error and drop deltas since the last snapshot into `window`."""
    counts = window.get("counts")
    if not isinstance(counts, dict):
        counts = {key: 0 for key in NETWORK_ERROR_KEYS}
        window["counts"] = counts
    for key in NETWORK_ERROR_KEYS:
        counts.setdefault(key, 0)

    previous = window.get("snapshot")
    if not isinstance(previous, dict):
        previous = {}
    snapshot: dict[str, list[int]] = {}
    for iface, current in counters.items():
        values = [current.rx_errs, current.tx_errs, current.rx_drop, current.tx_drop]
        snapshot[iface] = values
        before = previous.get(iface)
        if not isinstance(before, (list, tuple)) or len(before) < 4:
            continue
        for key, old, new in zip(NETWORK_ERROR_KEYS, before, values):
            counts[key] = int(counts.get(key, 0)) + counter_delta(int(old), new)
    window["snapshot"] = snapshot


def roll_network_window(window: dict[str, Any], now: float, window_seconds: int) -> dict[str, int] | None:
    """Close and reset the current network window if `window_seconds` have elapsed.

    Preserves `window["snapshot"]` so the first delta of the new window is not lost.
    """
    if now - float(window.get("started", now)) < window_seconds:
        return None
    raw_counts = window.get("counts") if isinstance(window.get("counts"), dict) else {}
    finished = {key: int(raw_counts.get(key, 0)) for key in NETWORK_ERROR_KEYS}
    window["started"] = float(now)
    window["counts"] = {key: 0 for key in NETWORK_ERROR_KEYS}
    return finished


def is_ssh_failed_attempt_line(message: str) -> bool:
    """Return True only for canonical per-attempt sshd failure lines.

    "Invalid user <u> from <ip>" (preauth notice) and "maximum authentication
    attempts exceeded ..." accompany the same attempt; counting them too would
    double-count every invalid-user failure.
    """
    return bool(SSH_FAILURE_LINE_RE.search(message))


def ssh_source_ip(message: str) -> str | None:
    """Extract and validate the remote source IP address from an sshd failure line.

    Usernames are logged verbatim without escaping, so a crafted username can
    inject a fake "from <ip> port <N>" earlier in the line. The genuine source
    is the LAST "from <ip> port <digits>" occurrence, emitted by sshd itself.
    """
    candidates = SSH_FROM_PORT_RE.findall(message)
    for candidate in reversed(candidates):
        try:
            # Validate and canonicalize IPv4/IPv6 addresses.
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def new_ssh_window(now: float) -> dict[str, Any]:
    """Create a fresh SSH authentication failure aggregation window."""
    return {"started": float(now), "total": 0, "sources": {}}


def record_ssh_failure(window: dict[str, Any], ip: str) -> None:
    """Increment total SSH failure count and track up to `SSH_MAX_TRACKED_SOURCES` IPs."""
    window["total"] = int(window.get("total", 0)) + 1
    sources = window.get("sources")
    if not isinstance(sources, dict):
        sources = {}
        window["sources"] = sources
    if ip in sources or len(sources) < SSH_MAX_TRACKED_SOURCES:
        sources[ip] = int(sources.get(ip, 0)) + 1


def is_oom_event(line: str) -> bool:
    """Return True if a kernel log message indicates an Out-Of-Memory killer event."""
    lower = line.lower()
    if "out of memory" in lower:
        return True
    if "oom-kill" in lower or "oom_reaper" in lower or "invoked oom-killer" in lower:
        return True
    if "killed process" in lower and "oom" in lower:
        return True
    return False


def is_sshd_entry(entry: dict[str, Any]) -> bool:
    """Return True if a journald JSON entry originated from the OpenSSH daemon."""
    comm = entry.get("_COMM")
    if isinstance(comm, str) and comm in SSHD_COMM_NAMES:
        return True
    syslog_id = entry.get("SYSLOG_IDENTIFIER")
    return isinstance(syslog_id, str) and syslog_id == "sshd"


def cpu_usage_percent(previous: Sequence[int] | None, current: Sequence[int]) -> float | None:
    """Calculate CPU busy percentage between two (total, idle) jiffy samples.

    Returns None on the first cycle, counter resets across a reboot, or a
    negative idle delta (NO_HZ iowait accounting artifact): a bad sample is
    skipped rather than clamped to a misleading 100% busy reading.
    """
    if not previous or len(previous) != 2 or len(current) != 2:
        return None
    try:
        prev_total, prev_idle = int(previous[0]), int(previous[1])
        cur_total, cur_idle = int(current[0]), int(current[1])
    except (TypeError, ValueError):
        return None
    total_delta = cur_total - prev_total
    idle_delta = cur_idle - prev_idle
    if total_delta <= 0 or idle_delta < 0:
        return None  # Counter reset, zero elapsed ticks, or inconsistent sample
    return min(100.0, max(0.0, 100.0 * (1.0 - idle_delta / total_delta)))


def df_percent(blocks: int, free: int, available: int) -> int:
    """Calculate filesystem usage percentage rounded up identically to POSIX `df`."""
    used = max(0, blocks - free)
    denominator = used + max(0, available)
    if denominator <= 0:
        return 0
    return max(0, min(100, -(-used * 100 // denominator)))


def _unescape_mount_field(value: str) -> str:
    """Decode octal escape sequences (such as `\\040` for spaces) in `/proc/self/mounts`."""
    return MOUNT_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 8)), value)


def parse_mounts(text: str) -> list[tuple[str, str, str]]:
    """Parse `/proc/self/mounts` into `(source, mountpoint, fstype)` for real filesystems.

    Allows `overlay` when mounted directly on `/` so systems or containers with
    an overlayfs root filesystem still have `/` monitored, while excluding
    non-root container overlay mounts (such as `/var/lib/docker/overlay2/...`).
    """
    result: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        source, mount, fstype = (_unescape_mount_field(item) for item in parts[:3])
        if fstype == "overlay" and mount == "/":
            result.append((source, mount, fstype))
            continue
        if fstype in EXCLUDED_FSTYPES or fstype == "fuse" or fstype.startswith("fuse."):
            continue
        if source.startswith("/dev/loop"):
            continue
        result.append((source, mount, fstype))
    return result


def _normalize_local_addr(local: str) -> str:
    """Canonicalize wildcard listen addresses so `ss` and /proc/net agree.

    `ss` may render IPv4/IPv6 wildcard binds as "*:22" while /proc/net decodes
    them as "0.0.0.0:22" / "[::]:22"; without a shared canonical form a single
    fallback run would emit a bogus "port changed" alert.
    """
    host, sep, port = local.rpartition(":")
    if sep and host in {"*", "0.0.0.0", "[::]"}:
        return f"*:{port}"
    return local


def normalize_port_keys(keys: Iterable[str]) -> set[str]:
    """Re-normalize persisted port keys so pre-upgrade state compares equal."""
    result: set[str] = set()
    for key in keys:
        netid, _, local = str(key).partition(" ")
        if netid and local:
            result.add(f"{netid} {_normalize_local_addr(local)}")
        else:
            result.add(str(key))
    return result


def filter_ignored_ports(ports: Iterable[str], patterns: Sequence[str]) -> set[str]:
    """Drop listening-port keys matching any configured fnmatch ignore pattern."""
    selected = set(ports)
    if not patterns:
        return selected
    return {key for key in selected if not any(fnmatch.fnmatchcase(key, pat) for pat in patterns)}


def parse_listening_ports(text: str, ephemeral_start: int = DEFAULT_EPHEMERAL_PORT_START) -> set[str]:
    """Return stable `'netid local_address:port'` keys from `ss -H -lntu` output.

    Ignores volatile Recv-Q/Send-Q columns and filters out unconnected UDP
    sockets bound to ephemeral client ports (`>= ephemeral_start`). Wildcard
    addresses are canonicalized via `_normalize_local_addr`.
    """
    ports: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        netid, local = parts[0], parts[4]
        try:
            port = int(local.rpartition(":")[2])
        except ValueError:
            continue
        if netid.startswith("udp") and port >= ephemeral_start:
            continue
        ports.add(f"{netid} {_normalize_local_addr(local)}")
    return ports


def _decode_proc_net_addr(hex_addr: str, is_ipv6: bool) -> str | None:
    """Decode a hex IP:port token from `/proc/net/{tcp,udp}*` into `address:port`."""
    host_hex, sep, port_hex = hex_addr.partition(":")
    if not sep:
        return None
    try:
        port = int(port_hex, 16)
        raw = bytes.fromhex(host_hex)
        if not is_ipv6 and len(raw) == 4:
            # Little-endian 32-bit IPv4 address on little-endian architectures.
            if sys.byteorder == "little":
                raw = raw[::-1]
            ip_str = str(ipaddress.IPv4Address(raw))
            return f"{ip_str}:{port}"
        if is_ipv6 and len(raw) == 16:
            # Kernel stores IPv6 as four 32-bit words in host byte order.
            if sys.byteorder == "little":
                raw = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
            ip_str = str(ipaddress.IPv6Address(raw))
            return f"[{ip_str}]:{port}"
    except ValueError:
        return None
    return None


def parse_proc_net_sockets(
    table_text: str,
    netid: str,
    is_ipv6: bool,
    ephemeral_start: int = DEFAULT_EPHEMERAL_PORT_START,
) -> set[str]:
    """Fallback parser for `/proc/net/{tcp,tcp6,udp,udp6}` when `ss` is unavailable."""
    ports: set[str] = set()
    is_tcp = netid == "tcp"
    for line in table_text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local_hex, rem_hex, state_hex = parts[1], parts[2], parts[3].upper()
        # TCP_LISTEN == 0x0A; unconnected bound UDP sockets have state 0x07 (TCP_CLOSE)
        # and a zero remote port (:0000).
        if is_tcp:
            if state_hex != "0A":
                continue
        else:
            if state_hex != "07" or not rem_hex.endswith(":0000"):
                continue
        decoded = _decode_proc_net_addr(local_hex, is_ipv6)
        if not decoded:
            continue
        decoded = _normalize_local_addr(decoded)
        port = int(decoded.rpartition(":")[2])
        if port == 0 or (not is_tcp and port >= ephemeral_start):
            continue
        ports.add(f"{netid} {decoded}")
    return ports


def parse_journal_json(text: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON records emitted by `journalctl -o json`."""
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("-- "):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            entries.append(obj)
    return entries


def entry_message(entry: dict[str, Any]) -> str:
    """Extract a UTF-8 string message from a journald JSON entry."""
    message = entry.get("MESSAGE")
    if isinstance(message, str):
        return message
    if isinstance(message, list):  # journald encodes non-UTF-8 payloads as byte arrays
        try:
            return bytes(message).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return ""
    return ""


# --------------------------------------------------------------------------
# Debounced resource incident tracking
# --------------------------------------------------------------------------
class ResourceIncidentTracker:
    """Debounced incident state machine: healthy -> active -> recovering -> resolved."""

    VALID_STATUSES = frozenset({"healthy", "active", "recovering", "resolved"})

    def __init__(self, persistence_samples: int = 3, recovery_minutes: int = 10):
        self.persistence_samples = max(1, int(persistence_samples))
        self.recovery_seconds = max(60, int(recovery_minutes) * 60)
        self._incidents: dict[str, dict[str, Any]] = {}

    def state(self, key: str) -> dict[str, Any]:
        """Return a normalized incident state record for `key`."""
        rec = self._incidents.get(key)
        if not isinstance(rec, dict):
            rec = {"status": "healthy", "bad_samples": 0, "recovery_since": None}
            self._incidents[key] = rec
            return rec
        if rec.get("status") not in self.VALID_STATUSES:
            rec["status"] = "healthy"
        try:
            rec["bad_samples"] = max(0, int(rec.get("bad_samples", 0)))
        except (TypeError, ValueError):
            rec["bad_samples"] = 0
        rec.setdefault("recovery_since", None)
        return rec

    def observe(self, key: str, is_bad: bool, now: float | int | None = None) -> str | None:
        """Record a sample and return `'triggered'`, `'relapse'`, `'resolved'`, or `None`.

        `'relapse'` means a recovering incident crossed the threshold again before
        `recovery_seconds` elapsed; callers suppress duplicate alerts on relapse.
        """
        ts = time.time() if now is None else float(now)
        rec = self.state(key)
        status = rec["status"]
        event: str | None = None
        if is_bad:
            rec["bad_samples"] = min(int(rec.get("bad_samples", 0)) + 1, self.persistence_samples)
            if status in {"healthy", "resolved"}:
                if rec["bad_samples"] >= self.persistence_samples:
                    rec["status"] = "active"
                    event = "triggered"
            elif status == "recovering":
                rec["status"] = "active"
                event = "relapse"
            rec["recovery_since"] = None
        elif status == "active":
            rec["status"] = "recovering"
            rec["recovery_since"] = ts
        elif status == "recovering":
            recovery_since = rec.get("recovery_since")
            try:
                since_ts = float(recovery_since) if recovery_since is not None else ts
            except (TypeError, ValueError):
                since_ts = ts
            rec["recovery_since"] = since_ts
            if ts - since_ts >= self.recovery_seconds:
                rec["status"] = "resolved"
                rec["bad_samples"] = 0
                rec["recovery_since"] = None
                event = "resolved"
        else:
            rec["status"] = "healthy"
            rec["bad_samples"] = 0
            rec["recovery_since"] = None
        return event

    def prune(self, prefix: str, keep: set[str]) -> None:
        """Remove tracked incidents starting with `prefix` that are no longer in `keep`."""
        for key in [k for k in self._incidents if k.startswith(prefix) and k not in keep]:
            del self._incidents[key]

    def load(self, incidents: dict[str, Any] | None) -> None:
        """Adopt previously persisted incident records (sanitized lazily on access)."""
        self._incidents = dict(incidents) if isinstance(incidents, dict) else {}

    def dump(self) -> dict[str, Any]:
        """Return a JSON-safe copy of incident records for state persistence."""
        return {str(key): dict(rec) if isinstance(rec, dict) else rec for key, rec in self._incidents.items()}


# --------------------------------------------------------------------------
# Alert formatting, delivery backends, and persistent outbox
# --------------------------------------------------------------------------
def make_alert(title: str, body: str, severity: str = "warning") -> dict[str, Any]:
    """Create a structured alert payload dictionary."""
    return {
        "title": str(title),
        "body": str(body),
        "severity": str(severity),
        "host": host(),
        "time": stamp(),
    }


def format_alert(alert: dict[str, Any]) -> str:
    """Format an alert dictionary into a human-readable text message."""
    severity = str(alert.get("severity", "warning")).upper()
    title = str(alert.get("title", "Alert"))
    alert_host = str(alert.get("host") or host())
    alert_time = str(alert.get("time") or stamp())
    body = str(alert.get("body", ""))
    message = f"[{severity}] {title}\nHost: {alert_host}\nTime: {alert_time}\n\n{body}"
    return message[:ALERT_MAX_CHARS]


def _redact_secrets(text: str) -> str:
    """Redact Telegram bot tokens from URLs before writing error messages to logs."""
    return TELEGRAM_TOKEN_REDACT_RE.sub(r"\1<redacted>", text)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse HTTP redirects so credentials are never re-sent cross-host.

    urllib's default redirect handler forwards the Authorization header to the
    redirect target; combined with an attacker-controlled 30x this leaks the
    bearer token. Refusing redirects is fail-safe for alert delivery.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102 (urllib API)
        raise urllib.error.HTTPError(newurl, code, "redirect refused to protect credentials", headers, fp)


class AlertSender:
    """Delivers a single alert to the configured backend; never raises on network errors."""

    def __init__(self, cfg: dict[str, Any]):
        self.alerts: dict[str, Any] = dict(cfg.get("alerts", {}))
        self.backend = str(self.alerts.get("backend", "stdout")).strip().lower()
        self.opener = urllib.request.build_opener(_NoRedirectHandler)

    def deliver(self, alert: dict[str, Any]) -> bool:
        """Send `alert` via stdout, Telegram, or Webhook. Returns True on success."""
        if not isinstance(alert, dict):
            return True
        message = format_alert(alert)
        if self.backend == "stdout":
            print(message, flush=True)
            return True
        try:
            if self.backend == "telegram":
                token = str(self.alerts.get("telegram_bot_token", "")).strip()
                chat_id = str(self.alerts.get("telegram_chat_id", "")).strip()
                if not token or not chat_id:
                    raise ValueError("telegram configuration missing bot token or chat ID")
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                payload = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode("utf8")
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
                    method="POST",
                )
            elif self.backend == "webhook":
                url = str(self.alerts.get("webhook_url", "")).strip()
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    raise ValueError("invalid webhook_url scheme or host")
                headers = {"Content-Type": "application/json; charset=utf-8"}
                token = str(self.alerts.get("webhook_bearer_token", "")).strip()
                if token:
                    if parsed.scheme != "https":
                        raise ValueError("webhook_bearer_token requires an https:// webhook_url")
                    headers["Authorization"] = f"Bearer {token}"
                req = urllib.request.Request(
                    url,
                    data=json.dumps(
                        {
                            "title": alert.get("title", "Alert"),
                            "severity": alert.get("severity", "warning"),
                            "host": alert.get("host") or host(),
                            "timestamp": alert.get("time") or stamp(),
                            "message": alert.get("body", ""),
                        }
                    ).encode("utf8"),
                    headers=headers,
                    method="POST",
                )
            else:
                LOGGER.error("unsupported alert backend: %s", self.backend)
                return False

            with self.opener.open(req, timeout=12) as response:
                if not 200 <= response.status < 300:
                    raise ValueError(f"unexpected HTTP status {response.status}")
            return True
        except Exception as exc:  # noqa: BLE001 - delivery must never kill the cycle
            # Broad on purpose: http.client.IncompleteRead / RemoteDisconnected
            # and other exotic socket errors must degrade to a retry, not abort.
            LOGGER.error(
                "alert delivery failed for %s: %s",
                alert.get("title"),
                _redact_secrets(str(exc)),
            )
            return False


def enqueue_alert(state: dict[str, Any], title: str, body: str, severity: str = "warning") -> None:
    """Queue an alert in the persistent outbox; removed only after confirmed delivery."""
    outbox = state.get("outbox")
    if not isinstance(outbox, list):
        outbox = []
        state["outbox"] = outbox
    alert = make_alert(title, body, severity)
    alert.update({"created": time.time(), "attempts": 0, "next_try": 0.0})
    outbox.append(alert)
    overflow = len(outbox) - OUTBOX_MAX_ITEMS
    if overflow > 0:
        LOGGER.warning("alert outbox full; dropping %d oldest alert(s)", overflow)
        del outbox[:overflow]


def flush_outbox(
    state: dict[str, Any],
    deliver: Callable[[dict[str, Any]], bool],
    now: float | None = None,
    save: Callable[[], None] | None = None,
) -> int:
    """Attempt delivery of queued alerts in FIFO order with exponential backoff.

    Stops at the first failed delivery so an unreachable backend is not hammered.
    When `save` is provided, state is checkpointed after EVERY successful send
    (the delivered alert is removed and persisted immediately), shrinking the
    crash window that would otherwise duplicate alerts. Returns the count of
    successfully delivered alerts.
    """
    now = time.time() if now is None else float(now)
    outbox = state.get("outbox")
    if not isinstance(outbox, list):
        state["outbox"] = []
        return 0
    valid_items = [a for a in outbox if isinstance(a, dict)]
    fresh = [a for a in valid_items if now - float(a.get("created", now)) <= OUTBOX_MAX_AGE_SECONDS]
    if len(fresh) != len(valid_items):
        LOGGER.warning("dropped %d expired alert(s) from the outbox", len(valid_items) - len(fresh))
    remaining = list(fresh)
    delivered = 0
    blocked = False
    index = 0
    while index < len(remaining):
        alert = remaining[index]
        if blocked or float(alert.get("next_try", 0.0)) > now:
            index += 1
            continue
        if deliver(alert):
            delivered += 1
            del remaining[index]
            state["outbox"] = remaining
            if save is not None:
                try:
                    save()
                except (OSError, AgentError) as exc:
                    LOGGER.warning("could not checkpoint outbox after delivery: %s", exc)
            continue
        attempts = int(alert.get("attempts", 0)) + 1
        alert["attempts"] = attempts
        backoff = min(OUTBOX_BACKOFF_BASE_SECONDS * (2 ** min(attempts - 1, 10)), OUTBOX_BACKOFF_MAX_SECONDS)
        alert["next_try"] = now + backoff
        blocked = True
        index += 1
    state["outbox"] = remaining
    return delivered


# --------------------------------------------------------------------------
# Linux system probes
# --------------------------------------------------------------------------
def get_meminfo() -> dict[str, int]:
    """Read `/proc/meminfo` and return memory metrics in bytes."""
    data: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf8").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parts = value.strip().split()
        if not parts:
            continue
        try:
            data[key.strip()] = int(parts[0]) * 1024
        except ValueError:
            continue
    return data


def get_cpu_ticks() -> tuple[int, int]:
    """Read aggregate `(total, idle)` CPU jiffies from `/proc/stat`.

    Columns 1..8 are `user, nice, system, idle, iowait, irq, softirq, steal`.
    Columns 9..10 (`guest`, `guest_nice`) are already included in `user`/`nice`
    by the Linux kernel and are therefore excluded to avoid double-counting.
    """
    lines = Path("/proc/stat").read_text(encoding="utf8").splitlines()
    if not lines:
        raise ValueError("/proc/stat is empty")
    fields = lines[0].split()
    if len(fields) < 5 or fields[0] != "cpu":
        raise ValueError(f"unexpected /proc/stat header: {lines[0]!r}")
    parts = [int(x) for x in fields[1:9]]
    total = sum(parts)
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    return total, idle


def get_load_average() -> float:
    """Return the 1-minute system load average from `/proc/loadavg`."""
    return float(Path("/proc/loadavg").read_text(encoding="utf8").split()[0])


def _probe_mount_fs(mount: str, timeout: float = MOUNT_PROBE_TIMEOUT_SECONDS) -> tuple[int, os.statvfs_result] | None:
    """stat + statvfs a mount with a hard timeout, for hung network filesystems.

    statvfs() on a hung NFS/ceph mount blocks indefinitely in the kernel; a
    daemon thread plus join(timeout) lets the cycle skip it and stay alive.
    The leaked thread is a daemon, so it can never block process exit.
    """
    result: list[tuple[int, os.statvfs_result]] = []

    def worker() -> None:
        try:
            result.append((os.stat(mount).st_dev, os.statvfs(mount)))
        except OSError:
            result.clear()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive() or not result:
        return None
    return result[0]


def build_mount_report(
    mounts_text: str,
    mount_probe: Callable[[str], tuple[int, os.statvfs_result] | None],
) -> list[dict[str, Any]]:
    """Pure core of `get_mounts`: parse `mounts_text` and probe each mount.

    Mounts whose stat/statvfs fails (or times out) are kept in the list with
    `percent=None`/`error=True`: dropping them here would make the incident
    tracker prune their active incidents and re-alert them later. Callers skip
    threshold checks for errored entries and count them as probe failures.
    """
    parsed = sorted(parse_mounts(mounts_text), key=lambda item: (len(item[1]), item[1]))
    seen_devices: set[int] = set()
    seen_btrfs_sources: set[str] = set()
    mounts: list[dict[str, Any]] = []

    for source, mount, fstype in parsed:
        probed = mount_probe(mount)
        if probed is None:
            LOGGER.warning("cannot stat mount %s (hung or inaccessible); keeping it listed", mount)
            mounts.append(
                {
                    "device": source,
                    "mount": mount,
                    "fstype": fstype,
                    "percent": None,
                    "inode_percent": None,
                    "error": True,
                }
            )
            continue
        device_id, usage = probed
        if usage.f_blocks == 0 or device_id in seen_devices:
            continue  # Bind mount of an already-seen device, or a zero-sized pseudo mount
        if fstype == "btrfs" and source.startswith("/dev/"):
            if source in seen_btrfs_sources:
                continue  # Btrfs subvolume on an already-monitored block device pool
            seen_btrfs_sources.add(source)
        seen_devices.add(device_id)

        inode_percent: int | None = None
        if usage.f_files > 0:
            inode_avail = getattr(usage, "f_favail", usage.f_ffree)
            inode_percent = df_percent(usage.f_files, usage.f_ffree, inode_avail)
        mounts.append(
            {
                "device": source,
                "mount": mount,
                "fstype": fstype,
                "percent": df_percent(usage.f_blocks, usage.f_bfree, usage.f_bavail),
                "inode_percent": inode_percent,
            }
        )
    return mounts


def get_mounts(mount_probe: Callable[[str], tuple[int, os.statvfs_result] | None] = _probe_mount_fs) -> list[dict[str, Any]]:
    """Collect block and inode usage for real filesystems via `/proc/self/mounts` + `statvfs`.

    Sorts mounts by `(len(mount), mount)` before deduplication so canonical mount
    points (such as `/`) always take precedence over longer bind-mount paths, and
    deduplicates Btrfs subvolumes sharing the same underlying block device.
    """
    try:
        text = Path("/proc/self/mounts").read_text(encoding="utf8")
    except OSError as exc:
        raise AgentError(f"cannot read /proc/self/mounts: {exc}") from exc
    return build_mount_report(text, mount_probe)


def is_physical_interface(name: str) -> bool:
    """Return True when `<name>` is a physical NIC (has a /sys/class/net device link).

    Bonds, VLANs, bridges, WireGuard/tailscale devices, and libvirt bridges have
    no `device` symlink; their traffic duplicates the parent physical NIC's
    counters, so summing both double-counts.
    """
    try:
        return Path(f"/sys/class/net/{name}/device").exists()
    except OSError:
        return False


def select_traffic_interfaces(
    names: Iterable[str],
    patterns: Sequence[str],
    physical_only: bool,
    device_exists: Callable[[str], bool],
) -> list[str]:
    """Pure selector: interfaces to count for traffic, after ignore/physical filters."""
    selected: list[str] = []
    for name in names:
        if is_ignored_interface(name, patterns):
            continue
        if physical_only and not device_exists(name):
            continue
        selected.append(name)
    return selected


def get_network_counters(
    ignore_patterns: Sequence[str],
    physical_only: bool = True,
) -> dict[str, IfaceCounters] | None:
    """Read `/proc/net/dev` and return counters for monitored interfaces.

    By default only physical interfaces are counted (see `is_physical_interface`)
    so virtual layers above a NIC are not double-counted; set `physical_only=False`
    for the legacy behavior of counting everything not explicitly ignored.
    """
    try:
        text = Path("/proc/net/dev").read_text(encoding="utf8")
    except OSError:
        LOGGER.warning("failed to read /proc/net/dev")
        return None
    parsed = parse_net_dev(text)
    selected = select_traffic_interfaces(parsed.keys(), ignore_patterns, physical_only, is_physical_interface)
    return {name: parsed[name] for name in selected}


def ephemeral_port_start(configured_min: int = 0) -> int:
    """Return the UDP ephemeral port cutoff.

    If `configured_min > 0`, uses that explicit threshold (up to 65536, which
    disables UDP ephemeral filtering so high-port UDP services like WireGuard on
    51820 are tracked). When `configured_min == 0`, reads the kernel's
    `/proc/sys/net/ipv4/ip_local_port_range` lower bound.
    """
    if configured_min > 0:
        return configured_min
    try:
        return int(Path("/proc/sys/net/ipv4/ip_local_port_range").read_text(encoding="utf8").split()[0])
    except (OSError, ValueError, IndexError):
        return DEFAULT_EPHEMERAL_PORT_START


def _get_listening_ports_from_proc(ephemeral_start: int) -> set[str] | None:
    """Read listening TCP/UDP sockets directly from `/proc/net/{tcp,tcp6,udp,udp6}`."""
    specs = (
        ("/proc/net/tcp", "tcp", False),
        ("/proc/net/tcp6", "tcp", True),
        ("/proc/net/udp", "udp", False),
        ("/proc/net/udp6", "udp", True),
    )
    ports: set[str] = set()
    read_any = False
    for proc_path, netid, is_ipv6 in specs:
        path = Path(proc_path)
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf8")
        except OSError:
            continue
        read_any = True
        ports.update(parse_proc_net_sockets(text, netid, is_ipv6, ephemeral_start))
    return ports if read_any else None


def get_listening_ports(configured_ephemeral_min: int = 0) -> set[str] | None:
    """Return active listening TCP/UDP sockets via `ss`, with a `/proc/net` fallback."""
    ephemeral_start = ephemeral_port_start(configured_ephemeral_min)
    if shutil.which("ss"):
        result = run_command(["ss", "-H", "-lntu"])
        if result.returncode == 0:
            return parse_listening_ports(result.stdout, ephemeral_start)
        LOGGER.warning("ss command failed (%s); falling back to /proc/net", result.stderr.strip())
    fallback = _get_listening_ports_from_proc(ephemeral_start)
    if fallback is None:
        LOGGER.warning("unable to read listening ports from ss or /proc/net")
    return fallback


def _lc_all_env() -> dict[str, str]:
    """Return os.environ with LC_ALL=C for stable, locale-independent tool output."""
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    return env


def _journal_permission_denied(stderr: str) -> bool:
    """Return True if `journalctl` stderr indicates insufficient permissions to read system logs."""
    lower = stderr.lower()
    return (
        "not seeing messages from other users and the system" in lower
        or "no journal files were opened due to insufficient permissions" in lower
        or "insufficient permissions" in lower
    )


def anchor_journal_cursor() -> tuple[list[dict[str, Any]], str | None] | None:
    """Return the cursor of the newest journal entry without replaying historical logs."""
    result = run_command(["journalctl", "--no-pager", "-o", "json", "-n", "1"], timeout=30, env=_lc_all_env())
    if result.returncode != 0:
        LOGGER.warning("journalctl unavailable: %s", result.stderr.strip())
        return None
    if _journal_permission_denied(result.stderr):
        LOGGER.warning("insufficient permissions to read system journal: %s", result.stderr.strip())
        return None
    entries = parse_journal_json(result.stdout)
    cursor = entries[-1].get("__CURSOR") if entries else None
    return [], cursor if isinstance(cursor, str) else None


def read_journal(cursor: str | None) -> tuple[list[dict[str, Any]], str | None, bool] | None:
    """Read kernel and sshd journal entries newer than `cursor`.

    Returns `(entries, cursor, gap)`. `gap=True` means the previous cursor was
    invalid or the read timed out and the stream re-anchored at the tail, so
    entries may have been skipped — callers must surface a "journal gap" alert
    instead of silently continuing.
    Using `--after-cursor` guarantees each entry is processed once without
    maintaining growing hash sets in `state.json`. Verified empirically on
    systemd 255: `--after-cursor C -n N` yields the FIRST N entries after the
    cursor, so the bounded read itself drops nothing (the next cycle continues
    from the returned cursor).
    """
    if cursor is None:
        anchored = anchor_journal_cursor()
        if anchored is None:
            return None
        return anchored[0], anchored[1], False
    result = run_command(
        [
            "journalctl",
            "--no-pager",
            "-o",
            "json",
            "--after-cursor",
            cursor,
            "-n",
            str(JOURNAL_MAX_ENTRIES_PER_CYCLE),
            *JOURNAL_MATCHES,
        ],
        timeout=30,
        env=_lc_all_env(),
    )
    if result.returncode != 0:
        stderr_lower = result.stderr.lower()
        if "cursor" in stderr_lower or "timed out" in stderr_lower:
            LOGGER.warning(
                "journal cursor invalid or timed out, re-anchoring at tail; entries may have been skipped: %s",
                result.stderr.strip(),
            )
            anchored = anchor_journal_cursor()
            if anchored is None:
                return None
            return [], anchored[1], True
        LOGGER.warning("journalctl failed: %s", result.stderr.strip())
        return None
    if _journal_permission_denied(result.stderr):
        LOGGER.warning("insufficient permissions to read system journal: %s", result.stderr.strip())
        return None
    entries = parse_journal_json(result.stdout)
    last = entries[-1].get("__CURSOR") if entries else None
    return entries, last if isinstance(last, str) else cursor, False


def systemd_failed_units() -> set[str] | None:
    """Return the set of currently failed systemd unit names."""
    result = run_command(["systemctl", "--failed", "--no-legend", "--plain"], timeout=12, env=_lc_all_env())
    if result.returncode != 0:
        LOGGER.warning("systemctl --failed failed: %s", result.stderr.strip())
        return None
    failed: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        # Strip leading bullet symbol if an older systemctl version emits one.
        if parts[0] == "●":
            parts = parts[1:]
        if parts:
            failed.add(parts[0])
    return failed


def timedatectl_ntp_state() -> bool | None:
    """Return True if the system clock is NTP-synchronized, False if not, or None if unavailable."""
    result = run_command(
        ["timedatectl", "show", "--property=NTPSynchronized", "--value"], timeout=12, env=_lc_all_env()
    )
    if result.returncode == 0:
        value = result.stdout.strip().lower()
        if value in {"yes", "no"}:
            return value == "yes"
    # Fallback for older systemd versions without `timedatectl show`.
    status_res = run_command(["timedatectl", "status"], timeout=12, env=_lc_all_env())
    if status_res.returncode != 0:
        return None
    for line in status_res.stdout.splitlines():
        lower = line.strip().lower()
        if lower.startswith(("system clock synchronized:", "ntp synchronized:")):
            val = lower.partition(":")[2].strip()
            if val in {"yes", "no"}:
                return val == "yes"
    return None


def boot_id() -> str:
    """Return the kernel's unique boot UUID from `/proc/sys/kernel/random/boot_id`."""
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf8").strip()
        return value or "unknown"
    except OSError:
        return "unknown"


def uptime_seconds() -> float:
    """Return system uptime in seconds from `/proc/uptime` (0.0 when unreadable)."""
    try:
        return float(Path("/proc/uptime").read_text(encoding="utf8").split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def get_vmstat() -> dict[str, int]:
    """Read `/proc/vmstat` into a key/value map (used for pswpin/pswpout rates)."""
    data: dict[str, int] = {}
    try:
        text = Path("/proc/vmstat").read_text(encoding="utf8")
    except OSError:
        return data
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            data[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return data


def swap_activity_rate(
    previous: Sequence[float] | None,
    current: Sequence[float],
    elapsed_seconds: float,
) -> float | None:
    """Return swap-in/out activity in pages/second (the busier direction), or None.

    `previous`/`current` are `[pswpin, pswpout]` snapshots. Unlike sticky swap
    usage, the rate distinguishes active thrashing from pages that merely stay
    on disk since boot.
    """
    if previous is None or len(previous) < 2 or len(current) < 2 or elapsed_seconds <= 0:
        return None
    try:
        swap_in = max(0.0, float(current[0]) - float(previous[0]))
        swap_out = max(0.0, float(current[1]) - float(previous[1]))
    except (TypeError, ValueError):
        return None
    return max(swap_in, swap_out) / float(elapsed_seconds)


_CONTAINER_CGROUP_RE = re.compile(r"\b(?:docker|containerd|kubepods|lxc|libpod)\b")


def is_containerized(dockerenv: bool, containerenv: bool, init_cgroup: str) -> bool:
    """Pure container-detection predicate from /.dockerenv, /.containerenv, /proc/1/cgroup."""
    return dockerenv or containerenv or bool(_CONTAINER_CGROUP_RE.search(init_cgroup))


def detect_container() -> bool:
    """Return True when running inside a container (Docker/Podman/LXC/K8s)."""
    try:
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf8")
    except OSError:
        cgroup = ""
    return is_containerized(Path("/.dockerenv").exists(), Path("/run/.containerenv").exists(), cgroup)


def has_lxcfs() -> bool:
    """Return True when lxcfs virtualizes /proc CPU/mem stats for this container."""
    return Path("/var/lib/lxcfs").exists()


def parse_cpu_max(text: str) -> float | None:
    """Parse a cgroup v2 `cpu.max` value into a CPU-core quota; None when unlimited."""
    parts = text.split()
    if len(parts) != 2 or parts[0] == "max":
        return None
    try:
        quota, period = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    if quota <= 0 or period <= 0:
        return None
    return quota / period


def cgroup_cpu_quota() -> float | None:
    """Return the container's CPU quota in cores (cgroup v2, then v1); None if unlimited."""
    try:
        quota = parse_cpu_max(Path("/sys/fs/cgroup/cpu.max").read_text(encoding="utf8"))
        if quota is not None:
            return quota
    except OSError:
        pass
    try:
        quota_us = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text(encoding="utf8"))
        period_us = int(Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text(encoding="utf8"))
        if quota_us > 0 and period_us > 0:
            return quota_us / period_us
    except (OSError, ValueError):
        pass
    return None


def effective_cpu_count() -> int:
    """CPU cores the agent may actually use: affinity, capped by the cgroup quota."""
    count = get_cpu_count()
    quota = cgroup_cpu_quota()
    if quota is not None:
        return max(1, min(count, int(quota)))
    return count


def sd_notify(message: str) -> bool:
    """Send a systemd notification datagram to $NOTIFY_SOCKET via raw AF_UNIX.

    Used for READY=1 and WATCHDOG=1 keepalives (stdlib only; no python-systemd).
    Best-effort: returns False when NOTIFY_SOCKET is unset or the send fails.
    """
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]  # abstract namespace socket
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode("utf8"))
        return True
    except OSError:
        return False


def network_errors_significant(finished: dict[str, int], minimum: int) -> bool:
    """Return True when a rolled network-error window deserves a report."""
    return sum(int(finished.get(key, 0)) for key in NETWORK_ERROR_KEYS) >= max(0, int(minimum))


def record_probe_result(
    state: dict[str, Any],
    probe: str,
    ok: bool,
    notify: Callable[[str, str, str], None],
    blind_after: int,
) -> None:
    """Track consecutive per-probe failures and alert when the monitor goes blind.

    A probe that keeps failing never alerts by itself; after `blind_after`
    consecutive failures a single "blind" alert is enqueued, and a single
    "recovered" alert fires when the probe works again.
    """
    failures = state.setdefault("probe_failures", {})
    blind = state.setdefault("blind_alerted", {})
    if not isinstance(failures, dict):
        failures = {}
        state["probe_failures"] = failures
    if not isinstance(blind, dict):
        blind = {}
        state["blind_alerted"] = blind
    if ok:
        if failures.get(probe, 0) >= blind_after and blind.get(probe):
            notify(f"👁️ Probe '{probe}' recovered", f"The {probe} probe is producing data again.", "info")
        failures[probe] = 0
        blind.pop(probe, None)
    else:
        failures[probe] = int(failures.get(probe, 0)) + 1
        if failures[probe] >= blind_after and not blind.get(probe):
            notify(
                f"👁️ Probe '{probe}' is blind",
                f"The {probe} probe has failed {failures[probe]} cycles in a row; "
                "monitoring data for it is missing.",
                "warning",
            )
            blind[probe] = True


# --------------------------------------------------------------------------
# Prerequisite verification, package installation, and systemd setup
# --------------------------------------------------------------------------
# Binary-to-package mapping for supported package managers (systemd distros
# only). Arch (pacman) and Alpine (apk, no systemd) are intentionally NOT
# supported for automatic installation; the installer prints manual
# instructions instead.
_SHARED_SYSTEMD_TOOLS = {
    "systemctl": "systemd",
    "journalctl": "systemd",
    "timedatectl": "systemd",
    "id": "coreutils",
    "ca-certificates": "ca-certificates",
}
_RPM_TOOLS = {"ss": "iproute", "useradd": "shadow-utils", "usermod": "shadow-utils"}
PACKAGE_MAP: dict[str, dict[str, str]] = {
    "apt-get": {"ss": "iproute2", "useradd": "passwd", "usermod": "passwd", **_SHARED_SYSTEMD_TOOLS},
    "dnf": {**_RPM_TOOLS, **_SHARED_SYSTEMD_TOOLS},
    "yum": {**_RPM_TOOLS, **_SHARED_SYSTEMD_TOOLS},
    "zypper": {"ss": "iproute2", "useradd": "shadow", "usermod": "shadow", **_SHARED_SYSTEMD_TOOLS},
}
# Managers we can detect but must never drive automatically.
UNSAFE_PACKAGE_MANAGERS = ("pacman", "apk")


def _has_ca_certificates() -> bool:
    """Return True if a usable TLS CA certificate bundle is installed on the host."""
    verify_paths = ssl.get_default_verify_paths()
    for candidate in (
        verify_paths.cafile,
        verify_paths.capath,
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/certs",
    ):
        if candidate and Path(candidate).exists():
            return True
    return False


def _detect_package_manager() -> str | None:
    """Return the host's package manager binary name (supported or unsafe-listed)."""
    for manager in PACKAGE_MAP:
        if shutil.which(manager):
            return manager
    for manager in UNSAFE_PACKAGE_MANAGERS:
        if shutil.which(manager):
            return manager
    return None


def install_missing_packages(missing_items: Sequence[str]) -> tuple[bool, str]:
    """Attempt to install missing system prerequisites using the host's package manager."""
    if os.geteuid() != 0:
        return False, "root privileges required to auto-install missing packages: " + ", ".join(missing_items)

    manager = _detect_package_manager()
    if manager in UNSAFE_PACKAGE_MANAGERS:
        return False, (
            f"{manager} is not supported for automatic installation "
            "(pacman -Sy causes partial upgrades; Alpine lacks systemd). "
            "Install these packages manually: " + ", ".join(missing_items)
        )
    if not manager:
        return False, "no supported package manager found to install: " + ", ".join(missing_items)

    pkg_lookup = PACKAGE_MAP.get(manager, {})
    packages = sorted({pkg_lookup.get(item, item) for item in missing_items})
    if not packages:
        return True, "no packages needed"

    LOGGER.info("installing missing prerequisite packages via %s: %s", manager, ", ".join(packages))
    env = dict(os.environ)

    if manager == "apt-get":
        env["DEBIAN_FRONTEND"] = "noninteractive"
        run_command(["apt-get", "update", "-qq"], timeout=120, env=env)
        cmd = ["apt-get", "install", "-y", "--no-install-recommends", *packages]
    elif manager in {"dnf", "yum"}:
        cmd = [manager, "install", "-y", *packages]
    elif manager == "zypper":
        cmd = ["zypper", "--non-interactive", "install", "-y", *packages]
    else:
        return False, f"unsupported package manager: {manager}"

    res = run_command(cmd, timeout=300, env=env)
    if res.returncode != 0:
        detail = (res.stderr or res.stdout).strip()
        return False, f"package installation via {manager} failed: {detail}"
    return True, f"installed packages via {manager}: {', '.join(packages)}"


# Tools each feature needs when enabled. Features not listed here rely only on
# /proc (always present on Linux).
FEATURE_REQUIRED_TOOLS: dict[str, tuple[str, ...]] = {
    "ssh_failures": ("journalctl",),
    "oom": ("journalctl",),
    "systemd_services": ("systemctl",),
    "time_sync": ("timedatectl",),
    "listening_ports": ("ss",),  # the /proc/net fallback may satisfy this
}


def required_tools_for_config(cfg: dict[str, Any] | None, for_install: bool = False) -> list[str]:
    """Return external binaries required by the enabled features (pure; testable)."""
    features = (cfg or {}).get("features", FEATURE_DEFAULTS)
    tools: set[str] = set()
    for feature, needed in FEATURE_REQUIRED_TOOLS.items():
        if features.get(feature, FEATURE_DEFAULTS.get(feature, False)):
            tools.update(needed)
    if for_install:
        tools.update({"systemctl", "useradd", "usermod", "id"})
    if "ss" in tools and Path("/proc/net/tcp").exists():
        tools.discard("ss")  # pure-Python /proc/net fallback is available
    return sorted(tools)


def ensure_dependencies(
    cfg: dict[str, Any] | None = None,
    auto_install: bool = False,
    for_install: bool = False,
) -> tuple[bool, str]:
    """Verify binaries needed by the ENABLED features (plus CA certs for HTTPS backends).

    `auto_install=True` (consent-gated behind --auto-install-deps) installs
    missing packages; otherwise the missing items are reported so the caller
    can abort or ask the user for consent.
    """
    ensure_standard_path()
    required_binaries = required_tools_for_config(cfg, for_install=for_install)
    missing = [binary for binary in required_binaries if not shutil.which(binary)]

    backend = str((cfg or {}).get("alerts", {}).get("backend", ALERT_DEFAULTS["backend"]))
    if auto_install and backend in {"telegram", "webhook"} and not _has_ca_certificates():
        missing.append("ca-certificates")

    if not missing:
        return True, "required tools available"

    if auto_install:
        installed_ok, install_msg = install_missing_packages(missing)
        if not installed_ok:
            LOGGER.warning("%s", install_msg)
            return False, install_msg
        still_missing = [binary for binary in required_binaries if not shutil.which(binary)]
        if not still_missing:
            return True, install_msg
        return False, "missing required tools: " + ", ".join(still_missing)

    return False, "missing required tools: " + ", ".join(missing)


def _group_exists(group_name: str) -> bool:
    """Return True if the POSIX group `group_name` exists on the system."""
    try:
        grp.getgrnam(group_name)
        return True
    except KeyError:
        return False


def _nologin_shell() -> str:
    """Return a valid non-interactive shell path for the system service user."""
    for candidate in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"):
        if Path(candidate).exists():
            return candidate
    return "/usr/sbin/nologin"


def install_service_user() -> None:
    """Create the `auto-monitoring` system user and grant journal read group membership."""
    if run_command(["id", "-u", NAME]).returncode != 0:
        result = run_command(
            [
                "useradd",
                "--system",
                "--home-dir",
                str(STATE_DIR),
                "--shell",
                _nologin_shell(),
                "--user-group",
                NAME,
            ]
        )
        if result.returncode != 0:
            raise AgentError(f"unable to create user {NAME}: {result.stderr.strip()}")
        _lookup_service_uid_gid.cache_clear()

    # Ensure the service user belongs to `systemd-journal` so both the systemd
    # unit and `sudo -u auto-monitoring Auto-Monitoring.py check` can read
    # kernel and sshd journal entries without root privileges. `adm` is NOT
    # granted: it would expose all of /var/log/*, far beyond what is needed.
    if shutil.which("usermod") and _group_exists("systemd-journal"):
        run_command(["usermod", "-a", "-G", "systemd-journal", NAME])
    # Repair older installs that added the service user to `adm`.
    if _group_exists("adm"):
        try:
            if NAME in grp.getgrnam("adm").gr_mem and shutil.which("gpasswd"):
                run_command(["gpasswd", "-d", NAME, "adm"])
        except (KeyError, OSError):
            pass


def unit_file_text() -> str:
    """Generate the hardened systemd unit file for `auto-monitoring.service`.

    Uses `ProtectHome=read-only` rather than `ProtectHome=true` so separate
    `/home` partitions remain visible to `statvfs()` for disk/inode monitoring.
    Every sandbox directive was checked against the agent's real needs:
    - AF_NETLINK stays in RestrictAddressFamilies because the `ss` child needs it.
    - ProtectKernelLogs is safe because journalctl reads journal FILES via the
      systemd-journal group, not /dev/kmsg.
    - ProtectKernelTunables/ControlGroups keep /proc/sys and /sys/fs/cgroup
      readable (the agent only READS ip_local_port_range, boot_id and cpu.max).
    - CapabilityBoundingSet= (empty) is fine: the agent only makes outbound
      connections from ephemeral ports and never binds privileged ports.
    - Unknown directives are ignored by older systemd versions with a warning.
    """
    supplementary = "SupplementaryGroups=systemd-journal\n" if _group_exists("systemd-journal") else ""
    return f"""[Unit]
Description=Low-noise Linux host alerting agent
Wants=network-online.target
After=network-online.target systemd-journald.service

[Service]
Type=simple
User={NAME}
Group={NAME}
{supplementary}ExecStart={sys.executable} {INSTALL_ROOT}/Auto-Monitoring.py run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=15s
WatchdogSec={WATCHDOG_SEC_TEXT}
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallArchitectures=native
ReadWritePaths={STATE_DIR}
UMask=0027

[Install]
WantedBy=multi-user.target
"""


def print_feature_menu(cfg: dict[str, Any] | None = None) -> None:
    """Display available monitoring checks, marking which ones are enabled."""
    enabled = (cfg or {}).get("features", {})
    features = [
        ("cpu", "Detects sustained high CPU usage (tick-based)."),
        ("load", "Detects sustained high load average per core (optional)."),
        ("ram", "Detects sustained high memory usage."),
        ("swap", "Detects high swap usage."),
        ("disk", "Detects high filesystem usage."),
        ("inode", "Detects inode exhaustion."),
        ("traffic", "Tracks daily RX/TX network traffic."),
        ("network_errors", "Aggregates interface errors and packet drops."),
        ("ssh_failures", "Aggregates failed SSH authentication attempts."),
        ("oom", "Detects Linux OOM events."),
        ("systemd_services", "Detects services that remain failed."),
        ("reboot", "Detects system reboot."),
        ("time_sync", "Detects time synchronization problems."),
        ("listening_ports", "Detects unexpected listening-port changes."),
    ]
    print("\nMonitoring features:\n")
    for name, description in features:
        is_on = enabled.get(name, FEATURE_DEFAULTS.get(name, False))
        marker = "✓" if is_on else " "
        print(f"[{marker}] {name.replace('_', ' ').title()}\n    {description}\n")


def _safe_input(prompt: str) -> str:
    """Read a line from stdin, returning an empty string on EOF (non-interactive shells)."""
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        return ""


def _prompt_int_in_range(prompt_label: str, default: int, low: int, high: int) -> int:
    """Prompt the user for an integer within `[low, high]`, re-prompting on invalid input."""
    while True:
        raw = _safe_input(f"{prompt_label} [{default}] ")
        if not raw:
            return default
        try:
            value = int(raw)
            if low <= value <= high:
                return value
        except ValueError:
            pass
        print(f"  Please enter an integer between {low} and {high}.")


def prompt_for_install_config(existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Interactively prompt for configuration values, preserving existing defaults."""
    cfg = merge_config(default_config(), existing)

    for feature_name, enabled in list(cfg["features"].items()):
        while True:
            raw = _safe_input(f"Enable {feature_name}? [{str(enabled).lower()}] ").lower()
            if not raw:
                break
            try:
                cfg["features"][feature_name] = _parse_bool("features", feature_name, raw)
                break
            except ValueError as exc:
                print(f"  {exc} — please answer yes/no (or 1/0, on/off).")

    for item in ("cpu", "ram", "swap", "disk", "inode"):
        cfg["thresholds"][item] = _prompt_int_in_range(
            f"{item.title()} threshold %", int(cfg["thresholds"][item]), 1, 100
        )

    if cfg["features"].get("load", False):
        cfg["thresholds"]["load_percent"] = _prompt_int_in_range(
            "Load average per-core threshold %", int(cfg["thresholds"]["load_percent"]), 1, 1000
        )

    cfg["thresholds"]["traffic_gb_daily"] = _prompt_int_in_range(
        "Traffic daily limit in GB", int(cfg["thresholds"]["traffic_gb_daily"]), 1, 1_000_000
    )

    for key, label in (
        ("check_interval_seconds", "Check interval seconds"),
        ("persistence_samples", "Persistence samples"),
        ("recovery_minutes", "Recovery minutes"),
        ("aggregation_window_hours", "Aggregation window hours"),
        ("udp_ephemeral_port_min", "UDP ephemeral port cutoff (0=auto, 65536=track all UDP)"),
    ):
        low, high = MONITORING_RANGES[key]
        cfg["monitoring"][key] = _prompt_int_in_range(label, int(cfg["monitoring"][key]), low, high)

    current_ignore = cfg["monitoring"]["ignore_interfaces"]
    raw_ignore = _safe_input(f"Ignore interfaces (comma-separated globs) [{current_ignore}] ")
    if raw_ignore:
        cfg["monitoring"]["ignore_interfaces"] = raw_ignore

    current_backend = cfg["alerts"]["backend"]
    while True:
        raw_backend = _safe_input(f"Alert backend [stdout|telegram|webhook] [{current_backend}] ").lower()
        chosen = raw_backend or current_backend
        if chosen in {"stdout", "telegram", "webhook"}:
            cfg["alerts"]["backend"] = chosen
            break
        print("  Please choose one of: stdout, telegram, webhook.")

    if cfg["alerts"]["backend"] == "telegram":
        has_token = " [configured]" if cfg["alerts"].get("telegram_bot_token") else ""
        token = getpass.getpass(f"Telegram bot token{has_token}: ").strip()
        if token:
            cfg["alerts"]["telegram_bot_token"] = token
        current_chat = cfg["alerts"].get("telegram_chat_id", "")
        chat_prompt = f" [{current_chat}]" if current_chat else ""
        chat_id = _safe_input(f"Telegram chat ID{chat_prompt}: ")
        if chat_id:
            cfg["alerts"]["telegram_chat_id"] = chat_id
    elif cfg["alerts"]["backend"] == "webhook":
        current_url = cfg["alerts"].get("webhook_url", "")
        url_prompt = f" [{current_url}]" if current_url else ""
        url = _safe_input(f"Webhook URL{url_prompt}: ")
        if url:
            cfg["alerts"]["webhook_url"] = url
        has_bearer = " [configured]" if cfg["alerts"].get("webhook_bearer_token") else ""
        bearer = getpass.getpass(f"Webhook bearer token (optional){has_bearer}: ").strip()
        if bearer:
            cfg["alerts"]["webhook_bearer_token"] = bearer

    validate_config(cfg)
    return cfg


def _systemd_running() -> bool:
    """Return True only when systemd is actually PID 1 on this host."""
    return Path("/run/systemd/system").exists()


def _check_python_version() -> None:
    """Fail early on Python versions missing stdlib features the agent relies on."""
    if sys.version_info < (3, 8):
        raise AgentError(f"Python 3.8+ is required, found {sys.version.split()[0]}")


def install(non_interactive: bool = False, auto_install_deps: bool = False, force: bool = False) -> int:
    """Install prerequisites, user account, configuration, and systemd service."""
    if os.geteuid() != 0:
        raise AgentError("install requires root privileges; run with sudo")
    _check_python_version()
    if not _systemd_running():
        raise AgentError("systemd is not running on this host (is PID 1 systemd?); installation aborted")

    # Step 1: verify prerequisites. Packages are only installed with explicit
    # consent (--auto-install-deps); otherwise print what is missing and abort.
    ok, detail = ensure_dependencies(auto_install=auto_install_deps, for_install=True)
    if not ok:
        raise AgentError(
            detail
            + "\nRe-run with --auto-install-deps to install them automatically, or install them manually."
        )

    # Step 2: gather configuration (may be interactive) BEFORE mutating the system.
    print_feature_menu()
    if CONFIG_PATH.exists():
        existing_cfg = load_config(CONFIG_PATH)
        print(f"Existing config found at {CONFIG_PATH}")
        if non_interactive:
            cfg = existing_cfg
        else:
            answer = _safe_input("Edit existing configuration? [y/N]: ").lower()
            cfg = prompt_for_install_config(existing_cfg) if answer in {"y", "yes"} else existing_cfg
    else:
        cfg = default_config() if non_interactive else prompt_for_install_config()
    validate_config(cfg)

    if non_interactive and str(cfg["alerts"].get("backend", "stdout")) == "stdout" and not force:
        print(
            "\nWARNING: the alert backend is 'stdout', so nobody is notified — alerts are only"
            "\nvisible in the service journal. Configure Telegram/Webhook with `sudo"
            f"\n{sys.executable} {Path(__file__).resolve()} install` (interactive), or pass --force to accept."
        )
        if not non_interactive or not _ask_continue():
            raise AgentError("installation aborted: configure an alert backend (telegram/webhook) or pass --force")

    # Step 3: mutate the system, rolling back what we created if anything fails.
    install_service_user()
    ensure_dirs()
    write_config(cfg)
    with state_lock():
        state = load_state()
        save_state(state)

    INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
    target = INSTALL_ROOT / "Auto-Monitoring.py"
    source_path = Path(__file__).resolve()
    if source_path != target.resolve():
        shutil.copy2(source_path, target)
    os.chmod(target, 0o755)

    service_file = Path("/etc/systemd/system") / SERVICE_NAME
    service_file.write_text(unit_file_text(), encoding="utf8")
    os.chmod(service_file, 0o644)
    try:
        result = run_command(["systemctl", "daemon-reload"], timeout=30)
        if result.returncode != 0:
            raise AgentError(f"daemon-reload failed: {result.stderr.strip()}")

        enable = run_command(["systemctl", "enable", SERVICE_NAME], timeout=30)
        if enable.returncode != 0:
            raise AgentError(f"systemctl enable failed: {enable.stderr.strip()}")

        # Use `restart` so upgrading an already-running installation reloads the new code.
        restart = run_command(["systemctl", "restart", SERVICE_NAME], timeout=30)
        if restart.returncode != 0:
            raise AgentError(f"systemctl restart failed: {restart.stderr.strip()}")

        sys_check = run_command(["systemctl", "is-active", SERVICE_NAME], timeout=12)
        if sys_check.stdout.strip() != "active":
            LOGGER.warning("service is not active yet: %s", sys_check.stdout.strip() or sys_check.stderr.strip())
    except BaseException:
        print("installation failed; rolling back service changes...", file=sys.stderr)
        run_command(["systemctl", "disable", "--now", SERVICE_NAME], timeout=30)
        try:
            service_file.unlink(missing_ok=True)
            run_command(["systemctl", "daemon-reload"], timeout=30)
        except OSError:
            pass
        raise

    # Step 4: prove the alert path works; a silent monitor is worse than no monitor.
    if str(cfg["alerts"].get("backend", "stdout")) != "stdout":
        sender = AlertSender(cfg)
        if not sender.deliver(
            make_alert("Auto-Monitoring installation test", "Installer verified the configured backend.", "info")
        ):
            print(
                "ERROR: the post-installation test alert could not be delivered; the service is running but "
                "notifications are NOT working. Check your credentials, or rerun the installer.",
                file=sys.stderr,
            )
            if not force:
                return 1

    print(f"Configuration installed at {CONFIG_PATH}")
    print(f"Service installed as {SERVICE_NAME}")
    return 0


def _ask_continue() -> bool:
    """Ask for yes/no confirmation; abort when stdin is not interactive."""
    if not sys.stdin.isatty():
        return False
    return _safe_input("Continue anyway? [y/N]: ").lower() in {"y", "yes"}


def uninstall() -> int:
    """Best-effort removal of the service unit; keeps config and state for review."""
    if os.geteuid() != 0:
        raise AgentError("uninstall requires root privileges; run with sudo")
    run_command(["systemctl", "disable", "--now", SERVICE_NAME], timeout=30)
    service_file = Path("/etc/systemd/system") / SERVICE_NAME
    try:
        service_file.unlink(missing_ok=True)
    except OSError as exc:
        LOGGER.warning("could not remove %s: %s", service_file, exc)
    run_command(["systemctl", "daemon-reload"], timeout=30)
    if INSTALL_ROOT.exists():
        shutil.rmtree(INSTALL_ROOT, ignore_errors=True)
    print(f"Service {SERVICE_NAME} removed.")
    print(f"Kept for review: {CONFIG_PATH} (root-owned), {STATE_DIR} (service-owned), user '{NAME}'.")
    print("Remove them manually if they are no longer needed.")
    return 0


# --------------------------------------------------------------------------
# Monitoring cycle
# --------------------------------------------------------------------------
def _format_resource_title(name: str, suffix: str) -> str:
    """Format a resource alert title without uppercasing case-sensitive mount paths."""
    if ":" in name:
        kind, _, target = name.partition(":")
        return f"{kind.upper()} ({target}) {suffix}"
    return f"{name.upper()} {suffix}"


def run_agent_once(cfg: dict[str, Any]) -> bool:
    """Run one monitoring cycle under the exclusive state lock. Returns False if any probe failed."""
    with state_lock():
        return _run_cycle(cfg)


def _run_cycle(cfg: dict[str, Any]) -> bool:
    """Execute all enabled monitoring probes, update incidents/windows, and flush alerts.

    Every probe runs inside its own exception guard: one failing probe cannot
    abort the others, and state is ALWAYS saved in the `finally` block so a
    mid-cycle crash never discards the window/outbox/cursor updates that
    already happened (a poisoned cycle that saves nothing would otherwise
    repeat forever).
    """
    cfg = merge_config(default_config(), cfg)
    state = load_state()
    sender = AlertSender(cfg)
    features = cfg["features"]
    thresholds = cfg["thresholds"]
    monitoring = cfg["monitoring"]
    tracker = ResourceIncidentTracker(
        persistence_samples=monitoring["persistence_samples"],
        recovery_minutes=monitoring["recovery_minutes"],
    )
    tracker.load(state.get("resource_incidents"))
    window_seconds = int(monitoring["aggregation_window_hours"]) * 3600
    now = time.time()
    result = True
    blind_after = max(1, int(monitoring["persistence_samples"]))
    failed_probes: set[str] = set()

    def notify(title: str, body: str, severity: str = "warning") -> None:
        enqueue_alert(state, title, body, severity)

    def probe_context(probe: str):
        """Context manager: an exception in one probe marks it failed, not the cycle."""
        @contextmanager
        def guard() -> Iterator[None]:
            nonlocal result
            try:
                yield
            except Exception as exc:  # noqa: BLE001 - probe isolation is the point
                LOGGER.exception("probe %s failed: %s", probe, exc)
                result = False
                failed_probes.add(probe)
        return guard()

    def check_resource(name: str, metric: float, threshold: int) -> None:
        event = tracker.observe(name, metric >= threshold, now=now)
        if event == "triggered":
            notify(
                _format_resource_title(name, "alert"),
                f"{name} reached {metric:.1f}% (threshold: {threshold}%)",
                "warning",
            )
        elif event == "resolved":
            notify(
                _format_resource_title(name, "resolved"),
                f"{name} recovered to {metric:.1f}% (below {threshold}%)",
                "info",
            )
        elif event == "relapse":
            LOGGER.info("%s went bad again while recovering; alert already active", name)

    try:
        # Check boot ID early so kernel counter baselines from a previous boot are
        # invalidated before CPU and network deltas are computed.
        current_boot = boot_id()
        previous_boot = state.get("boot_id")
        rebooted = bool(previous_boot and current_boot != "unknown" and previous_boot != current_boot)
        if rebooted:
            state.pop("last_cpu_ticks", None)
            state.pop("last_swap_activity", None)
            if isinstance(state.get("traffic"), dict):
                state["traffic"]["snapshot"] = {}
            if isinstance(state.get("network_window"), dict):
                state["network_window"]["snapshot"] = {}

        if features.get("reboot", True):
            if current_boot == "unknown":
                result = False
            else:
                if rebooted:
                    notify("🔄 System Rebooted", f"Boot ID changed from {previous_boot} to {current_boot}", "info")
                state["boot_id"] = current_boot
        elif current_boot != "unknown":
            state["boot_id"] = current_boot

        # Container awareness: inside Docker/Podman/LXC without lxcfs, CPU/RAM
        # and load are host-wide, not container-scoped; warn once, measure
        # load% against the effective (quota-capped) CPU count for consistency.
        cpu_count = get_cpu_count()
        if detect_container() and not has_lxcfs():
            if not state.get("container_warned"):
                state["container_warned"] = True
                LOGGER.warning(
                    "running inside a container without lxcfs: CPU/RAM/load reflect the HOST, not this container"
                )
            cpu_count = effective_cpu_count()

        # CPU: tick delta only. Skipped (not reported as 0%) on the first cycle.
        if features.get("cpu", True):
            with probe_context("cpu"):
                ticks = get_cpu_ticks()
                usage = cpu_usage_percent(state.get("last_cpu_ticks"), ticks)
                state["last_cpu_ticks"] = list(ticks)
                if usage is not None:
                    check_resource("cpu", usage, thresholds["cpu"])

        # Load average: separate optional signal (1-minute load as percentage of usable cores).
        if features.get("load", False):
            with probe_context("load"):
                load_percent = 100.0 * get_load_average() / max(1, cpu_count)
                check_resource("load", load_percent, thresholds["load_percent"])

        # Memory and Swap probes.
        mem = None
        if features.get("ram", True) or features.get("swap", True):
            with probe_context("memory"):
                mem = get_meminfo()
        if mem is not None and features.get("ram", True):
            total = max(mem.get("MemTotal", 1), 1)
            if "MemAvailable" in mem:
                available = mem["MemAvailable"]
            else:
                available = (
                    mem.get("MemFree", 0)
                    + mem.get("Buffers", 0)
                    + mem.get("Cached", 0)
                    + mem.get("SReclaimable", 0)
                )
            ram_usage = min(100.0, max(0.0, 100.0 * (total - available) / total))
            check_resource("ram", ram_usage, thresholds["ram"])

        if mem is not None and features.get("swap", True):
            swap_total = mem.get("SwapTotal", 0)
            swap_free = mem.get("SwapFree", 0)
            swap_usage = min(100.0, max(0.0, 100.0 * (swap_total - swap_free) / swap_total)) if swap_total > 0 else 0.0
            check_resource("swap", swap_usage, thresholds["swap"])
            # Swap activity rate: sticky usage stays high until reboot, but real
            # thrashing shows up as pswpin/pswpout deltas per second.
            with probe_context("swap_activity"):
                vmstat = get_vmstat()
                current_vm = [vmstat.get("pswpin", 0), vmstat.get("pswpout", 0)]
                previous_vm = state.get("last_swap_activity")
                cycle_elapsed = now - float(state.get("last_cycle_time", now - int(monitoring["check_interval_seconds"])))
                rate = swap_activity_rate(previous_vm, current_vm, cycle_elapsed)
                state["last_swap_activity"] = current_vm
                if rate is not None and rate >= float(thresholds["swap_rate_pages_per_s"]):
                    if not state.get("swap_activity_alerted"):
                        state["swap_activity_alerted"] = True
                        notify(
                            "🔁 Swap Thrashing",
                            f"Swap activity {rate:.0f} pages/s "
                            f"(threshold {thresholds['swap_rate_pages_per_s']}/s) — active paging in/out.",
                            "warning",
                        )
                elif rate is not None and state.get("swap_activity_alerted"):
                    state["swap_activity_alerted"] = False
                    notify("🔁 Swap Thrashing ended", f"Swap activity dropped to {rate:.0f} pages/s.", "info")

        # Disk block and inode usage probes.
        if features.get("disk", True) or features.get("inode", True):
            with probe_context("filesystem"):
                mounts: list[dict[str, Any]] = get_mounts()
            present_mounts: set[str] = set()
            for mount in mounts:
                present_mounts.add(mount["mount"])
                if mount.get("error"):
                    result = False  # statvfs failed/hung for this mount
                    failed_probes.add("filesystem")
                    continue
                if features.get("disk", True):
                    key = f"disk:{mount['mount']}"
                    check_resource(key, float(mount["percent"]), thresholds["disk"])
                if features.get("inode", True) and mount["inode_percent"] is not None:
                    key = f"inode:{mount['mount']}"
                    check_resource(key, float(mount["inode_percent"]), thresholds["inode"])
            # Prune only mount points that truly vanished from /proc/self/mounts;
            # a single failed statvfs must not delete an active incident.
            tracker.prune("disk:", {f"disk:{m}" for m in present_mounts})
            tracker.prune("inode:", {f"inode:{m}" for m in present_mounts})

        # Network traffic and interface error/drop probes.
        counters: dict[str, IfaceCounters] | None = None
        if features.get("traffic", True) or features.get("network_errors", True):
            with probe_context("network"):
                counters = get_network_counters(
                    parse_ignore_patterns(monitoring["ignore_interfaces"]),
                    physical_only=bool(monitoring.get("traffic_physical_only", True)),
                )
            if counters is None:
                result = False
                failed_probes.add("network")

        if features.get("traffic", True) and counters is not None:
            traffic = state.setdefault("traffic", {})
            if not isinstance(traffic, dict):
                traffic = {}
                state["traffic"] = traffic
            update_traffic_state(traffic, counters, datetime.now(timezone.utc).strftime("%Y-%m-%d"))
            rx_total = sum(int(entry[0]) for entry in traffic["totals"].values() if isinstance(entry, list) and len(entry) >= 2)
            tx_total = sum(int(entry[1]) for entry in traffic["totals"].values() if isinstance(entry, list) and len(entry) >= 2)
            snapshot = build_traffic_snapshot(rx_total, tx_total)
            traffic_limit = int(thresholds["traffic_gb_daily"]) * 1_000_000_000
            if snapshot["total_bytes"] >= traffic_limit and not traffic.get("alerted"):
                notify(
                    "📊 Traffic Alert",
                    f"Total: {snapshot['total_gb_decimal']:.1f} GB\nRX: {snapshot['rx_gb_decimal']:.1f} GB\n"
                    f"TX: {snapshot['tx_gb_decimal']:.1f} GB\nLimit: {thresholds['traffic_gb_daily']} GB/day",
                    "warning",
                )
                traffic["alerted"] = True

        if features.get("network_errors", True) and counters is not None:
            window = state.get("network_window")
            if not isinstance(window, dict):
                window = new_network_window(now)
                state["network_window"] = window
            # Accumulate current cycle deltas first so errors occurring in the final
            # interval of a window are included when the window rolls over.
            accumulate_network_errors(window, counters)
            finished = roll_network_window(window, now, window_seconds)
            if finished and network_errors_significant(finished, monitoring.get("network_error_min", 0)):
                notify(
                    "🌐 Network Report",
                    "\n".join(
                        [
                            f"RX errors: {finished['rx_errors']}",
                            f"TX errors: {finished['tx_errors']}",
                            f"RX drops: {finished['rx_drops']}",
                            f"TX drops: {finished['tx_drops']}",
                        ]
                    ),
                    "warning",
                )

        # Journald probes: SSH failures and kernel OOM events.
        ssh_enabled = features.get("ssh_failures", True)
        oom_enabled = features.get("oom", True)
        if ssh_enabled or oom_enabled:
            with probe_context("journal"):
                fetched = read_journal(state.get("journal_cursor"))
            if fetched is None:
                result = False
                failed_probes.add("journal")
            else:
                entries, cursor, gap = fetched
                if gap:
                    notify(
                        "📜 Journal Gap",
                        "The journal cursor was invalid or rotated; entries during the gap may be missing "
                        "(SSH failures and OOM events from that period are not counted).",
                        "warning",
                    )
                ssh_window = state.get("ssh_window")
                if not isinstance(ssh_window, dict):
                    ssh_window = new_ssh_window(now)
                    state["ssh_window"] = ssh_window
                oom_lines: list[str] = []
                for entry in entries:
                    message = entry_message(entry)
                    if not message:
                        continue
                    if entry.get("_TRANSPORT") == "kernel":
                        if oom_enabled and is_oom_event(message):
                            oom_lines.append(message)
                    elif ssh_enabled and is_sshd_entry(entry) and is_ssh_failed_attempt_line(message):
                        source = ssh_source_ip(message)
                        if source:
                            record_ssh_failure(ssh_window, source)
                if oom_lines:
                    # One OOM event emits multiple kernel lines; send a single alert per cycle.
                    primary = next((line for line in oom_lines if "killed process" in line.lower()), oom_lines[0])
                    extra = len(oom_lines) - 1
                    body = primary[:500] + (f"\n(+{extra} related kernel line(s))" if extra else "")
                    notify("💀 OOM Detected", body, "critical")
                if cursor:
                    state["journal_cursor"] = cursor

        if ssh_enabled:
            ssh_window = state.get("ssh_window")
            if not isinstance(ssh_window, dict):
                ssh_window = new_ssh_window(now)
                state["ssh_window"] = ssh_window
            if now - float(ssh_window.get("started", now)) >= window_seconds:
                total = int(ssh_window.get("total", 0))
                if total > 0:
                    sources_map = ssh_window.get("sources") if isinstance(ssh_window.get("sources"), dict) else {}
                    top = Counter(sources_map).most_common(SSH_TOP_SOURCES)
                    top_text = "\n".join(f"{idx}. {ip} → {count}" for idx, (ip, count) in enumerate(top, start=1))
                    notify("🔐 SSH Failure Report", f"Total failures: {total}\n\nTop sources:\n{top_text}", "warning")
                state["ssh_window"] = new_ssh_window(now)

        # Systemd failed service units, debounced via the incident tracker so a
        # flapping unit does not spam alert/resolved pairs.
        if features.get("systemd_services", True):
            with probe_context("systemd"):
                current = systemd_failed_units()
            if current is None:
                result = False
                failed_probes.add("systemd")
            else:
                for unit in sorted(current):
                    event = tracker.observe(f"unit:{unit}", True, now=now)
                    if event == "triggered":
                        notify("⚙️ Service Failed", f"{unit} has failed.", "critical")
                    elif event == "relapse":
                        LOGGER.info("unit %s failed again while recovering; alert already active", unit)
                raw_prev = state.get("failed_systemd_services")
                previous = set(raw_prev) if isinstance(raw_prev, (set, list)) else set()
                for unit in sorted(previous - current):
                    if tracker.observe(f"unit:{unit}", False, now=now) == "resolved":
                        notify("✅ Service Resolved", f"{unit} recovered successfully.", "info")
                state["failed_systemd_services"] = current
                tracker.prune("unit:", {f"unit:{u}" for u in previous | current})

        # NTP clock synchronization check, debounced with the incident tracker and
        # granted a post-boot grace period so a normal boot never emits a
        # "not synchronized" + "restored" pair while timesyncd converges.
        if features.get("time_sync", True):
            with probe_context("time_sync"):
                ntp_synchronized = timedatectl_ntp_state()
            if ntp_synchronized is None:
                result = False
                failed_probes.add("time_sync")
            else:
                within_boot_grace = uptime_seconds() < NTP_BOOT_GRACE_SECONDS
                if not within_boot_grace:
                    event = tracker.observe("ntp", not ntp_synchronized, now=now)
                    if event == "triggered":
                        notify("🕐 Time Sync Problem", "timedatectl reports NTP is not synchronized.", "warning")
                    elif event == "resolved":
                        notify("🕐 Time Sync Restored", "NTP synchronization has recovered.", "info")
                state["ntp_synchronized"] = ntp_synchronized

        # Listening TCP/UDP ports check.
        if features.get("listening_ports", True):
            with probe_context("ports"):
                udp_min = int(monitoring.get("udp_ephemeral_port_min", 0))
                current_ports = get_listening_ports(configured_ephemeral_min=udp_min)
            if current_ports is None:
                result = False
                failed_probes.add("ports")
            else:
                current_ports = filter_ignored_ports(
                    normalize_port_keys(current_ports),
                    parse_ignore_patterns(monitoring.get("port_ignore_patterns", "")),
                )
                previous_ports = state.get("ports")
                if previous_ports is not None and current_ports != set(previous_ports):
                    added = sorted(current_ports - set(previous_ports))
                    removed = sorted(set(previous_ports) - current_ports)
                    notify(
                        "🔌 Listening Port Change",
                        "Added:\n" + ("\n".join(added) if added else "none")
                        + "\n\nRemoved:\n" + ("\n".join(removed) if removed else "none"),
                        "warning",
                    )
                state["ports"] = current_ports

        # One failed probe must eventually surface: after `blind_after`
        # consecutive failures, enqueue a single "blind" alert (and one
        # "recovered" alert when it starts working again).
        for probe_name in ("cpu", "memory", "filesystem", "network", "journal", "systemd", "time_sync", "ports"):
            record_probe_result(state, probe_name, probe_name not in failed_probes, notify, blind_after)
    finally:
        # Persist no matter what happened above: dropping the cycle's window
        # aggregation, journal cursor, or outbox updates would poison every
        # future cycle.
        state["last_cycle_time"] = now
        state["resource_incidents"] = tracker.dump()
        flush_outbox(state, sender.deliver, now=now, save=lambda: save_state(state))
        try:
            save_state(state)
        except (OSError, AgentError) as exc:
            LOGGER.error("could not save state: %s", exc)
    return result


# --------------------------------------------------------------------------
# Daemon loop and signal handling
# --------------------------------------------------------------------------
class Shutdown:
    """Signal coordinator: SIGTERM/SIGINT stop the loop; SIGHUP wakes it to reload config."""

    def __init__(self) -> None:
        self.stop = threading.Event()
        self.wake = threading.Event()

    def install_handlers(self) -> None:
        """Register POSIX signal handlers when running on the main thread."""
        signal.signal(signal.SIGTERM, self._on_stop)
        signal.signal(signal.SIGINT, self._on_stop)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._on_reload)

    def _on_stop(self, _signum: int, _frame: Any) -> None:
        self.stop.set()
        self.wake.set()

    def _on_reload(self, _signum: int, _frame: Any) -> None:
        self.wake.set()


def run_forever(cfg: dict[str, Any]) -> int:
    """Main daemon loop: reload config each cycle, execute checks, and sleep interruptibly.

    When systemd supervises the unit with WatchdogSec, every cycle pings
    WATCHDOG=1 via sd_notify; a hung cycle (e.g. statvfs stuck in the kernel
    despite the thread timeout) stops the pings and systemd restarts the unit.
    """
    shutdown = Shutdown()
    shutdown.install_handlers()
    LOGGER.info("monitoring started (v%s)", AGENT_VERSION)
    sd_notify("READY=1")
    while not shutdown.stop.is_set():
        started = time.monotonic()
        if CONFIG_PATH.exists():
            try:
                cfg = load_config(CONFIG_PATH)  # Re-read every cycle so edits apply without a restart
            except (OSError, ValueError, configparser.Error) as exc:
                LOGGER.error("invalid configuration, keeping previous settings: %s", exc)
        try:
            run_agent_once(cfg)
        except Exception as exc:  # Runtime guard: one failed cycle must not kill the daemon
            LOGGER.exception("monitoring cycle failed: %s", exc)
        sd_notify("WATCHDOG=1")
        interval = int(cfg["monitoring"]["check_interval_seconds"])
        elapsed = time.monotonic() - started
        if not shutdown.stop.is_set():
            # Sleep in chunks no longer than WATCHDOG_PING_SECONDS so the
            # watchdog stays fed even when check_interval_seconds exceeds
            # WatchdogSec (e.g. a 1h interval against a 15min watchdog).
            deadline = time.monotonic() + max(1.0, interval - elapsed)
            while not shutdown.stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                shutdown.wake.wait(min(remaining, WATCHDOG_PING_SECONDS))
                if shutdown.wake.is_set():
                    shutdown.wake.clear()
                    break
                sd_notify("WATCHDOG=1")
    LOGGER.info("shutdown requested; state saved, exiting")
    return 0


# --------------------------------------------------------------------------
# Deterministic self-test suite (no root privileges or external services needed)
# --------------------------------------------------------------------------
def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"ok   {message}")


NET_DEV_SAMPLE = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 5000000 4000 3 2 11 12 13 14 9000000 7000 5 4 99 88 77 66
docker0: 700 7 0 0 0 0 0 0 800 8 0 0 0 0 0 0
"""

SS_SAMPLE_A = """\
tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      128        127.0.0.1:5432       0.0.0.0:*
udp   UNCONN 0      0            0.0.0.0:123        0.0.0.0:*
udp   UNCONN 0      0            0.0.0.0:41234      0.0.0.0:*
tcp   LISTEN 0      4096            [::]:22            [::]:*
"""

SS_SAMPLE_B = SS_SAMPLE_A.replace("0      4096         0.0.0.0:22", "3      5            0.0.0.0:22").replace(
    "0      128        127.0.0.1", "9      77         127.0.0.1"
)

PROC_NET_TCP_SAMPLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1538 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 20 0 0 10 -1
"""

MOUNTS_SAMPLE = """\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /mnt/my\\040disk ext4 rw 0 0
/dev/loop3 /snap/core/1 squashfs ro 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0
tmpfs /run tmpfs rw 0 0
proc /proc proc rw 0 0
server:/exports /mnt/nfs nfs4 rw 0 0
"""

MOUNTS_OVERLAY_ROOT_SAMPLE = """\
overlay / overlay rw,relatime 0 0
overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0
"""


def _counters(rx: int, tx: int, rxe: int = 0, txe: int = 0, rxd: int = 0, txd: int = 0) -> IfaceCounters:
    return IfaceCounters(rx, 0, rxe, rxd, tx, 0, txe, txd)


def _expect_raises(exc_type: type[BaseException], fn: Callable[[], Any], message: str) -> None:
    try:
        fn()
    except exc_type:
        print(f"ok   {message}")
        return
    raise AssertionError(f"expected {exc_type.__name__}: {message}")


def run_selftest() -> int:
    """Execute deterministic unit tests for parsers, counters, outbox, and state machines."""
    parsed = parse_net_dev(NET_DEV_SAMPLE)
    eth0 = parsed["eth0"]
    _expect(eth0.tx_bytes == 9000000 and eth0.rx_bytes == 5000000, "net: RX/TX bytes read from the right columns")
    _expect((eth0.rx_errs, eth0.rx_drop, eth0.tx_errs, eth0.tx_drop) == (3, 2, 5, 4), "net: errs/drop columns are correct")
    patterns = parse_ignore_patterns(MONITORING_DEFAULTS["ignore_interfaces"])
    kept = [n for n in parsed if not is_ignored_interface(n, patterns)]
    _expect(kept == ["eth0"], "net: lo and docker* are ignored by default")

    # Traffic selection (P1-8): only physical interfaces by default.
    fake_devices = {"eth0": True, "bond0": False, "wg0": False, "tailscale0": False}
    selected = select_traffic_interfaces(
        ["eth0", "bond0", "wg0", "tailscale0"], [], physical_only=True, device_exists=fake_devices.get
    )
    _expect(selected == ["eth0"], "traffic: virtual interfaces (bond/wg/tailscale) excluded by default")
    selected_legacy = select_traffic_interfaces(
        ["eth0", "bond0", "wg0"], [], physical_only=False, device_exists=fake_devices.get
    )
    _expect(selected_legacy == ["eth0", "bond0", "wg0"], "traffic: physical_only=false keeps legacy behavior")
    selected_ignored = select_traffic_interfaces(
        ["eth0", "lo"], patterns, physical_only=False, device_exists=fake_devices.get
    )
    _expect(selected_ignored == ["eth0"], "traffic: ignore_interfaces still applied")

    _expect(counter_delta(100, 150) == 50, "counter: normal increase")
    _expect(counter_delta(5000, 100) == 100, "counter: reset counts from zero")
    _expect(counter_delta(2**32 - 100, 50) == 50, "counter: backwards counter after wrap is a reset, not invented data")
    _expect(counter_delta(2**40, 10) == 10, "counter: 64-bit counter going back is a reset")

    traffic: dict[str, Any] = {}
    update_traffic_state(traffic, {"eth0": _counters(1000, 2000)}, "2026-10-12")
    update_traffic_state(traffic, {"eth0": _counters(1500, 2600)}, "2026-10-12")
    _expect(traffic["totals"]["eth0"] == [500, 600], "traffic: per-interface deltas accumulate")
    update_traffic_state(traffic, {"eth0": _counters(1700, 2700)}, "2026-10-13")
    _expect(traffic["totals"]["eth0"] == [200, 100], "traffic: delta is kept across UTC day rollover")
    update_traffic_state(traffic, {"eth0": _counters(50, 40)}, "2026-10-13")
    _expect(traffic["totals"]["eth0"] == [250, 140], "traffic: counter reset does not lose or invent data")

    window = new_network_window(0.0)
    accumulate_network_errors(window, {"eth0": _counters(0, 0, 3, 5, 2, 1)})
    accumulate_network_errors(window, {"eth0": _counters(0, 0, 5, 9, 2, 4)})
    _expect(
        window["counts"] == {"rx_errors": 2, "tx_errors": 4, "rx_drops": 0, "tx_drops": 3},
        "network: error/drop deltas map to the right fields",
    )
    finished = roll_network_window(window, 100000.0, 3600)
    _expect(
        finished is not None and finished["tx_errors"] == 4 and "eth0" in window["snapshot"],
        "network: window rollover keeps the snapshot",
    )
    accumulate_network_errors(window, {"eth0": _counters(0, 0, 6, 9, 2, 4)})
    _expect(window["counts"]["rx_errors"] == 1, "network: first delta after rollover is not lost")
    _expect(
        not network_errors_significant({"rx_drops": 1, "rx_errors": 0, "tx_errors": 0, "tx_drops": 0}, 10)
        and network_errors_significant({"rx_drops": 12, "rx_errors": 0, "tx_errors": 0, "tx_drops": 0}, 10),
        "network: report threshold suppresses single-packet noise (P3-20)",
    )

    # Listening ports (P1-12): ss and /proc keys normalize to the same form.
    _expect(
        parse_listening_ports(SS_SAMPLE_A) == parse_listening_ports(SS_SAMPLE_B),
        "ports: queue size changes do not alter the key set",
    )
    ports = parse_listening_ports(SS_SAMPLE_A)
    _expect("udp *:41234" not in ports and "udp *:123" in ports, "ports: ephemeral UDP sockets are ignored")
    ports_all_udp = parse_listening_ports(SS_SAMPLE_A, ephemeral_start=65536)
    _expect("udp *:41234" in ports_all_udp, "ports: configurable ephemeral_start=65536 keeps high UDP ports")
    proc_ports = parse_proc_net_sockets(PROC_NET_TCP_SAMPLE, "tcp", False)
    _expect(proc_ports == {"tcp *:22", "tcp 127.0.0.1:5432"}, "ports: /proc fallback normalizes wildcards like ss")
    _expect(
        _normalize_local_addr("*:22") == "*:22"
        and _normalize_local_addr("0.0.0.0:22") == "*:22"
        and _normalize_local_addr("[::]:22") == "*:22"
        and _normalize_local_addr("127.0.0.1:22") == "127.0.0.1:22",
        "ports: wildcard addresses share one canonical form",
    )
    _expect(
        normalize_port_keys({"tcp 0.0.0.0:22", "tcp [::]:443", "udp 1.2.3.4:53"})
        == {"tcp *:22", "tcp *:443", "udp 1.2.3.4:53"},
        "ports: legacy state keys are re-normalized for comparison",
    )
    _expect(
        filter_ignored_ports({"tcp *:22", "tcp 0.0.0.0:5432"}, ["tcp *:5432"]) == {"tcp *:22"},
        "ports: ignore patterns filter normalized keys (P3-19)",
    )

    tracker = ResourceIncidentTracker(persistence_samples=2, recovery_minutes=1)
    events = [tracker.observe("cpu", bad, now=t) for t, bad in [(0, True), (1, True), (2, False), (3, True), (4, False), (70, False)]]
    _expect(events == [None, "triggered", None, "relapse", None, "resolved"], "tracker: flapping gives one trigger and one resolve")
    tracker.load({"disk:/old": {"status": "invalid-state", "bad_samples": "bad"}})
    _expect(tracker.state("disk:/old")["status"] == "healthy", "tracker: corrupted state record is sanitized")
    tracker.prune("disk:", {"disk:/mnt/failed"})
    _expect(
        "disk:/old" not in tracker.dump() and "disk:/mnt/failed" not in tracker.dump(),
        "tracker: prune removes only keys outside the keep set",
    )
    loaded_tracker = ResourceIncidentTracker()
    loaded_tracker.load({"disk:/a": {"status": "active"}})
    _expect(loaded_tracker.dump() == {"disk:/a": {"status": "active"}}, "tracker: load/dump round-trip without external mutation")

    _expect(cpu_usage_percent(None, (100, 50)) is None, "cpu: first cycle reports no value")
    _expect(cpu_usage_percent([100, 50], (200, 100)) == 50.0, "cpu: tick delta percentage")
    _expect(cpu_usage_percent([100, 50], (200, 49)) is None, "cpu: negative idle delta is a skipped bad sample, not 100%")

    _expect(
        [m[1] for m in parse_mounts(MOUNTS_SAMPLE)] == ["/", "/mnt/my disk"],
        "mounts: spaces decoded, pseudo/loop/overlay/nfs excluded",
    )
    _expect(
        [m[1] for m in parse_mounts(MOUNTS_OVERLAY_ROOT_SAMPLE)] == ["/"],
        "mounts: overlay root / is preserved while docker overlay is excluded",
    )
    _expect("ceph" in EXCLUDED_FSTYPES and "glusterfs" in EXCLUDED_FSTYPES and "virtiofs" in EXCLUDED_FSTYPES
            and "9p" in EXCLUDED_FSTYPES and "lustre" in EXCLUDED_FSTYPES and "afs" in EXCLUDED_FSTYPES,
            "mounts: network/passthrough filesystem types are excluded (P0-4d)")
    _expect(df_percent(1000, 300, 250) == 74, "disk: percentage matches df rounding")
    _expect(_format_resource_title("disk:/var/lib/Postgres", "alert") == "DISK (/var/lib/Postgres) alert", "alert: mount path case is preserved")

    # get_mounts keeps stat-failed mounts listed with error=True (P1-10).
    class _FakeStatVfs:
        f_blocks = 1000
        f_bfree = 300
        f_bavail = 250
        f_files = 5000
        f_ffree = 4000
        f_favail = 4000

    def failing_probe(mount: str) -> tuple[int, Any] | None:
        return None if mount == "/mnt/my disk" else (1234, _FakeStatVfs())

    mounts_out = build_mount_report(MOUNTS_SAMPLE, failing_probe)
    kept_mounts = {m["mount"]: m for m in mounts_out}
    _expect(
        kept_mounts["/mnt/my disk"]["error"] is True and kept_mounts["/"]["percent"] is not None,
        "disk: hung mount stays listed with error=True instead of vanishing",
    )

    ssh_window = new_ssh_window(0.0)
    for i in range(100_000):
        record_ssh_failure(ssh_window, f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}")
    _expect(
        ssh_window["total"] == 100_000
        and len(ssh_window["sources"]) <= SSH_MAX_TRACKED_SOURCES
        and len(json.dumps(ssh_window)) < 200_000,
        "ssh: state stays bounded under 100k failures",
    )
    _expect(
        ssh_source_ip("Failed password for invalid user bob from 203.0.113.9 port 4242 ssh2") == "203.0.113.9",
        "ssh: source IP extracted",
    )
    _expect(ssh_source_ip("Failed password for root from ::ffff:203.0.113.9 port 22") is not None, "ssh: IPv6 source IP extracted")
    # Spoofed username (P1-7): the LAST from/port pair wins.
    _expect(
        ssh_source_ip(
            "Failed password for invalid user x from 8.8.8.8 port 22 ssh2 from 203.0.113.9 port 4242 ssh2"
        )
        == "203.0.113.9",
        "ssh: attacker-injected 'from IP' is ignored in favor of the last (real) one",
    )
    _expect(
        is_ssh_failed_attempt_line("Failed password for root from 1.2.3.4 port 22 ssh2")
        and not is_ssh_failed_attempt_line("Invalid user bob from 1.2.3.4 port 22 ssh2")
        and not is_ssh_failed_attempt_line("maximum authentication attempts exceeded for invalid user bob from 1.2.3.4 port 22"),
        "ssh: each attempt counted once (preauth and max-auth lines excluded from counting)",
    )
    _expect(
        is_sshd_entry({"_COMM": "sshd-session"}) and is_sshd_entry({"SYSLOG_IDENTIFIER": "sshd"}),
        "ssh: OpenSSH 9.8+ sshd-session recognized",
    )
    _expect(is_oom_event("Out of memory: Killed process 1234 (python3)"), "oom: kernel OOM message detected")

    # Debounced NTP with boot grace (P3-16).
    ntp_tracker = ResourceIncidentTracker(persistence_samples=3, recovery_minutes=10)
    ntp_events = [ntp_tracker.observe("ntp", bad, now=t) for t, bad in [(0, True), (1, True), (2, True)]]
    _expect(ntp_events == [None, None, "triggered"], "time_sync: debounce requires N consecutive bad samples")

    # Swap activity rate (P3-18).
    _expect(swap_activity_rate([10, 20], [110, 220], 100.0) == 2.0, "swap: activity rate computed from pswpin/out deltas")
    _expect(swap_activity_rate([100, 100], [90, 80], 10.0) == 0.0, "swap: counter reset counts as zero activity")
    _expect(swap_activity_rate(None, [1, 2], 10.0) is None, "swap: first cycle has no rate")

    # Container awareness (P3-21) and cgroup quota parsing.
    _expect(is_containerized(True, False, ""), "container: /.dockerenv detected")
    _expect(is_containerized(False, False, "12:cpuset:/docker/abc"), "container: docker cgroup path detected")
    _expect(not is_containerized(False, False, "0::/init.slice"), "container: normal host not flagged")
    _expect(parse_cpu_max("200000 100000") == 2.0, "container: cpu.max quota parsed as cores")
    _expect(parse_cpu_max("max 100000") is None, "container: unlimited cpu.max yields None")
    _expect(sd_notify("READY=1") is False, "watchdog: sd_notify is a no-op without NOTIFY_SOCKET")

    # Probe blindness tracking (P0-4a).
    blind_state: dict[str, Any] = {}
    blind_alerts: list[str] = []
    record_probe_result(blind_state, "journal", False, lambda t, b, s: blind_alerts.append(t), 3)
    record_probe_result(blind_state, "journal", False, lambda t, b, s: blind_alerts.append(t), 3)
    _expect(not blind_alerts, "blind: no alert before the failure threshold")
    record_probe_result(blind_state, "journal", False, lambda t, b, s: blind_alerts.append(t), 3)
    record_probe_result(blind_state, "journal", False, lambda t, b, s: blind_alerts.append(t), 3)
    _expect(
        blind_alerts == ["👁️ Probe 'journal' is blind"],
        "blind: exactly one alert after N consecutive failures",
    )
    record_probe_result(blind_state, "journal", True, lambda t, b, s: blind_alerts.append(t), 3)
    _expect(
        blind_alerts[-1] == "👁️ Probe 'journal' recovered" and not blind_state["blind_alerted"].get("journal"),
        "blind: single recovery alert and state reset",
    )

    outbox_state: dict[str, Any] = {}
    enqueue_alert(outbox_state, "t", "b")
    base = time.time()
    _expect(
        flush_outbox(outbox_state, lambda _a: False, base) == 0 and len(outbox_state["outbox"]) == 1,
        "outbox: failed delivery keeps the alert",
    )
    _expect(flush_outbox(outbox_state, lambda _a: True, base + 5) == 0, "outbox: backoff delays the retry")
    _expect(
        flush_outbox(outbox_state, lambda _a: True, base + 40) == 1 and not outbox_state["outbox"],
        "outbox: delivered after recovery and then removed",
    )
    # Per-delivery checkpoint (P3-22): save() runs after every successful send.
    checkpoint_state: dict[str, Any] = {}
    enqueue_alert(checkpoint_state, "a", "x")
    enqueue_alert(checkpoint_state, "b", "y")
    saves: list[int] = []
    flush_outbox(checkpoint_state, lambda _a: True, base + 60, save=lambda: saves.append(len(checkpoint_state["outbox"])))
    _expect(saves == [1, 0], "outbox: state checkpointed after each successful delivery")

    for _ in range(150):
        enqueue_alert(outbox_state, "t", "b")
    _expect(len(outbox_state["outbox"]) == OUTBOX_MAX_ITEMS, "outbox: size is bounded")
    flush_outbox(outbox_state, lambda _a: True, base + OUTBOX_MAX_AGE_SECONDS + 100)
    _expect(not outbox_state["outbox"], "outbox: expired alerts are dropped")

    migrated = migrate_state_v1(
        {
            "schema_version": 1,
            "boot_id": "x",
            "oom_events": ["a"],
            "ports": ["p"],
            "ssh_window": {"started": 1.0, "failures": ["1.1.1.1", "1.1.1.1", "2.2.2.2"]},
        }
    )
    _expect(
        migrated["schema_version"] == STATE_SCHEMA_VERSION
        and "oom_events" not in migrated
        and migrated["ssh_window"]["total"] == 3
        and migrated["ssh_window"]["sources"]["1.1.1.1"] == 2
        and migrated["boot_id"] == "x",
        "state: v1 migrates to v2",
    )
    journal = parse_journal_json('{"MESSAGE":"hi","__CURSOR":"c1"}\nnot json\n{"MESSAGE":[104,105],"__CURSOR":"c2"}\n')
    _expect(len(journal) == 2 and entry_message(journal[1]) == "hi", "journal: JSON lines and byte-array messages parsed")
    _expect(
        _redact_secrets("https://api.telegram.org/bot12345:SECRET/sendMessage")
        == "https://api.telegram.org/bot<redacted>/sendMessage",
        "security: Telegram bot token redacted from logs",
    )
    _expect(bool(host()), "host: fast non-DNS hostname resolution returns non-empty string")

    # Redirect refusal (P1-5): credentials must never follow a 30x.
    _expect_raises(
        urllib.error.HTTPError,
        lambda: _NoRedirectHandler().redirect_request(None, None, 301, "moved", {}, "http://evil.example/collect"),
        "security: HTTP redirects are refused to protect credentials",
    )

    # Config validation & atomic disk persistence tests
    _expect_raises(
        ValueError,
        lambda: _parse_config_value("features", "cpu", "tru_typo"),
        "config: strict boolean parser rejects typos",
    )
    _expect(_parse_config_value("monitoring", "traffic_physical_only", "yes") is True, "config: monitoring booleans parse strictly")
    bad_bool_cfg = default_config()
    bad_bool_cfg["thresholds"]["cpu"] = True
    _expect_raises(ValueError, lambda: validate_config(bad_bool_cfg), "config: boolean rejected for integer threshold")

    bad_url_cfg = default_config()
    bad_url_cfg["alerts"]["backend"] = "webhook"
    bad_url_cfg["alerts"]["webhook_url"] = "file:///etc/passwd"
    _expect_raises(ValueError, lambda: validate_config(bad_url_cfg), "config: non-http(s) webhook URL rejected")

    bearer_cfg = default_config()
    bearer_cfg["alerts"]["backend"] = "webhook"
    bearer_cfg["alerts"]["webhook_url"] = "http://collector.internal/hook"
    bearer_cfg["alerts"]["webhook_bearer_token"] = "s3cr3t"
    _expect_raises(
        ValueError,
        lambda: validate_config(bearer_cfg),
        "security: bearer token over plain http:// rejected (P1-5)",
    )

    # Feature-aware prerequisites (P2-13).
    minimal_cfg = default_config()
    for feature in ("ssh_failures", "oom", "systemd_services", "time_sync", "listening_ports"):
        minimal_cfg["features"][feature] = False
    required = required_tools_for_config(minimal_cfg)
    _expect(required == [], "install: disabled features require no external tools")
    full_required = required_tools_for_config(default_config())
    _expect(
        "journalctl" in full_required and "systemctl" in full_required and "timedatectl" in full_required,
        "install: enabled features require their tools",
    )
    _expect(
        "useradd" in required_tools_for_config(None, for_install=True),
        "install: installer always needs user management tools",
    )

    # Hardened systemd unit (sandbox directives must not break the real probes).
    unit = unit_file_text()
    _expect(
        f"ExecStart={sys.executable} {INSTALL_ROOT}/Auto-Monitoring.py run" in unit,
        "unit: ExecStart uses the resolved interpreter and installed file",
    )
    for directive in (
        "WatchdogSec=", "CapabilityBoundingSet=", "SystemCallFilter=@system-service",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "ProtectKernelTunables=true", "PrivateDevices=true",
    ):
        _expect(directive in unit, f"unit: hardened with {directive}")
    _expect("AF_NETLINK" in unit, "unit: netlink stays allowed so the ss child keeps working")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cfg_file = tmp_path / "config.ini"
        state_file = tmp_path / "state.json"
        lock_file = tmp_path / "state.lock"
        cfg = default_config()
        cfg["monitoring"]["udp_ephemeral_port_min"] = 50000
        write_config(cfg, cfg_file)
        loaded_cfg = load_config(cfg_file)
        _expect(
            loaded_cfg["monitoring"]["udp_ephemeral_port_min"] == 50000
            and loaded_cfg["monitoring"]["traffic_physical_only"] is True,
            "persistence: atomic write_config/load_config round-trip with fsync",
        )
        with state_lock(lock_file):
            save_state({"boot_id": "b1", "ports": {"tcp 0.0.0.0:22"}}, state_file)
            loaded_st = load_state(state_file)
            _expect(
                loaded_st["boot_id"] == "b1" and loaded_st["ports"] == {"tcp *:22"},
                "persistence: atomic save_state/load_state with flock and normalized ports",
            )
        state_file.write_text("{corrupt", encoding="utf8")
        recovered_st = load_state(state_file)
        _expect(
            recovered_st == {"schema_version": STATE_SCHEMA_VERSION} and (tmp_path / "state.json.corrupt").exists(),
            "persistence: corrupted state file backed up and reset cleanly",
        )

        # Transient OSError (P0-3): a directory standing in for state.json is an
        # EISDIR OSError — must raise TransientStateError and touch nothing.
        not_a_file = tmp_path / "state_dir.json"
        not_a_file.mkdir()
        _expect_raises(TransientStateError, lambda: load_state(not_a_file), "state: transient OSError skips the cycle without deleting state")
        _expect(not_a_file.exists() and not list(tmp_path.glob("state_dir.json.corrupt")), "state: transient failure left the file untouched")

        # Symlink refusal (P0-1): state and config never load through symlinks.
        victim = tmp_path / "victim.txt"
        victim.write_text("original", encoding="utf8")
        link = tmp_path / "state_link.json"
        link.symlink_to(victim)
        _expect_raises(AgentError, lambda: load_state(link), "security: state behind a symlink is refused")
        config_link = tmp_path / "config_link.ini"
        config_link.symlink_to(victim)
        _expect_raises(AgentError, lambda: load_config(config_link), "security: config behind a symlink is refused")

        # Symlinked lock path (P0-1): state_lock must fail loudly, not follow.
        planted_lock = tmp_path / "planted.lock"
        planted_lock.symlink_to(victim)
        _expect_raises(AgentError, lambda: state_lock(planted_lock).__enter__(), "security: symlinked lock file is refused (O_NOFOLLOW)")

    print("\nAll selftests passed.")
    return 0


def _drop_to_service_user() -> bool:
    """Drop root privileges to the service account before touching state files.

    `check` only reads the state directory, which the service user owns anyway;
    running it as root would honor symlinks planted there (root's chown/open
    would follow them). Returns False when dropping is not possible.
    """
    if os.geteuid() != 0:
        return True
    try:
        uid, gid = _lookup_service_uid_gid(NAME)
    except KeyError:
        return False
    try:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    except OSError as exc:
        LOGGER.error("could not drop privileges to %s: %s", NAME, exc)
        return False
    return True


def main() -> int:
    """CLI entry point for `install`, `uninstall`, `run`, `check`, `test-alert`, and `selftest`."""
    ensure_standard_path()
    parser = argparse.ArgumentParser(description="Low-noise Linux host monitoring agent")
    parser.add_argument("command", choices=("install", "uninstall", "run", "check", "test-alert", "selftest"))
    parser.add_argument(
        "-y",
        "--yes",
        "--non-interactive",
        dest="non_interactive",
        action="store_true",
        help="Run install without interactive prompts, using existing or default settings.",
    )
    parser.add_argument(
        "--auto-install-deps",
        dest="auto_install_deps",
        action="store_true",
        help="install: install missing system packages via the package manager (explicit consent).",
    )
    parser.add_argument(
        "--force",
        dest="force",
        action="store_true",
        help="install: continue even when the test alert fails or the backend is stdout.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {AGENT_VERSION} (state schema v{STATE_SCHEMA_VERSION})")
    args = parser.parse_args()

    if args.command == "selftest":
        return run_selftest()

    try:
        if args.command == "install":
            return install(
                non_interactive=args.non_interactive,
                auto_install_deps=args.auto_install_deps,
                force=args.force,
            )
        if args.command == "uninstall":
            return uninstall()
    except (AgentError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        cfg = load_config(CONFIG_PATH)
    except (OSError, ValueError, configparser.Error) as exc:
        raise AgentError(f"invalid configuration: {exc}") from exc

    if args.command == "test-alert":
        sender = AlertSender(cfg)
        return 0 if sender.deliver(make_alert("Auto-Monitoring test alert", "Manual test alert.", "info")) else 1

    if not CONFIG_PATH.exists():
        raise AgentError(f"missing configuration: {CONFIG_PATH}")

    if args.command == "check":
        if os.geteuid() == 0 and not _drop_to_service_user():
            raise AgentError(
                f"check was run as root but could not drop privileges to '{NAME}'; "
                "refusing to touch the service-owned state directory. "
                f"Run as: sudo -u {NAME} ..."
            )
        ok = run_agent_once(cfg)
        print(
            "Health check passed: configuration valid and one monitoring cycle completed."
            if ok
            else "Health check failed."
        )
        return 0 if ok else 1

    return run_forever(cfg)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AgentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except KeyboardInterrupt:
        raise SystemExit(0)