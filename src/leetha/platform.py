"""Cross-platform abstraction layer.

All OS-specific operations are centralised here so the rest of the
codebase never calls os.getuid(), AF_PACKET, pwd, or shell commands
like ``ip`` directly.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Platform constant
# ---------------------------------------------------------------------------

if sys.platform.startswith("linux"):
    PLATFORM = "linux"
elif sys.platform == "darwin":
    PLATFORM = "macos"
elif sys.platform == "win32":
    PLATFORM = "windows"
else:
    PLATFORM = sys.platform  # best-effort fallback


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    """Return True when the current process has admin / root privileges."""
    if PLATFORM == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    return os.getuid() == 0


def has_capture_privilege() -> bool:
    """Return True when the process can open a raw packet capture."""
    if is_root():
        return True

    if PLATFORM == "linux":
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            s.close()
            return True
        except (OSError, AttributeError):
            return False

    if PLATFORM == "macos":
        import glob
        for dev in glob.glob("/dev/bpf*"):
            if os.access(dev, os.R_OK):
                return True
        return False

    if PLATFORM == "windows":
        return ctypes.util.find_library("wpcap") is not None

    return False


def escalate_privileges() -> None:
    """Re-launch the current process with elevated privileges.

    On Linux/macOS this exec's via ``sudo``.  On Windows it uses the
    ``runas`` shell verb.  Prints a clear error on failure.
    """
    if PLATFORM == "windows":
        try:
            ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
                None, "runas", sys.executable, " ".join(sys.argv), None, 1,
            )
            sys.exit(0)
        except (AttributeError, OSError) as exc:
            print(f"[!] Failed to elevate privileges: {exc}", file=sys.stderr)
            return

    # Linux / macOS
    try:
        os.execvp("sudo", ["sudo", sys.executable, *sys.argv])
    except OSError as exc:
        print(f"[!] Failed to elevate privileges via sudo: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def set_promiscuous(interface: str) -> bool:
    """Enable promiscuous mode on *interface*.  Returns success flag."""
    if PLATFORM == "windows":
        # Npcap handles promiscuous mode at capture time.
        return True

    if PLATFORM == "macos":
        cmd = ["ifconfig", interface, "promisc"]
    else:
        cmd = ["ip", "link", "set", interface, "promisc", "on"]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_routes() -> List[dict]:
    """Return the system routing table as a list of dicts.

    Each dict contains at least ``dst``, ``gateway``, and ``dev`` keys.
    """
    if PLATFORM == "linux":
        return _get_linux_routes()
    if PLATFORM == "macos":
        return _get_macos_routes()
    if PLATFORM == "windows":
        return _get_windows_routes()
    return []


def _get_linux_routes() -> List[dict]:
    try:
        result = subprocess.run(
            ["ip", "-j", "route"],
            capture_output=True,
            text=True,
            check=True,
        )
        entries = json.loads(result.stdout)
        routes: List[dict] = []
        for e in entries:
            routes.append({
                "dst": e.get("dst", ""),
                "gateway": e.get("gateway", ""),
                "dev": e.get("dev", ""),
            })
        return routes
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        return []


def _get_macos_routes() -> List[dict]:
    try:
        result = subprocess.run(
            ["netstat", "-rn"],
            capture_output=True,
            text=True,
            check=True,
        )
        return _parse_netstat_routes(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _get_windows_routes() -> List[dict]:
    try:
        result = subprocess.run(
            ["route", "print"],
            capture_output=True,
            text=True,
            check=True,
        )
        return _parse_windows_routes(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


# ---------------------------------------------------------------------------
# Route-parsing helpers
# ---------------------------------------------------------------------------

def _parse_netstat_routes(output: str) -> List[dict]:
    """Parse macOS ``netstat -rn`` output into route dicts."""
    routes: List[dict] = []
    in_table = False
    for line in output.splitlines():
        if line.startswith("Destination"):
            in_table = True
            continue
        if not in_table:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        routes.append({
            "dst": parts[0],
            "gateway": parts[1],
            "dev": parts[3] if len(parts) > 3 else "",
        })
    return routes


def _parse_windows_routes(output: str) -> List[dict]:
    """Parse Windows ``route print`` output into route dicts."""
    routes: List[dict] = []
    in_table = False
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"Network\s+Destination", stripped):
            in_table = True
            continue
        if in_table:
            if not stripped or stripped.startswith("="):
                in_table = False
                continue
            parts = stripped.split()
            if len(parts) >= 4:
                routes.append({
                    "dst": parts[0],
                    "gateway": parts[2],
                    "dev": parts[3],
                })
    return routes


# ---------------------------------------------------------------------------
# Filesystem / environment helpers
# ---------------------------------------------------------------------------

def get_home_dir() -> Path:
    """Return the real user's home directory, even under ``sudo``."""
    if PLATFORM != "windows":
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            try:
                import pwd
                return Path(pwd.getpwnam(sudo_user).pw_dir)
            except (KeyError, ImportError):
                pass
    return Path.home()


def has_live_terminal() -> bool:
    """Return True when stdout is connected to a real terminal (not Windows)."""
    if PLATFORM == "windows":
        return False
    try:
        import termios  # noqa: F401
        return True
    except ImportError:
        return False
