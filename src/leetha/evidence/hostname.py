"""Hostname validation – rejects UUIDs, hex strings, IPs, and external FQDNs."""

from __future__ import annotations

import ipaddress
import re

# 8-4-4-4-12 hex (standard UUID) or 8-4-4-4 (truncated UUID)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}(-[0-9a-f]{12})?$",
    re.IGNORECASE,
)

# Pure hex string, 8+ characters
_PURE_HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)

# Known public TLDs (common ones – enough to catch the obvious external names)
_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "io", "co", "uk", "de", "fr",
    "jp", "cn", "ru", "br", "au", "in", "ca", "us", "eu", "info", "biz",
    "me", "tv", "cc", "ws", "app", "dev", "cloud", "xyz",
})


def _is_hex_segment(s: str) -> bool:
    """Return True if *s* is a non-empty string of hex digits."""
    return bool(s) and all(c in "0123456789abcdefABCDEF" for c in s)


def is_valid_hostname(name: str | None) -> bool:
    """Return True when *name* looks like a human-assigned hostname.

    Returns False for None / empty / whitespace, UUIDs, hex blobs, IPs,
    IPv6 addresses, and external FQDNs.
    """
    if name is None:
        return False
    name = name.strip()
    if not name:
        return False

    # --- IPv4 / IPv6 ---------------------------------------------------------
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        pass

    # --- External FQDN (2+ dots, last label is a known TLD) -----------------
    if "." in name:
        parts = name.split(".")
        if len(parts) >= 3 and parts[-1].lower() in _TLDS:
            return False

    # --- Full UUID (8-4-4-4-12 or 8-4-4-4) ----------------------------------
    if _UUID_RE.match(name):
        return False

    # --- Dash-separated segments analysis ------------------------------------
    if "-" in name:
        segments = name.split("-")

        # All segments are pure hex → reject  (e.g. f80f-f9c5-49d2)
        if all(_is_hex_segment(seg) for seg in segments):
            return False

        # "word-hex-hex-hex…" pattern: if 3+ trailing segments are all hex,
        # it's likely a UUID-derivative (e.g. fuchsia-f80f-f9c5-49d2).
        if len(segments) >= 4:
            trailing_hex = 0
            for seg in reversed(segments):
                if _is_hex_segment(seg):
                    trailing_hex += 1
                else:
                    break
            if trailing_hex >= 3:
                return False

    # --- Pure hex blob (8+ chars, no dashes) ---------------------------------
    if _PURE_HEX_RE.match(name):
        return False

    return True
