"""
CLI Live Mode -- real-time packet stream with fingerprint reasoning.

Renders each captured packet with evidence tree showing which fingerprint
sources matched and why, plus the final device verdict.
"""

from __future__ import annotations

import asyncio
import collections
import sys
import time
from datetime import datetime

try:
    import select
    import termios
    import tty
    _HAS_TERMINAL = True
except ImportError:
    _HAS_TERMINAL = False

from rich.console import Console
from leetha.app import LeethaApp


class _RateLimiter:
    """Token-bucket rate limiter for display throttling."""

    def __init__(self, max_per_sec: int | None = None):
        self._max = max_per_sec
        self._window_start = time.monotonic()
        self._count = 0
        self.skipped = 0

    def allow(self) -> bool:
        if self._max is None:
            return True
        now = time.monotonic()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._count = 0
        if self._count < self._max:
            self._count += 1
            return True
        self.skipped += 1
        return False


class _StatusBar:
    """Persistent status line for live capture mode."""

    def __init__(self, max_rate: int | None = None):
        self.max_rate = max_rate
        self.total_events = 0
        self.skipped = 0
        self.paused = False
        self.buffered = 0
        self.interface_name = ""
        self.seen_macs: set[str] = set()
        self.alert_count = 0
        self.remote_sensor_count = 0
        self._timestamps: collections.deque[float] = collections.deque(maxlen=100)

    def record_event(self) -> None:
        self.total_events += 1
        self._timestamps.append(time.monotonic())

    def events_per_sec(self) -> int:
        if not self._timestamps:
            return 0
        now = time.monotonic()
        cutoff = now - 1.0
        count = sum(1 for t in self._timestamps if t >= cutoff)
        return count

    def render(self) -> str:
        iface = f"  {self.interface_name}" if self.interface_name else ""
        device_count = len(self.seen_macs)
        if self.paused:
            return (
                f"[PAUSED]{iface}"
                f" | {self.total_events} events"
                f" | {device_count} devices"
                f" | {self.alert_count} alerts"
                f" | {self.buffered} buffered"
                f" | Space: resume"
            )
        rate_str = f"{self.max_rate}/s" if self.max_rate else "unlimited"
        eps = self.events_per_sec()
        remote_str = f" | {self.remote_sensor_count} sensors" if self.remote_sensor_count else ""
        return (
            f"[LIVE]{iface}"
            f" | {self.total_events} events"
            f" | {device_count} devices"
            f" | {self.alert_count} alerts"
            f"{remote_str}"
            f" | {eps}/s"
            f" | Space: pause"
            f" | Ctrl+C: stop"
        )

    def print(self, console: 'Console') -> None:
        """Print status bar pinned to bottom of terminal."""
        text = self.render()
        console.print(
            f"\033[s\033[{console.height};0H\033[2K"
            f"[dim]{text}[/dim]"
            f"\033[u",
            highlight=False,
            end="",
        )


class _KeyReader:
    """Non-blocking keyboard reader using raw terminal mode."""

    def __init__(self):
        self._old_settings = None
        self._fd = None

    def enable(self) -> None:
        self._fd = sys.stdin.fileno()
        self._old_settings = termios.tcgetattr(self._fd)
        tty.setcbreak(self._fd)

    def disable(self) -> None:
        if self._old_settings is not None and self._fd is not None:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_settings)

    def poll(self) -> str | None:
        """Return keypress character if available, else None."""
        if self._fd is None:
            return None
        rlist, _, _ = select.select([sys.stdin], [], [], 0)
        if rlist:
            return sys.stdin.read(1)
        return None


def _get_mac(event: dict) -> str:
    """Extract source MAC from event."""
    pkt = event.get("packet")
    if pkt and isinstance(pkt, dict):
        return pkt.get("src_mac", event.get("mac", "??:??:??:??:??:??"))
    return event.get("mac", "??:??:??:??:??:??")


async def run_live(
    interfaces: list | None = None,
    decode: bool = False,
    packet_filter: str | None = None,
    rate: int | None = None,
    app: LeethaApp | None = None,
):
    """Entry point for --live mode.

    If *app* is provided, subscribe to it without managing its lifecycle.
    If *app* is None, create and manage a new LeethaApp.
    """
    if not _HAS_TERMINAL:
        Console().print(
            "[bold red]Live packet viewer requires a Unix terminal "
            "(not available on Windows).[/bold red]\n"
            "Use [bold]--web[/bold] for the web dashboard instead."
        )
        return

    console = Console(emoji=False)
    owns_app = app is None
    if owns_app:
        app = LeethaApp(interfaces=interfaces)
        await app.start()

    events = app.subscribe()
    limiter = _RateLimiter(max_per_sec=rate)
    status = _StatusBar(max_rate=rate)
    keys = _KeyReader()
    paused = False
    buffer: list[dict] = []
    repeat_tracker = _RepeatTracker()

    interface_name = ", ".join(app.capture_engine.interfaces.keys()) or "auto"
    status.interface_name = interface_name

    console.print(
        "[bold green]LEETHA Live Capture[/bold green]"
        f"  [dim]{interface_name}[/dim]\n"
    )

    keys.enable()
    try:
        last_status_update = time.monotonic()
        while True:
            # Check for keypress
            key = keys.poll()
            if key == " ":
                paused = not paused
                status.paused = paused
                if not paused:
                    # Drain buffer on resume
                    for buffered_event in buffer:
                        if limiter.allow():
                            status.record_event()
                            status.seen_macs.add(_get_mac(buffered_event))
                            _render_event(console, buffered_event, decode=decode, repeat_tracker=repeat_tracker)
                        else:
                            status.skipped = limiter.skipped
                    buffer.clear()
                    status.buffered = 0

            # Non-blocking get with timeout for responsive key handling
            try:
                event = await asyncio.wait_for(events.get(), timeout=0.05)
            except asyncio.TimeoutError:
                # Refresh status bar periodically
                now = time.monotonic()
                if now - last_status_update >= 1.0:
                    # Update remote sensor count
                    if hasattr(app, '_remote_sensor_manager'):
                        status.remote_sensor_count = len(app._remote_sensor_manager.sensors)
                    status.print(console)
                    last_status_update = now
                continue

            if packet_filter and not _matches_filter(event, packet_filter):
                continue

            if paused:
                buffer.append(event)
                status.buffered = len(buffer)
            elif limiter.allow():
                status.record_event()
                status.seen_macs.add(_get_mac(event))
                _render_event(console, event, decode=decode, repeat_tracker=repeat_tracker)
            else:
                status.skipped = limiter.skipped

            # Refresh status bar every second
            now = time.monotonic()
            if now - last_status_update >= 1.0:
                status.print(console)
                last_status_update = now

    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        keys.disable()
        app.unsubscribe(events)
        # Clear the status bar line on exit
        console.print(f"\033[{console.height};0H\033[2K", end="")
        if owns_app:
            await app.stop()


# Protocol tag colors
_PROTO_COLORS: dict[str, str] = {
    "arp": "bright_cyan",
    "tcp_syn": "bright_blue",
    "dhcpv4": "bright_green",
    "dhcpv6": "green",
    "mdns": "bright_yellow",
    "dns": "yellow",
    "dns_answer": "yellow",
    "ssdp": "bright_magenta",
    "netbios": "orange1",
    "tls": "magenta",
    "banner": "white",
    "icmpv6": "cyan",
    "http_useragent": "bright_white",
    "ip_observed": "dim white",
}

# Indentation for tree lines
_INDENT = "             "


def _conf_style(conf: int) -> str:
    """Return Rich style string for a confidence percentage."""
    if conf >= 80:
        return "bold bright_green"
    if conf >= 50:
        return "yellow"
    return "red"


class _RepeatTracker:
    """Detect consecutive identical evidence from the same MAC."""

    def __init__(self):
        self._last_mac: str | None = None
        self._last_hash: int | None = None
        self.repeat_count: int = 0

    def check(self, mac: str, evidence_keys: list[str],
              confidence: int, alert_count: int) -> bool:
        """Return True if this event is a repeat of the previous one.

        Resets when MAC, evidence, confidence, or alert count changes.
        """
        h = hash((mac, tuple(sorted(evidence_keys)), confidence, alert_count))
        if mac == self._last_mac and h == self._last_hash:
            self.repeat_count += 1
            return True
        self._last_mac = mac
        self._last_hash = h
        self.repeat_count = 0
        return False


def _proto_tag(protocol: str) -> str:
    """Return a colored, fixed-width protocol tag."""
    color = _PROTO_COLORS.get(protocol, "white")
    _PROTO_NAMES = {
        "tcp_syn": "TCP SYN",
        "dhcpv4": "DHCPv4",
        "dhcpv6": "DHCPv6",
        "dns_answer": "DNS ANSWER",
        "http_useragent": "HTTP",
        "ip_observed": "IP",
        "icmpv6": "ICMPv6",
    }
    label = _PROTO_NAMES.get(protocol, protocol.upper())
    return f"[bold {color}]{label:<12s}[/bold {color}]"


def _render_event(console: Console, event: dict, decode: bool = False,
                  repeat_tracker: _RepeatTracker | None = None):
    """Render a single packet event with fingerprint reasoning.

    Events are dicts emitted by LeethaApp with keys:
        type, mac, verdict (dict), packet (dict with protocol/src_mac/src_ip/dst_ip/fields/timestamp)
    """
    pkt = event.get("packet") or {}
    verdict = event.get("verdict") or {}

    protocol = pkt.get("protocol", "?")
    src_mac = pkt.get("src_mac", event.get("mac", "?"))
    src_ip = pkt.get("src_ip") or ""
    dst_ip = pkt.get("dst_ip") or ""
    fields = pkt.get("fields") or {}

    # Parse timestamp
    ts_raw = pkt.get("timestamp")
    if ts_raw:
        try:
            ts = datetime.fromisoformat(ts_raw).strftime("%H:%M:%S")
        except (ValueError, TypeError):
            ts = "??:??:??"
    else:
        ts = datetime.now().strftime("%H:%M:%S")

    # ── Header: timestamp + protocol + src MAC/IP + dst + verdict ──
    tag = _proto_tag(protocol)
    # Tag remote sensor packets
    iface = pkt.get("interface", "")
    remote_tag = ""
    if iface and iface.startswith("remote:"):
        sensor_name = iface.split(":", 1)[1]
        remote_tag = f" [bold violet]⬤ {sensor_name}[/bold violet]"
    mac_str = f"[bright_blue]{src_mac}[/bright_blue]"
    ip_str = f"  [white]{src_ip}[/white]" if src_ip else ""
    dst_str = f"  [dim]→[/dim] [white]{dst_ip}[/white]" if dst_ip else ""

    # Build verdict line from verdict dict
    verdict_str = ""
    if verdict and verdict.get("category"):
        dtype = verdict.get("category", "—")
        mfr = verdict.get("hostname") or verdict.get("vendor") or "Unknown"
        os_str = verdict.get("platform") or "—"
        if verdict.get("platform_version"):
            os_str = f"{os_str} {verdict['platform_version']}"
        conf = verdict.get("certainty", 0)
        style = _conf_style(conf)
        verdict_str = (
            f"  [bold bright_white]{dtype}[/bold bright_white]"
            f" [dim]|[/dim] [white]{mfr}[/white]"
            f" [dim]|[/dim] [white]{os_str}[/white]"
            f" [dim]|[/dim] [{style}]{conf}%[/{style}]"
        )

    console.print(f"[dim white]{ts}[/dim white]  {tag}{remote_tag}{mac_str}{ip_str}{dst_str}{verdict_str}")

    # Build evidence key for repeat detection
    evidence_chain = verdict.get("evidence_chain") or []
    evidence_keys = [f"{e.get('source', '?')}:{e.get('certainty', 0)}" for e in evidence_chain]
    device_conf = verdict.get("certainty", 0)

    if repeat_tracker and repeat_tracker.check(src_mac, evidence_keys, device_conf, 0):
        console.print(
            f"{_INDENT}[dim]\u21bb same evidence (\u00d7{repeat_tracker.repeat_count})[/dim]"
        )
        console.print()
        return

    # ── Protocol-specific details ──
    if protocol == "arp":
        op = fields.get("op", "")
        op_label = "Request" if op == 1 else "Reply" if op == 2 else str(op)
        console.print(
            f"{_INDENT}[yellow]Op:[/yellow] {op_label}"
            f"  [yellow]Target:[/yellow] {dst_ip or '?'}"
        )

    elif protocol == "tcp_syn":
        ttl = fields.get("ttl", "?")
        win = fields.get("window_size", "?")
        mss = fields.get("mss", "?")
        wscale = fields.get("window_scale", "")
        opts = fields.get("tcp_options", "")
        dst_port = fields.get("dst_port", "")
        parts = [f"TTL: {ttl}", f"Win: {win}", f"MSS: {mss}"]
        if wscale:
            parts.append(f"WScale: {wscale}")
        if opts:
            parts.append(f"Opts: {opts}")
        if dst_port:
            parts.append(f"Port: {dst_port}")
        console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")

    elif protocol == "dhcpv4":
        parts = []
        msg_type = fields.get("message_type", "")
        if msg_type:
            parts.append(f"Type: {msg_type}")
        if fields.get("hostname"):
            parts.append(f"Hostname: {fields['hostname']}")
        if fields.get("opt55"):
            parts.append(f"Opt55: {fields['opt55']}")
        if fields.get("opt60"):
            parts.append(f"Vendor: {fields['opt60']}")
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")

    elif protocol == "dhcpv6":
        parts = []
        if fields.get("message_type"):
            parts.append(f"Type: {fields['message_type']}")
        if fields.get("oro"):
            parts.append(f"ORO: {fields['oro']}")
        if fields.get("duid"):
            parts.append(f"DUID: {fields['duid']}")
        if fields.get("fqdn"):
            parts.append(f"FQDN: {fields['fqdn']}")
        if fields.get("vendor_class"):
            parts.append(f"Vendor: {fields['vendor_class']}")
        if fields.get("enterprise_id"):
            parts.append(f"Enterprise: {fields['enterprise_id']}")
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")

    elif protocol == "dns":
        qname = fields.get("query_name", "")
        qtype_name = fields.get("query_type_name", str(fields.get("query_type", "")))
        console.print(
            f"{_INDENT}[yellow]Query:[/yellow] {qname}  "
            f"[yellow]Type:[/yellow] {qtype_name}"
        )

    elif protocol == "mdns":
        parts = []
        if fields.get("service_type"):
            parts.append(f"Service: {fields['service_type']}")
        if fields.get("name"):
            parts.append(f'Name: "{fields["name"]}"')
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")
        txt_parts = []
        if fields.get("model"):
            txt_parts.append(f"Model: {fields['model']}")
        if fields.get("apple_model"):
            txt_parts.append(f"Apple: {fields['apple_model']}")
        if fields.get("friendly_name"):
            txt_parts.append(f'Friendly: "{fields["friendly_name"]}"')
        if fields.get("txt_manufacturer"):
            txt_parts.append(f"Mfr: {fields['txt_manufacturer']}")
        if txt_parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(txt_parts)}[/yellow]")

    elif protocol == "ssdp":
        parts = []
        if fields.get("server"):
            parts.append(f"Server: {fields['server']}")
        if fields.get("st"):
            parts.append(f"ST: {fields['st']}")
        if fields.get("ssdp_type"):
            parts.append(f"Type: {fields['ssdp_type']}")
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")
        if fields.get("usn"):
            console.print(f"{_INDENT}[yellow]USN: {fields['usn']}[/yellow]")
        if fields.get("location"):
            console.print(f"{_INDENT}[yellow]Location: {fields['location']}[/yellow]")

    elif protocol == "netbios":
        qtype = fields.get("query_type", "").upper()
        console.print(f"{_INDENT}[yellow]{qtype}:[/yellow] {fields.get('query_name')}")
        if fields.get("netbios_suffix") is not None:
            console.print(f"{_INDENT}[yellow]Suffix:[/yellow] 0x{fields['netbios_suffix']:02X}")

    elif protocol == "tls":
        ja3 = fields.get("ja3_hash", "")
        ja4 = fields.get("ja4", "")
        tls_ver = fields.get("tls_version", "")
        sni = fields.get("sni", "")
        console.print(
            f"{_INDENT}[yellow]JA3:[/yellow] {ja3}  "
            f"[yellow]JA4:[/yellow] {ja4}"
        )
        line_parts = []
        if tls_ver:
            line_parts.append(f"[yellow]TLS:[/yellow] {tls_ver}")
        if sni:
            line_parts.append(f"[yellow]SNI:[/yellow] {sni}")
        if line_parts:
            console.print(f"{_INDENT}{'  '.join(line_parts)}")

    elif protocol == "icmpv6":
        icmp_type = fields.get("icmpv6_type", "")
        type_display = icmp_type.replace("_", " ").title() if icmp_type else "?"
        line = f"{_INDENT}[yellow]Type:[/yellow] {type_display}"
        if fields.get("hop_limit"):
            line += f"  [yellow]Hop Limit:[/yellow] {fields['hop_limit']}"
        if fields.get("target"):
            line += f"  [yellow]Target:[/yellow] {fields['target']}"
        console.print(line)
        # Show flags for RA and NA
        flag_parts = []
        if fields.get("managed"):
            flag_parts.append("Managed")
        if fields.get("other"):
            flag_parts.append("Other")
        if fields.get("router"):
            flag_parts.append("Router")
        if fields.get("solicited"):
            flag_parts.append("Solicited")
        if fields.get("override"):
            flag_parts.append("Override")
        if flag_parts:
            console.print(f"{_INDENT}[yellow]Flags:[/yellow] {', '.join(flag_parts)}")

    elif protocol == "banner":
        banner_text = fields.get("banner", "")
        if banner_text:
            display = banner_text[:120] + ("..." if len(banner_text) > 120 else "")
            console.print(f"{_INDENT}[yellow]Banner:[/yellow] {display}")

    elif protocol == "ip_observed":
        ttl = fields.get("ttl", "?")
        os_hint = fields.get("ttl_os_hint", "")
        hops = fields.get("ttl_hops", "")
        src_port = fields.get("src_port")
        dst_port = fields.get("dst_port")
        hint_str = f" ({os_hint}, {hops} hops)" if os_hint else ""
        port_str = ""
        if src_port and dst_port:
            port_str = f"  Port: {src_port} -> {dst_port}"
        console.print(f"{_INDENT}[yellow]TTL: {ttl}{hint_str}{port_str}[/yellow]")

    elif protocol == "http_useragent":
        method = fields.get("method", "")
        path = fields.get("path", "")
        host = fields.get("host", "")
        ua = fields.get("user_agent", "")
        parts = []
        if method:
            parts.append(method)
        if path:
            parts.append(path)
        if host:
            parts.append(f"Host: {host}")
        if parts:
            console.print(f"{_INDENT}[yellow]{'  '.join(parts)}[/yellow]")
        if ua:
            display_ua = ua[:120] + ("..." if len(ua) > 120 else "")
            console.print(f"{_INDENT}[yellow]UA: {display_ua}[/yellow]")

    elif protocol == "dns_answer":
        qname = fields.get("query_name", "?")
        rtype = fields.get("record_type", "?")
        answer_ip = fields.get("answer_ip", "")
        hostname = fields.get("hostname", "")
        ttl = fields.get("ttl", "")
        target = answer_ip or hostname or "?"
        ttl_str = f"  TTL: {ttl}" if ttl else ""
        console.print(
            f"{_INDENT}[yellow]{qname}  {rtype} -> {target}{ttl_str}[/yellow]"
        )

    # ── Evidence from verdict's evidence chain ──
    for i, ev in enumerate(evidence_chain):
        is_last = i == len(evidence_chain) - 1
        prefix = "\u2514\u2500" if is_last else "\u251c\u2500"
        conf_pct = ev.get("certainty", 0)
        style = _conf_style(conf_pct)
        source = ev.get("source", "?")

        parts = []
        if ev.get("vendor"):
            parts.append(f"[white]vendor=[/white]{ev['vendor']}")
        if ev.get("platform"):
            parts.append(f"[white]os=[/white]{ev['platform']}")
        if ev.get("category"):
            parts.append(f"[white]type=[/white]{ev['category']}")
        if ev.get("model"):
            parts.append(f"[white]model=[/white]{ev['model']}")
        detail = ", ".join(parts) if parts else ev.get("match_type", source)
        console.print(
            f"{_INDENT}  {prefix} [cyan]{source}[/cyan]: "
            f"{detail} [{style}]({conf_pct}%)[/{style}]"
        )

    console.print()  # blank line


def _matches_filter(event: dict, packet_filter: str) -> bool:
    """Check if event matches the user's --filter."""
    pkt = event.get("packet") or {}
    src_mac = pkt.get("src_mac", event.get("mac", ""))
    protocol = pkt.get("protocol", "")
    if packet_filter.startswith("mac="):
        return src_mac.upper().startswith(packet_filter[4:].upper())
    return protocol == packet_filter
