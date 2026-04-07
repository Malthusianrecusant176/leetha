"""Connection type inference — determine if a device is wired, wireless, or unknown.

Uses multiple signals:
1. MAC randomization (locally-administered bit → wireless)
2. Device type (phones/tablets always wireless, switches/servers always wired)
3. Wireless-only OUI prefixes (Intel Wireless, Qualcomm Atheros, etc.)
4. mDNS service indicators (Apple mobile services, Google Cast, etc.)
5. LLDP/CDP presence (always wired)
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Device types that are always wired
_ALWAYS_WIRED = frozenset({
    "router", "switch", "access_point", "firewall", "gateway",
    "load_balancer", "mesh_router", "server", "nas",
    "hypervisor", "container_host", "kubernetes_node",
    "kvm_host", "hyper_v", "printer", "scanner",
    "voip_phone", "pbx", "storage_array", "thin_client",
    "ups", "pdu", "pos_terminal", "digital_signage",
    "media_server", "wireless_bridge", "3d_printer",
    "plc", "rtu", "hmi", "industrial_switch", "industrial_robot",
    "cnc_machine", "power_meter", "fire_alarm", "elevator_controller",
    "building_automation", "access_control", "atm",
    "time_clock", "lab_instrument", "medical_device",
    "handheld_scanner", "kiosk",
})

# Device types that are always wireless
_ALWAYS_WIRELESS = frozenset({
    "smartphone", "phone", "mobile", "tablet", "wearable",
})

# Device types that are almost always wireless
# Device types that are almost always wireless
# NOTE: smart_tv and game_console are NOT here — they can be wired via ethernet
_LIKELY_WIRELESS = frozenset({
    "smart_speaker", "smart_home", "thermostat", "doorbell",
    "smart_lighting", "smart_plug", "smart_lock",
    "streaming_device", "smart_display", "robot_vacuum", "iot",
    "microcontroller", "embedded", "camera", "ip_camera",
    "wearable", "sensor",
    "ev_charger", "solar_inverter", "irrigation", "garage_door",
    "smoke_detector", "air_purifier", "baby_monitor", "pet_device",
    "drone", "appliance",
    "dashcam", "weather_station", "sbc",
    "body_camera", "satellite_terminal", "tactical_radio",
    "gps_tracker", "marine_device", "vehicle",
    "vending_machine", "wireless_presentation",
})

# OUI prefixes (first 3 bytes) for wireless-only chipsets
_WIRELESS_OUI_PREFIXES = frozenset({
    # Intel Wireless adapters
    "00:13:02", "00:13:ce", "00:13:e8", "00:15:00", "00:16:ea",
    "00:18:de", "00:1b:77", "00:1c:bf", "00:1d:e0", "00:1e:64",
    "00:1e:65", "00:21:5c", "00:21:5d", "00:21:6a", "00:22:fa",
    "00:22:fb", "00:24:d6", "00:24:d7", "00:26:c6", "00:26:c7",
    "00:27:10", "08:d4:0c", "34:02:86", "40:25:c2", "58:91:cf",
    "5c:51:4f", "60:67:20", "68:5d:43", "7c:76:35", "7c:b2:7d",
    "84:3a:5b", "8c:70:5a", "a4:34:d9", "b4:6b:fc", "bc:77:37",
    "c8:ff:28", "d0:7e:35", "d4:3b:04", "dc:1b:a1", "e0:94:67",
    "f4:d4:88", "f8:63:3f",
    # Qualcomm Atheros wireless
    "00:03:7f", "00:09:5b", "00:0b:6b", "00:0d:0b", "00:0e:6a",
    "00:11:f5", "00:13:74", "00:15:af", "00:1a:6b", "00:1b:9e",
    "00:1d:0f", "00:1e:a6", "00:20:a6", "00:24:05", "04:f0:21",
    "1c:b7:2c", "28:c2:dd", "48:a4:72", "54:e6:fc", "74:da:38",
    "9c:b7:0d", "b4:ee:b4", "d8:c7:c8",
    # Broadcom wireless (BCM43xx)
    "00:10:18", "00:90:4c", "20:10:7a", "40:4d:7f",
    # MediaTek wireless
    "00:0c:e7", "00:0c:43", "00:13:31", "0c:96:bf", "18:d6:c7",
    "70:66:1b", "8c:88:2b", "e8:4e:06",
    # Realtek wireless
    "48:02:2a", "60:02:b4", "90:de:80", "c0:25:e9", "d8:c4:6a",
    # Espressif (ESP8266/ESP32 — always wireless)
    "18:fe:34", "24:0a:c4", "24:62:ab", "24:6f:28", "30:ae:a4",
    "3c:61:05", "3c:71:bf", "40:f5:20", "54:5a:a6", "5c:cf:7f",
    "60:01:94", "68:c6:3a", "70:03:9f", "80:7d:3a", "84:0d:8e",
    "84:cc:a8", "90:97:d5", "94:b9:7e", "a0:20:a6", "a4:cf:12",
    "a4:e5:7c", "ac:67:b2", "b4:e6:2d", "bc:dd:c2", "c4:4f:33",
    "c8:2b:96", "cc:50:e3", "d8:a0:1d", "dc:4f:22", "e0:98:06",
    "ec:fa:bc", "f0:08:d1",
})

# Manufacturers whose devices are virtually always wireless
_WIRELESS_MANUFACTURERS = frozenset({
    "apple", "samsung", "google", "xiaomi", "huawei", "oppo", "vivo",
    "oneplus", "realme", "nothing", "motorola", "nokia",
    "roborock", "ecovacs", "irobot", "dreame",  # robot vacuums
    "withings", "fitbit",  # health/wearables
    "ring", "arlo", "wyze", "blink",  # wireless cameras/doorbells
    "sonos", "jbl", "bose",  # wireless speakers
    "ecobee", "nest",  # smart home
    "lutron", "philips hue", "lifx", "hue",  # smart lighting
    "shelly", "meross", "kasa", "tp-link kasa",  # smart plugs
    "august", "yale",  # smart locks
    "roku",  # streaming
    "espressif",  # ESP32/ESP8266 always WiFi
    "tuya", "smartlife",  # IoT platform devices
})

# mDNS services that indicate wireless-only devices
_WIRELESS_MDNS_SERVICES = frozenset({
    "_apple-mobdev2._tcp",
    "_apple-mobdev._tcp",
    "_companion-link._tcp",
    "_touch-able._tcp",
    "_amzn-wplay._tcp",
    "_googlecast._tcp",
    "_googlehomedevice._tcp",
    "_spotify-connect._tcp",
    "_sonos._tcp",
    "_roku._tcp",
    "_smartthings._tcp",
})


def infer_connection_type(
    *,
    mac: str,
    device_type: str | None,
    is_randomized_mac: bool = False,
    manufacturer: str | None = None,
    observed_services: list[str] | None = None,
    has_lldp: bool = False,
    has_cdp: bool = False,
) -> str:
    """Infer whether a device is wired, wireless, or unknown.

    Returns: "wired", "wireless", or "unknown"
    """
    dt = (device_type or "").lower()

    # LLDP/CDP = definitively wired
    if has_lldp or has_cdp:
        return "wired"

    # Always-wired device types
    if dt in _ALWAYS_WIRED:
        return "wired"

    # MAC randomization = definitively wireless
    if is_randomized_mac:
        return "wireless"

    # Always-wireless device types
    if dt in _ALWAYS_WIRELESS:
        return "wireless"

    # Likely-wireless device types
    if dt in _LIKELY_WIRELESS:
        return "wireless"

    # Check manufacturer — some only make wireless devices
    mfr = (manufacturer or "").lower()
    if any(w in mfr for w in _WIRELESS_MANUFACTURERS):
        return "wireless"

    # Check OUI prefix for wireless-only chipsets
    mac_prefix = mac[:8].lower() if mac else ""
    if mac_prefix in _WIRELESS_OUI_PREFIXES:
        return "wireless"

    # Check mDNS services for wireless indicators
    if observed_services:
        for svc in observed_services:
            if svc in _WIRELESS_MDNS_SERVICES:
                return "wireless"


    # Desktop/computer — could be either, default to unknown
    if dt in ("computer", "workstation", "desktop", "laptop"):
        # Laptops are more likely wireless
        if dt == "laptop":
            return "wireless"
        return "unknown"

    return "unknown"
