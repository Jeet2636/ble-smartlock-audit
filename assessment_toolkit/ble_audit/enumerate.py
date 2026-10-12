"""
GATT enumeration + vulnerability classification module.

Connects to a target device, walks every service/characteristic/descriptor,
and flags characteristics that permit read/write with no authentication —
the core misconfiguration this tool hunts for.
"""
import asyncio

from bleak import BleakClient

from . import cvss
from .models import AssessmentResult, CharacteristicInfo, DiscoveredDevice, Finding, ServiceInfo, Severity

# Properties that, combined, mean "anyone who connects can read or change this
# value" with no pairing/bonding/encryption required. BlueZ/bleak don't expose
# a per-characteristic "requires auth" flag directly — in practice, if the
# GATT op succeeds without the stack prompting for pairing, it's unauthenticated.
RISKY_PROPS = {"read", "write", "write-without-response"}

# The 128-bit base shared by all SIG-assigned (16-bit) GATT UUIDs.
_SIG_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"

# Friendly labels so the report reads in plain English instead of raw UUIDs.
# Only entries we are confident about are named; anything else stays a UUID.
_CUSTOM_NAMES = {
    "a07498ca-ad5b-474e-940d-16f1fbe7e8cd": "SmartLock-AX300 Control Service (intentionally insecure)",
    "51ff12bb-3ed8-46e5-b4f9-d64e2fec021d": "Device info / firmware",
    "51ff12bb-3ed8-46e5-b4f9-d64e2fec021b": "Unlock PIN (master code)",
    "51ff12bb-3ed8-46e5-b4f9-d64e2fec021c": "Door lock state",
    "51ff12bb-3ed8-46e5-b4f9-d64e2fec021f": "Unlock command",
    "51ff12bb-3ed8-46e5-b4f9-d64e2fec021e": "Wi-Fi credentials",
}
_SIG_NAMES = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "180a": "Device Information",
    "180f": "Battery Service",
    "1812": "Human Interface Device",
    "2a00": "Device Name",
    "2a19": "Battery Level",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String",
    "2a50": "PnP ID",
}

# If a readable value's text contains any of these, it is almost certainly
# something that should never be exposed unauthenticated -> escalate severity.
_SENSITIVE_HINTS = ("pin", "pass", "pwd", "secret", "token", "key", "admin",
                    "cred", "ssid", "serial", "auth")


def _friendly_name(uuid: str) -> str | None:
    """Return a human label for a UUID, or None if we don't recognise it."""
    low = uuid.lower()
    if low in _CUSTOM_NAMES:
        return _CUSTOM_NAMES[low]
    if low.startswith("0000") and low.endswith(_SIG_BASE_SUFFIX):
        return _SIG_NAMES.get(low[4:8])
    return None


def _decode_value(raw: bytes) -> tuple[str, str | None]:
    """
    Turn raw characteristic bytes into (hex_preview, text).

    `text` is the UTF-8 decode when the value is printable (the interesting
    case: leaked PINs, names, states, tokens show up as readable strings);
    otherwise it's None and only the hex is meaningful.
    """
    hex_preview = raw[:64].hex()
    text = None
    try:
        decoded = raw.decode("utf-8")
        if decoded.isprintable():
            text = decoded[:200]
    except UnicodeDecodeError:
        pass
    return hex_preview, text


def _looks_sensitive(text: str | None) -> bool:
    return text is not None and any(hint in text.lower() for hint in _SENSITIVE_HINTS)


async def enumerate_device(
    address: str,
    device: DiscoveredDevice | None = None,
    attempt_read: bool = True,
    timeout: float = 15.0,
) -> AssessmentResult:
    """
    Connect to `address`, walk its full GATT profile, and return services +
    preliminary findings. `attempt_read` actually reads readable characteristics
    to capture evidence (the real leaked value) — set False for a profile-only pass.
    """
    result = AssessmentResult(target_address=address, target_name=device.name if device else None, device=device)

    async with BleakClient(address, timeout=timeout) as client:
        for service in client.services:
            svc_info = ServiceInfo(
                uuid=service.uuid,
                handle=service.handle,
                name=_friendly_name(service.uuid),
            )

            for char in service.characteristics:
                props = list(char.properties)
                value_preview = None
                value_text = None

                if attempt_read and "read" in props:
                    try:
                        # Read by characteristic object (not UUID) so duplicate
                        # UUIDs across services resolve to the right attribute.
                        raw = bytes(await client.read_gatt_char(char))
                        value_preview, value_text = _decode_value(raw)
                    except Exception:
                        value_preview = value_text = None  # read refused/failed — not unauthenticated

                char_info = CharacteristicInfo(
                    uuid=char.uuid,
                    name=_friendly_name(char.uuid),
                    handle=char.handle,
                    properties=props,
                    service_uuid=service.uuid,
                    descriptor_uuids=[d.uuid for d in char.descriptors],
                    value_preview=value_preview,
                    value_text=value_text,
                )
                svc_info.characteristics.append(char_info)

                # A read that actually succeeded with no pairing prompt is our
                # strongest evidence of unauthenticated access.
                readable_confirmed = value_preview is not None
                writable = "write" in props or "write-without-response" in props

                if readable_confirmed or writable:
                    result.findings.append(_classify(char_info, readable_confirmed, writable))

            result.services.append(svc_info)

    return result


def _classify(char_info: CharacteristicInfo, readable_confirmed: bool, writable: bool) -> Finding:
    access = []
    if readable_confirmed:
        access.append("read")
    if writable:
        access.append("write")
    access_str = "/".join(access)

    label = char_info.name or char_info.uuid
    sensitive = _looks_sensitive(char_info.value_text)

    # Human-readable form of what leaked, preferring decoded text over hex.
    if char_info.value_text is not None:
        leaked = repr(char_info.value_text)
    elif char_info.value_preview:
        leaked = f"0x{char_info.value_preview}"
    else:
        leaked = None

    # Severity: write access or confirmed sensitive data exposure is High;
    # a plain unauthenticated read is Medium.
    severity = Severity.HIGH if (writable or sensitive) else Severity.MEDIUM

    # Concrete impact sentence spelling out what an attacker actually gets.
    impact_bits = []
    if readable_confirmed:
        impact_bits.append(
            "read its value without authentication"
            + (f" (leaked value: {leaked})" if leaked is not None else "")
        )
    if writable:
        impact_bits.append("overwrite its value without authentication")
    impact = " and ".join(impact_bits)

    if sensitive:
        title = f"Sensitive data exposed over unauthenticated {access_str}: {label}"
    else:
        title = f"Unauthenticated {access_str} access on {label}"

    cvss_vector, cvss_score = cvss.for_finding(readable_confirmed, writable, sensitive)

    return Finding(
        finding_id=f"BLE-{char_info.uuid[-8:]}-{access_str.upper().replace('/', '-')}",
        title=title,
        severity=severity,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        characteristic_uuid=char_info.uuid,
        service_uuid=char_info.service_uuid,
        description=(
            f"Characteristic {label} ({char_info.uuid}, handle {char_info.handle}) "
            f"permits {access_str} with no pairing, bonding, or encryption required. "
            f"Any device within radio range can {impact}."
        ),
        evidence=(
            f"properties={char_info.properties}"
            + (f"; leaked value (plaintext): {char_info.value_text!r}" if char_info.value_text else "")
            + (f"; bytes (hex): {char_info.value_preview}" if char_info.value_preview else "")
        ),
        remediation=(
            "Require pairing/bonding (Security Mode 1 Level 2+) before granting access to this "
            "characteristic, or move sensitive state behind an application-layer auth check "
            "performed over an authenticated channel."
        ),
    )


def print_summary(result: AssessmentResult) -> None:
    print(f"\nTarget: {result.target_address} ({result.target_name or 'unknown'})")
    print(f"Services discovered: {len(result.services)}")
    for svc in result.services:
        suffix = f"   [{svc.name}]" if svc.name else ""
        print(f"\n  Service {svc.uuid}{suffix}")
        for c in svc.characteristics:
            suffix = f"   [{c.name}]" if c.name else ""
            print(f"    - {c.uuid}  props={c.properties}{suffix}")
            if c.value_text is not None:
                print(f"        value: {c.value_text!r}")
            elif c.value_preview:
                print(f"        value: 0x{c.value_preview}")

    print(f"\nFindings: {len(result.findings)}")
    for f in result.findings:
        cvss = f"CVSS {f.cvss_score}" if f.cvss_score is not None else ""
        print(f"  [{f.severity.value}] {cvss}  {f.title}")
        if f.cvss_vector:
            print(f"        {f.cvss_vector}")
        if f.evidence:
            print(f"        {f.evidence}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m ble_audit.enumerate <TARGET_ADDRESS>")
        sys.exit(1)
    res = asyncio.run(enumerate_device(sys.argv[1]))
    print_summary(res)
