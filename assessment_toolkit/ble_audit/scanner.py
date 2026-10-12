"""
Recon / fingerprinting module.

Passively scans for nearby BLE advertisements and builds a DiscoveredDevice
record for each one — no connection is made, so this phase is non-invasive
and safe to run against any device in range.
"""
import asyncio

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .models import DiscoveredDevice


async def scan(duration: float = 8.0, name_filter: str | None = None) -> list[DiscoveredDevice]:
    """
    Passively scan for BLE advertisements for `duration` seconds.

    If name_filter is given, only devices whose advertised name contains
    that substring (case-insensitive) are kept — handy once you know which
    device you're targeting and want to cut the noise.
    """
    found: dict[str, DiscoveredDevice] = {}

    def _callback(device: BLEDevice, adv: AdvertisementData) -> None:
        mfg_data = {cid: payload.hex() for cid, payload in adv.manufacturer_data.items()}
        svc_data = {uuid: payload.hex() for uuid, payload in adv.service_data.items()}

        found[device.address] = DiscoveredDevice(
            address=device.address,
            name=adv.local_name or device.name,
            rssi=adv.rssi,
            service_uuids=list(adv.service_uuids),
            manufacturer_data=mfg_data,
            service_data=svc_data,
            tx_power=adv.tx_power,
        )

    scanner = BleakScanner(_callback)
    await scanner.start()
    try:
        await asyncio.sleep(duration)
    finally:
        await scanner.stop()

    devices = list(found.values())
    if name_filter:
        needle = name_filter.lower()
        devices = [d for d in devices if d.name and needle in d.name.lower()]

    # Strongest signal (closest / most reliable) first.
    devices.sort(key=lambda d: (d.rssi is None, -(d.rssi or -999)))
    return devices


def print_devices(devices: list[DiscoveredDevice]) -> None:
    if not devices:
        print("No BLE devices found.")
        return
    print(f"\n{'ADDRESS':<20}{'RSSI':<7}{'NAME':<25}SERVICES")
    print("-" * 90)
    for d in devices:
        name = d.name or "(unknown)"
        rssi = f"{d.rssi} dBm" if d.rssi is not None else "n/a"
        svcs = ", ".join(d.service_uuids[:2]) + ("..." if len(d.service_uuids) > 2 else "")
        print(f"{d.address:<20}{rssi:<7}{name:<25}{svcs}")


if __name__ == "__main__":
    devices = asyncio.run(scan())
    print_devices(devices)
