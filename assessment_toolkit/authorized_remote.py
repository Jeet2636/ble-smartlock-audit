"""
AUTHORIZED REMOTE  —  the legitimate key fob.

This is how the lock is *meant* to be opened. The remote was provisioned with
the PIN by the owner (hardcoded below), so it already knows the code. It does
NOT read the PIN off the lock — it simply presents the code it was given.

Use this as a scripted stand-in for the iPhone (nRF Connect) if you'd rather
run the authorized role from the Mac. Run AFTER starting peripheral.py.

    python3 authorized_remote.py
"""
import asyncio
import sys

from bleak import BleakClient, BleakScanner

SERVICE_UUID    = "a07498ca-ad5b-474e-940d-16f1fbe7e8cd"
STATE_CHAR_UUID = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021c"
UNLOCK_CMD_UUID = "51ff12bb-3ed8-46e5-b4f9-d64e2fec021f"

# The owner provisioned this remote with the PIN out-of-band. It is NOT read
# from the lock — that is the whole difference between this and the intruder.
KNOWN_PIN = "4873"


async def find_lock(timeout: float = 12.0):
    print(f"[*] Scanning for the lock ({SERVICE_UUID}) ...")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for _, (device, adv) in devices.items():
        if SERVICE_UUID in [u.lower() for u in adv.service_uuids]:
            print(f"[+] Found the lock: {device.address}")
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
        print("[+] Connected as the authorized remote.\n")

        state = await read_text(client, STATE_CHAR_UUID)
        print(f"    Door state before : {state}")

        print(f"[*] Presenting provisioned PIN (known in advance, not read from the lock) ...")
        await client.write_gatt_char(UNLOCK_CMD_UUID, KNOWN_PIN.encode(), response=True)
        await asyncio.sleep(0.5)

        state = await read_text(client, STATE_CHAR_UUID)
        print(f"    Door state after  : {state}")

        if state.strip().upper().endswith("UNLOCKED"):
            print("\n[+] Door opened by the authorized remote. This is normal, intended use.")
            return 0
        print("\n[!] Door did not open; check the PIN or the lock output.")
        return 2


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)
