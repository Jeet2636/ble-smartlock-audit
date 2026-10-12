"""
THE TARGET: a deliberately-vulnerable BLE smart door lock (SmartLock-AX300).

Emulates a cheap smart lock misconfigured the way many real BLE IoT products
are: every characteristic is exposed with NO pairing/bonding/encryption, so
anyone in radio range can read secrets and send commands without authenticating.

Run this on the "target" machine (any computer with Bluetooth). It uses the
host's built-in Bluetooth via the `bless` library. Validated on Windows; the
Windows BLE backend needs a couple of compatibility shims, applied below only
when running on Windows.

Exposed GATT characteristics (all unauthenticated — that absence IS the vuln):

  - DEVICE INFO (read)   : model / firmware string (benign fingerprint)
  - UNLOCK PIN  (read)   : the master unlock code -- must never be readable (THE LEAK)
  - LOCK STATE  (read)   : door state, LOCKED / UNLOCKED (status only, not writable)
  - UNLOCK CMD  (write)  : write the PIN here; correct PIN opens the door
  - WIFI CREDS  (read)   : the Wi-Fi SSID + password the lock stored

Intended flow: a remote that already knows the PIN writes it to UNLOCK CMD.
The flaw: UNLOCK PIN is readable with no auth, so an intruder can steal the
PIN straight off the lock and then open it exactly like a real remote.

Controlled, intentionally-vulnerable target for our own assessment tool only.
"""
import asyncio
import sys
import threading
from datetime import datetime

if sys.platform == "win32":
    # --- bless WinRT backend compatibility shims (Windows only) --------------
    # bless 0.3.0's WinRT backend has two bugs that otherwise stop a GATT server
    # from working on a typical Windows laptop:
    #   1. BlessServer.__init__ builds a BLEAdapter whose CreateFile on a
    #      hand-built device path fails ("system cannot find the file
    #      specified"). That adapter is only used for a registry-rename hack we
    #      don't use, so we neutralise it.
    #   2. The read/write handlers spin up a new asyncio loop inside the WinRT
    #      callback (raises "cannot run the event loop while another loop is
    #      running", silently swallowed) and pywinrt drops the handler delegate
    #      so the event never fires. We replace both handlers (poll the WinRT
    #      async op instead of nesting a loop) and keep strong references.
    import time
    import traceback
    import types
    import bless.backends.winrt.server as _winrt_server

    class _NoopBLEAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def set_local_name(self, *args, **kwargs):
            pass

    _winrt_server.BLEAdapter = _NoopBLEAdapter

    def _await_winrt_op(op, timeout=5.0):
        """Block until a WinRT IAsyncOperation finishes; return its result."""
        deadline = time.monotonic() + timeout
        while op.status == 0 and time.monotonic() < deadline:  # 0 == Started
            time.sleep(0.002)
        if op.status != 1:  # 1 == Completed (2 Canceled, 3 Error)
            raise RuntimeError(f"WinRT async op status={op.status} err={op.error_code}")
        return op.get_results()

    def _read_characteristic(self, sender, args):
        deferral = args.get_deferral()
        try:
            value = self.read_request(str(sender.uuid), {})
            value = value if value is not None else b"\x00"
            writer = _winrt_server.DataWriter()
            writer.write_bytes(bytes(value))
            request = _await_winrt_op(args.get_request_async())
            if request is not None:
                request.respond_with_value(writer.detach_buffer())
        except Exception:
            traceback.print_exc()
        finally:
            deferral.complete()

    def _write_characteristic(self, sender, args):
        deferral = args.get_deferral()
        try:
            request = _await_winrt_op(args.get_request_async())
            if request is None:
                return
            reader = _winrt_server.DataReader.from_buffer(request.value)
            if reader is None:
                return
            n_bytes = reader.unconsumed_buffer_length
            value = bytearray(reader.read_byte() for _ in range(n_bytes))
            self.write_request(str(sender.uuid), value)
            if request.option == _winrt_server.GattWriteOption.WRITE_WITH_RESPONSE:
                request.respond()
        except Exception:
            traceback.print_exc()
        finally:
            deferral.complete()

    def _install_handlers(server):
        """Bind our corrected handlers as instance attributes (strong refs)
        before any characteristic is added, so pywinrt can't garbage-collect the
        delegates and silently drop the GATT events."""
        server.read_characteristic = types.MethodType(_read_characteristic, server)
        server.write_characteristic = types.MethodType(_write_characteristic, server)
        server.subscribe_characteristic = types.MethodType(
            _winrt_server.BlessServerWinRT.subscribe_characteristic, server
        )
else:
    def _install_handlers(server):
        """Non-Windows backends (CoreBluetooth / BlueZ) need no shims."""
        pass

from bless import (
    BlessServer,
    GATTCharacteristicProperties,
    GATTAttributePermissions,
)

SERVICE_UUID = "A07498CA-AD5B-474E-940D-16F1FBE7E8CD"
# All characteristics are exposed with no auth — that is the vulnerability.
INFO_CHAR_UUID    = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021D"  # device info / firmware (benign)
PIN_CHAR_UUID     = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B"  # master unlock PIN (sensitive, THE LEAK)
STATE_CHAR_UUID   = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021C"  # door lock state (read-only status)
UNLOCK_CMD_UUID   = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021F"  # write the PIN here to open the door
WIFI_CHAR_UUID    = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021E"  # stored Wi-Fi credentials (sensitive)

DEVICE_NAME = "SmartLock-AX300"
CORRECT_PIN = "4873"           # the real code; the lock opens only on this exact PIN
AUTO_RELOCK_SECONDS = 10       # door re-locks itself this many seconds after opening

trigger = asyncio.Event()
_server = None          # set in run(); used to flip the lock state
_relock_timer = None    # threading.Timer that re-locks the door

# Friendly labels for the event log.
_CHAR_LABELS = {
    INFO_CHAR_UUID.lower(): "device info",
    PIN_CHAR_UUID.lower(): "unlock PIN",
    STATE_CHAR_UUID.lower(): "door state",
    UNLOCK_CMD_UUID.lower(): "unlock command",
    WIFI_CHAR_UUID.lower(): "Wi-Fi credentials",
}


def _log(msg: str) -> None:
    """Print a timestamped event line, like a real device's console log."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def _set_state(value: bytes) -> None:
    if _server is not None:
        state = _server.get_characteristic(STATE_CHAR_UUID)
        if state is not None:
            state.value = bytearray(value)


def _auto_relock() -> None:
    _set_state(b"LOCKED")
    _log(f"Auto-relock after {AUTO_RELOCK_SECONDS}s  ->  door is now LOCKED")


def _schedule_relock() -> None:
    global _relock_timer
    if _relock_timer is not None:
        _relock_timer.cancel()
    _relock_timer = threading.Timer(AUTO_RELOCK_SECONDS, _auto_relock)
    _relock_timer.daemon = True
    _relock_timer.start()


def read_request(characteristic, **kwargs):
    label = _CHAR_LABELS.get(characteristic.uuid.lower(), characteristic.uuid)
    _log(f"READ   {label}")
    return characteristic.value


def write_request(characteristic, value, **kwargs):
    characteristic.value = value
    raw = bytes(value)

    # The only control surface: writing the PIN to UNLOCK CMD opens the door.
    if characteristic.uuid.lower() == UNLOCK_CMD_UUID.lower():
        submitted = raw.decode(errors="replace").strip()
        if submitted == CORRECT_PIN:
            _set_state(b"UNLOCKED")
            _log("UNLOCK accepted (correct PIN)  ->  door is now UNLOCKED")
            _schedule_relock()
        else:
            _log(f"UNLOCK denied (wrong PIN {submitted!r})  ->  door stays LOCKED")
    else:
        _log(f"WRITE  {_CHAR_LABELS.get(characteristic.uuid.lower(), characteristic.uuid)}")


async def run():
    global _server
    server = BlessServer(name=DEVICE_NAME)
    _server = server
    server.read_request_func = read_request
    server.write_request_func = write_request
    _install_handlers(server)  # Windows GATT-handler shims (no-op elsewhere)

    await server.add_new_service(SERVICE_UUID)

    # No GATTAttributePermissions passed = no encryption/auth requirement.
    # That absence IS the vulnerability we're demonstrating.
    open_perms = GATTAttributePermissions.readable | GATTAttributePermissions.writeable

    read_flag = GATTCharacteristicProperties.read
    write_flag = GATTCharacteristicProperties.write

    # Benign device fingerprint — realistic context, not sensitive on its own.
    await server.add_new_characteristic(
        SERVICE_UUID, INFO_CHAR_UUID, read_flag,
        b"SmartLock-AX300;fw=2.1.4;hw=rev-C", open_perms,
    )

    # The master unlock code — should require auth; here it is readable. THE LEAK.
    await server.add_new_characteristic(
        SERVICE_UUID, PIN_CHAR_UUID, read_flag,
        b"unlock_pin=4873", open_perms,
    )

    # Door lock state — read-only status. Only the PIN (below) can change it.
    await server.add_new_characteristic(
        SERVICE_UUID, STATE_CHAR_UUID, read_flag,
        b"LOCKED", open_perms,
    )

    # Unlock command — write the PIN here. Open to anyone (no auth) to write.
    await server.add_new_characteristic(
        SERVICE_UUID, UNLOCK_CMD_UUID, write_flag,
        b"", open_perms,
    )

    # Stored Wi-Fi credentials — network compromise if leaked.
    await server.add_new_characteristic(
        SERVICE_UUID, WIFI_CHAR_UUID, read_flag,
        b"wifi_ssid=Nirma_Home_5G;wifi_pass=hostel@2026", open_perms,
    )

    await server.start()
    print(f"\n{DEVICE_NAME} advertising. Service: {SERVICE_UUID}")
    print(f"  {INFO_CHAR_UUID}  device info      (read)")
    print(f"  {PIN_CHAR_UUID}  unlock PIN       (read, no auth)   <- the leak")
    print(f"  {STATE_CHAR_UUID}  door lock state  (read-only)")
    print(f"  {UNLOCK_CMD_UUID}  unlock command   (write PIN here)")
    print(f"  {WIFI_CHAR_UUID}  wifi credentials (read, no auth)")
    print("\n--- event log (Ctrl+C to stop) ---")
    _log(f"SmartLock-AX300 online  ->  door LOCKED (auto-relock {AUTO_RELOCK_SECONDS}s)")

    try:
        await trigger.wait()
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)
