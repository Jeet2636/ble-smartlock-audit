# smartlock_target — the vulnerable BLE device

Runs on the **target** machine. Emulates a cheap smart door lock,
**SmartLock-AX300**, deliberately misconfigured: every GATT characteristic is
exposed with **no pairing, bonding, or encryption**.

> Part of the BLE Security Assessment Framework. See the project
> [README](../README.md) and [DEMO guide](../DEMO.md).

## Run

```
pip install -r requirements.txt
python peripheral.py
```

The door starts **LOCKED**, advertises BLE service `A07498CA-…`, and the console
becomes a live, timestamped **event log**. The door **auto-relocks 10 seconds**
after any unlock.

## GATT map (service `A07498CA-…`)

| Characteristic | UUID ends | Access | Value | Note |
|----------------|-----------|--------|-------|------|
| Device info | `…021D` | read | `SmartLock-AX300;fw=2.1.4;…` | benign fingerprint |
| Unlock PIN | `…021B` | read | `unlock_pin=4873` | **the leak** — must never be readable |
| Door state | `…021C` | read | `LOCKED` / `UNLOCKED` | status only |
| Unlock command | `…021F` | write | (write the PIN) | correct PIN opens the door |
| Wi-Fi creds | `…021E` | read | `wifi_ssid=…;wifi_pass=…` | network compromise if leaked |

**Intended flow:** a remote that already knows the PIN writes `4873` to the
unlock command. **The flaw:** the PIN is readable with no auth, so an intruder
can steal it off the device and open the lock like a real remote.

## Platform note

Uses the host's built-in Bluetooth via the `bless` library. Validated on
**Windows** (the code applies Windows-only compatibility shims automatically;
they are a no-op on other platforms). `requirements.txt` lists the Windows
dependencies (`bless` + `pysetupdi`).
