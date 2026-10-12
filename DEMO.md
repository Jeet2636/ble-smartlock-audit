# DEMO GUIDE — BLE Smart Lock Security Assessment

A ready-to-present script. Pick the variation that fits the time and the
devices you have on hand. Full background is in [README.md](README.md).

**The one-line story:** *"This is a smart door lock. With no key and no pairing,
from across the room, we read its secret PIN and Wi-Fi password and open the
door — and our tool documents it as a professional security report."*

---

## Pre-flight (2 minutes, before you present)

- [ ] Bluetooth ON on all devices.
- [ ] **Target** and **attacker** are **two separate devices** (one radio can't attack itself).
- [ ] Dependencies installed (`pip install -r requirements.txt` in each folder).
- [ ] Phone has **nRF Connect** installed (if using the phone).
- [ ] Start the lock and keep its console visible — it's a live event log:
  ```
  cd smartlock_target
  python peripheral.py
  ```
  You should see `SmartLock-AX300 online -> door LOCKED (auto-relock 10s)`.

The door **auto-relocks 10 seconds** after every unlock, so you can repeat any
act without restarting.

---

## MAIN DEMO (recommended, ~5 min, 3 devices)

Keep the **target console** on screen the whole time — every action prints a
timestamped line, so the audience sees the attack land in real time.

### Act 1 — Normal, authorized use  *(sets the baseline)*
Run the legitimate remote (it already knows the PIN, like a real key fob):
```
cd assessment_toolkit
python authorized_remote.py
```
> **Say:** *"This is how it's meant to work — a remote that was given the PIN opens the lock."*
> Target console shows `UNLOCK accepted (correct PIN) -> UNLOCKED`, then `Auto-relock -> LOCKED`.

### Act 2 — A casual attacker with just a phone  *("anyone can do this")*
On the phone in **nRF Connect**:
1. Connect to the lock (shows under the target's Bluetooth name).
2. Open the service starting **`A07498CA`**.
3. On char **`…021B`** tap **read (⬇)** → it reveals **`unlock_pin=4873`**.
4. On char **`…021F`** tap **write (⬆)** → format **Text** → type **`4873`** → Write.
5. Read **`…021C`** → **`UNLOCKED`**.
> **Say:** *"No special hardware, no prior knowledge — a free app read the secret the lock should never expose, and opened the door."*

### Act 3 — A capable attacker with the toolkit  *(recon → exploit → report)*
On the attacker computer:
```
cd assessment_toolkit
python -m ble_audit.cli scan           # (a) passive recon: lists ALL nearby BLE devices, undetected
python intruder.py                     # (b) automated: steals the PIN, opens the door, grabs Wi-Fi
python -m ble_audit.cli enum <ADDRESS> --out result.json   # (c) full audit
```
Then **open `report.html`** in a browser.
> **Say:** *"A capable attacker maps the area silently, exploits the lock automatically, and — as auditors — we produce a formal report: every finding, its CVSS score, the exact leaked value as evidence, and the fix."*

---

## DEMO VARIATIONS (pick per time / devices)

| # | Variation | Devices | When to use |
|---|-----------|---------|-------------|
| A | **Full demo** (Acts 1-3 above) | target + attacker PC + phone | the real thing; most impact |
| B | **Two-device** (Acts 1 + 3, skip phone) | target + attacker PC | no phone / short on time |
| C | **Phone-only attack** (Act 2 only) | target + phone | quick "anyone can" hook, no toolkit |
| D | **Report walk-through** | target + attacker PC | emphasise the audit: run `enum`, then talk through `report.html` + CVSS |

All variations use the **same running target** — just start `peripheral.py`
once and run whichever acts you want.

---

## What to point at while presenting

- **Target console** — the timestamped event log makes the attack visible live:
  `READ unlock PIN` (the theft) → `UNLOCK accepted -> UNLOCKED` (the breach) → `Auto-relock`.
- **`intruder.py` output** — narrates the attack: *stolen PIN*, *stolen Wi-Fi*, *DOOR OPENED*.
- **`report.html`** — the professional deliverable: severity badges, CVSS v3.1 vectors, leaked values as evidence, remediation.

## Talking points / likely questions

- **"Is this a real lock?"** It emulates one; the *flaw* (secrets readable, controls writable with no pairing) is real and has shipped in real smart locks, trackers, and medical devices.
- **"Could you open *any* lock?"** No — only a device that exposes data/controls **without authentication**. A properly built lock requires pairing + encryption and would refuse all of this. That's the point.
- **"How do you fix it?"** Require pairing/bonding with encryption before access; never expose secrets in readable characteristics; gate control behind app-layer auth over the encrypted link.

## Reset between runs
The door auto-relocks after 10s. To force a clean reset, Ctrl+C the target and
re-run `python peripheral.py`.
