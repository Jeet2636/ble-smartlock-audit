# BLE Security Assessment Framework — Smart Lock Case Study

**Course:** Ethical Hacking & Vulnerability Assessment (3CS204ME24) — Semester Assignment
**Program:** B.Tech CSE, Semester 5, Nirma University
**Team:** Jeet Patel (24BCE085) · Priyansh Pujara (24BCE114)

---

## 1. What this is

A hands-on demonstration of a real, common IoT security flaw: a Bluetooth Low
Energy (BLE) device that exposes its data and controls **without any pairing,
bonding, or encryption**. We build a deliberately-vulnerable smart door lock,
show that anyone in radio range can open it, and provide an automated tool that
audits the device and produces a formal report with **CVSS v3.1** scores.

Everything runs on ordinary laptops and a phone over their built-in Bluetooth —
no special hardware, and no attacks on anyone else's devices.

> For the live walk-through, see **[DEMO.md](DEMO.md)**.

## 2. Roles (not machines)

The project has three roles. Assign each to **whatever device is convenient** —
the only hard rule is that the **target and the attacker must be two separate
devices** (a single Bluetooth radio cannot scan or connect to itself).

| Role | What it is | Runs |
|------|-----------|------|
| 🔒 **Target** | the vulnerable smart lock | `smartlock_target/peripheral.py` |
| 🦹 **Attacker / Auditor** | recon + exploit + report toolkit | `assessment_toolkit/` (Python) |
| 🔑 **Remote / casual attacker** | a phone with a generic BLE app | **nRF Connect** (iOS/Android) |

```
              ┌──────────────────────────┐
              │   TARGET  (any computer)  │   smartlock_target/peripheral.py
              │   "SmartLock-AX300"       │   BLE GATT server, service A07498CA...
              └─────────────▲─────────────┘
                            │  BLE  (no auth, in radio range)
            ┌───────────────┴───────────────┐
            │                                │
   ┌────────┴─────────┐           ┌──────────┴──────────┐
   │  PHONE            │           │  ATTACKER (computer)│
   │  nRF Connect app  │           │  assessment_toolkit │
   │  manual, "anyone" │           │  scan + intruder +  │
   │                   │           │  full CVSS report   │
   └───────────────────┘           └─────────────────────┘
```

Portability: the **attacker toolkit** runs on any OS with Python + Bluetooth
(Windows/macOS/Linux). The **target** uses the host's built-in Bluetooth; it was
built and validated on **Windows** (the code applies Windows-only shims
automatically and is a no-op elsewhere).

## 3. Repository layout

```
.
├── README.md                  ← this file (overview + setup)
├── DEMO.md                    ← the presentation script + demo variations
├── smartlock_target/          ← the TARGET device
│   ├── peripheral.py
│   ├── README.md
│   └── requirements.txt         (bless + pysetupdi, Windows)
└── assessment_toolkit/        ← the ATTACKER/AUDITOR device
    ├── ble_audit/
    │   ├── scanner.py            passive discovery
    │   ├── enumerate.py          GATT walk + vuln classification
    │   ├── cvss.py               CVSS v3.1 base-score calculator
    │   ├── report.py             HTML report generator
    │   ├── models.py             data structures
    │   └── cli.py                command-line entry point
    ├── intruder.py              automated steal-the-PIN-and-open attack
    ├── authorized_remote.py     legitimate key fob (baseline / contrast)
    ├── README.md
    └── requirements.txt          (bleak)
```

## 4. One-time setup

**Target device:**
```
cd smartlock_target
pip install -r requirements.txt
```

**Attacker device:**
```
cd assessment_toolkit
pip install -r requirements.txt
```

**Phone:** install **nRF Connect for Mobile** from the App Store / Play Store.

> Bluetooth ON everywhere. Keep the target and attacker on separate devices.

## 5. Quick run

On the **target**:
```
cd smartlock_target
python peripheral.py          # door LOCKED, advertising; console is a live event log
```
On the **attacker**:
```
cd assessment_toolkit
python -m ble_audit.cli scan                       # find the lock (look for service a07498ca)
python intruder.py                                 # automated attack: steal PIN + open
python -m ble_audit.cli enum <ADDRESS> --out result.json   # full audit -> result.json + report.html
```
The full step-by-step presentation flow is in **[DEMO.md](DEMO.md)**.

## 6. Reading the results

Each exposed characteristic becomes a **Finding** with severity + CVSS v3.1:

| Finding | Severity | CVSS | Why |
|---------|----------|------|-----|
| Unlock PIN readable | High | 7.4 | master code leaks → lock can be opened |
| Wi-Fi credentials readable | High | 7.4 | home network compromise |
| Unlock command writable | High | 7.4 | anyone can send unlock commands |
| Device info readable | Medium | 4.3 | minor information disclosure |
| Door state readable | Medium | 4.3 | status disclosure |

CVSS context: `AV:A` (attacker in Bluetooth range), `AC:L` (trivial),
`PR:N`/`UI:N` (no auth, no interaction); credential leaks and device control use
`S:C` (scope changed) because impact reaches beyond the BLE app to the physical
door and the network.

## 7. Remediation (how a real product should be built)

- Require **pairing + bonding** with encryption (LE Security Mode 1, Level 2+) before any access.
- **Never** expose secrets (PINs, keys, Wi-Fi credentials) in a readable characteristic.
- Gate control behind an **application-layer challenge/response** over the encrypted link, not a static PIN.
- Transport/rotate credentials out-of-band; never store them in plaintext on the device.

## 8. Scope & ethics

All testing is performed against **our own**, intentionally-vulnerable target
(`SmartLock-AX300`) on hardware we own, in a controlled setting, for coursework.
The tool only reads/writes what a device exposes without authentication; it does
not break encryption or attack third parties. Real-world stack-level BLE attacks
(**BlueBorne**, **KNOB**, **BIAS**) are out of scope — this project demonstrates
the far more common *application-level misconfiguration*.

## 9. Known limitations

- A single Bluetooth radio **cannot** scan/connect to its own advertisement — target and attacker must be **separate devices**.
- On macOS, Bluetooth addresses are per-host **CoreBluetooth UUIDs**, not real MACs (Apple privacy). The tool targets by **service UUID**, so it still works.
- The lock advertises under the host's Bluetooth name, so identify it by its **service UUID** (`a07498ca-…`), not a custom name.
