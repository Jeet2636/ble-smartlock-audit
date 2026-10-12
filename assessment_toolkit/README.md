# assessment_toolkit — the attacker / auditor

Runs on the **attacker** machine (any OS with Python + Bluetooth). Finds a BLE
target, enumerates it, classifies unauthenticated-access vulnerabilities, scores
them with **CVSS v3.1**, and produces a report. Includes two demo clients.

> Part of the BLE Security Assessment Framework. See the project
> [README](../README.md) and [DEMO guide](../DEMO.md).

## Setup

```
pip install -r requirements.txt    # bleak
```

## Commands

```
# 1) Passive reconnaissance — list every nearby BLE device (no connection made)
python -m ble_audit.cli scan
python -m ble_audit.cli scan --filter SmartLock      # optional name filter

# 2) Full audit — connect, enumerate, classify, score, report
python -m ble_audit.cli enum <ADDRESS> --out result.json
#    writes result.json AND report.html (open in a browser)
#    --no-html to skip the report, --html PATH to choose its location

# 3) Demo clients
python intruder.py            # ATTACK: steal the PIN off the lock, open it, grab Wi-Fi
python authorized_remote.py   # BASELINE: open the lock with a PIN known in advance
```

`<ADDRESS>` comes from the `scan` output (the row whose SERVICES column shows
`a07498ca-…`). On macOS this is a CoreBluetooth UUID, not a MAC — paste it as-is.
`intruder.py` and `authorized_remote.py` find the lock automatically by service
UUID, so they need no address.

## What a finding looks like

```
[High] CVSS 7.4  Sensitive data exposed over unauthenticated read: Unlock PIN
       CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N
       properties=['read']; leaked value (plaintext): 'unlock_pin=4873'; ...
```

## Module overview (`ble_audit/`)

| File | Role |
|------|------|
| `scanner.py` | passive BLE discovery / fingerprinting |
| `enumerate.py` | GATT walk, reads values, classifies findings, decodes leaked data |
| `cvss.py` | CVSS v3.1 base-score calculator |
| `report.py` | self-contained HTML report generator |
| `models.py` | data structures (devices, services, characteristics, findings) |
| `cli.py` | command-line entry point (`scan`, `enum`) |

## Note on the sample files

Any `report.html` / `result.json` already in this folder are **sample previews**;
your first real `enum` run overwrites them with live data.
