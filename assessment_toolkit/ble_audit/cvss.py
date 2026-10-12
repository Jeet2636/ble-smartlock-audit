"""
Minimal, correct CVSS v3.1 base-score calculator.

Only the base metric group is implemented (that's what we report per finding).
Formulas follow the official CVSS v3.1 specification, section 7.1.
"""
import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope Changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}


def _roundup(x: float) -> float:
    """Official CVSS v3.1 roundup: smallest 1-decimal number >= x."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(av, ac, pr, ui, scope, c, i, a) -> tuple[str, float]:
    """
    Compute (vector_string, base_score) for the given base metrics.

    Each argument is the single-letter CVSS value, e.g. av="A", c="H".
    """
    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    pr_val = _PR_C[pr] if scope == "C" else _PR_U[pr]
    exploitability = 8.22 * _AV[av] * _AC[ac] * pr_val * _UI[ui]

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10))

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
    return vector, score


def for_finding(readable: bool, writable: bool, sensitive: bool) -> tuple[str, float]:
    """
    Map a BLE characteristic finding to CVSS base metrics.

    Fixed context for this assessment: the attacker is in Bluetooth radio range
    (AV:Adjacent), the operation is trivial (AC:Low) and needs no privileges or
    user interaction (PR:None, UI:None).
      - reading sensitive data  -> Confidentiality High
      - reading benign data     -> Confidentiality Low
      - writable control surface-> Integrity High (attacker alters device state)
      - leaking a credential or controlling the device reaches beyond the BLE
        component itself (e.g. the physical door / the Wi-Fi network) -> Scope Changed
    """
    av, ac, pr, ui = "A", "L", "N", "N"
    c = "H" if (readable and sensitive) else ("L" if readable else "N")
    i = "H" if writable else "N"
    a = "N"
    scope = "C" if (sensitive or writable) else "U"
    return base_score(av, ac, pr, ui, scope, c, i, a)
