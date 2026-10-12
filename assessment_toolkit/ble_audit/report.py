"""
Human-readable report generator.

Turns an AssessmentResult into a self-contained HTML page (no external assets,
no network) that reads like a real pentest write-up: a severity summary, the
findings with the exact data that leaked, and the full GATT inventory.
"""
import html

from .models import AssessmentResult, Severity

_SEV_COLOR = {
    Severity.CRITICAL.value: "#7b1fa2",
    Severity.HIGH.value: "#d32f2f",
    Severity.MEDIUM.value: "#f57c00",
    Severity.LOW.value: "#fbc02d",
    Severity.INFO.value: "#1976d2",
}
_SEV_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _badge(severity: str) -> str:
    color = _SEV_COLOR.get(severity, "#555")
    return (
        f'<span class="badge" style="background:{color}">{_esc(severity)}</span>'
    )


def render_html(result: AssessmentResult) -> str:
    """Render the assessment as a complete HTML document (string)."""
    findings = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity.value, 9))

    # Severity tally for the summary strip.
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    summary_chips = "".join(
        f'<div class="chip"><span class="dot" style="background:{_SEV_COLOR.get(sev, "#555")}"></span>'
        f"{count} {_esc(sev)}</div>"
        for sev, count in sorted(counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))
    ) or '<div class="chip">No findings</div>'

    # Findings cards.
    finding_rows = []
    for f in findings:
        cvss_head = f'<span class="cvss">CVSS {f.cvss_score}</span>' if f.cvss_score is not None else ""
        cvss_row = (
            f'<dt>CVSS v3.1</dt><dd>{f.cvss_score} &nbsp;<code>{_esc(f.cvss_vector)}</code></dd>'
            if f.cvss_vector else ""
        )
        finding_rows.append(
            f"""
      <div class="finding">
        <div class="finding-head">{_badge(f.severity.value)}{cvss_head}<h3>{_esc(f.title)}</h3></div>
        <p class="desc">{_esc(f.description)}</p>
        <dl>
          {cvss_row}
          <dt>Characteristic</dt><dd><code>{_esc(f.characteristic_uuid)}</code></dd>
          <dt>Service</dt><dd><code>{_esc(f.service_uuid)}</code></dd>
          <dt>Evidence</dt><dd class="evidence">{_esc(f.evidence)}</dd>
          <dt>Remediation</dt><dd>{_esc(f.remediation)}</dd>
        </dl>
      </div>"""
        )
    findings_html = "\n".join(finding_rows) or "<p>No findings.</p>"

    # Full GATT inventory.
    inv_rows = []
    for svc in result.services:
        svc_label = f"{_esc(svc.uuid)}" + (f" &mdash; <b>{_esc(svc.name)}</b>" if svc.name else "")
        inv_rows.append(f'<tr class="svc"><td colspan="4">Service {svc_label}</td></tr>')
        for c in svc.characteristics:
            value = c.value_text if c.value_text is not None else (
                f"0x{c.value_preview}" if c.value_preview else "<not read>")
            inv_rows.append(
                f"<tr><td><code>{_esc(c.uuid)}</code></td>"
                f"<td>{_esc(c.name)}</td>"
                f"<td>{_esc(', '.join(c.properties))}</td>"
                f"<td class='val'>{_esc(value)}</td></tr>"
            )
    inventory_html = "\n".join(inv_rows) or "<tr><td colspan='4'>No services.</td></tr>"

    target = _esc(result.target_name or "unknown")
    addr = _esc(result.target_address)
    ts = _esc(result.timestamp)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BLE Security Assessment &mdash; {target}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #0f1115; color: #e6e8eb; line-height: 1.5; }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 32px 20px 64px; }}
  header h1 {{ margin: 0 0 4px; font-size: 1.6rem; }}
  header .meta {{ color: #9aa0a6; font-size: 0.9rem; }}
  header .meta code {{ color: #cdd3d9; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0 8px; }}
  .chip {{ background: #1b1f27; border: 1px solid #2a2f3a; border-radius: 999px;
          padding: 6px 14px; font-size: 0.9rem; display: flex; align-items: center; gap: 8px; }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
  h2 {{ margin: 32px 0 12px; font-size: 1.2rem; border-bottom: 1px solid #2a2f3a; padding-bottom: 6px; }}
  .finding {{ background: #151922; border: 1px solid #262c38; border-radius: 10px;
             padding: 16px 18px; margin-bottom: 14px; }}
  .finding-head {{ display: flex; align-items: center; gap: 10px; }}
  .finding-head h3 {{ margin: 0; font-size: 1.05rem; }}
  .badge {{ color: #fff; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em;
           text-transform: uppercase; padding: 3px 9px; border-radius: 6px; white-space: nowrap; }}
  .cvss {{ background: #262c38; color: #cdd3d9; font-size: 0.72rem; font-weight: 700;
          padding: 3px 9px; border-radius: 6px; white-space: nowrap; }}
  .desc {{ color: #c6ccd3; margin: 10px 0 12px; }}
  dl {{ display: grid; grid-template-columns: 130px 1fr; gap: 4px 14px; margin: 0; font-size: 0.92rem; }}
  dt {{ color: #8b93a0; }}
  dd {{ margin: 0; }}
  dd.evidence {{ color: #ffd7cc; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.86em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #222733; vertical-align: top; }}
  th {{ color: #8b93a0; font-weight: 600; }}
  tr.svc td {{ background: #1b1f27; font-weight: 600; color: #cdd3d9; }}
  td.val {{ color: #ffe0a3; font-family: ui-monospace, Consolas, monospace; word-break: break-all; }}
  footer {{ margin-top: 40px; color: #6b7280; font-size: 0.8rem; }}
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>BLE Security Assessment Report</h1>
      <div class="meta">
        Target: <b>{target}</b> &nbsp;|&nbsp; Address: <code>{addr}</code><br>
        Generated: {ts}
      </div>
    </header>

    <div class="summary">{summary_chips}</div>

    <h2>Findings</h2>
    {findings_html}

    <h2>GATT Inventory</h2>
    <table>
      <thead><tr><th>Characteristic UUID</th><th>Name</th><th>Properties</th><th>Value read</th></tr></thead>
      <tbody>
      {inventory_html}
      </tbody>
    </table>

    <footer>
      Generated by the BLE Security Assessment Framework. All testing performed against a
      controlled, intentionally-vulnerable target owned by the authors.
    </footer>
  </div>
</body>
</html>"""
