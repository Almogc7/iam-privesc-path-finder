"""Renders findings as a CLI table (rich) and a static HTML report."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import List

from rich.console import Console
from rich.table import Table

from models import Finding

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
}


def render_cli_table(findings: List[Finding]) -> None:
    """Prints a colored summary table plus one detail block per finding."""
    console = Console()

    if not findings:
        console.print("[bold green]No privilege-escalation paths detected.[/bold green]")
        return

    table = Table(title="IAM Privilege-Escalation Findings", show_lines=True)
    table.add_column("Principal", style="cyan", no_wrap=True)
    table.add_column("Technique", style="magenta", overflow="fold")
    table.add_column("Severity")
    table.add_column("Permissions Involved", overflow="fold")

    for f in findings:
        severity_style = SEVERITY_STYLE.get(f.severity, "white")
        table.add_row(
            f.principal_name,
            f.technique,
            f"[{severity_style}]{f.severity}[/{severity_style}]",
            ", ".join(f.permissions_involved),
        )

    console.print(table)
    console.print()

    for f in findings:
        console.print(f"[bold]{f.principal_name}[/bold] - [magenta]{f.technique}[/magenta]")
        console.print(f"  {f.explanation}")
        if f.chain:
            console.print(f"  [dim]Chain: {' -> '.join(f.chain)}[/dim]")
        console.print()


def render_html_report(findings: List[Finding], output_path: str) -> None:
    """Writes a single self-contained HTML file summarizing all findings."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for f in findings:
        chain_html = (
            f'<div class="chain">Chain: {html.escape(" -> ".join(f.chain))}</div>'
            if f.chain
            else ""
        )
        rows.append(
            f"""
            <tr>
              <td>{html.escape(f.principal_name)}</td>
              <td>{html.escape(f.technique)}</td>
              <td><span class="badge {f.severity.lower()}">{f.severity}</span></td>
              <td>{html.escape(", ".join(f.permissions_involved))}</td>
            </tr>
            <tr class="detail-row">
              <td colspan="4">
                <div class="explanation">{html.escape(f.explanation)}</div>
                {chain_html}
              </td>
            </tr>
            """
        )

    rows_html = "\n".join(rows) if rows else (
        '<tr><td colspan="4" class="empty">No privilege-escalation paths detected.</td></tr>'
    )

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IAM Privilege-Escalation Findings</title>
<style>
  body {{
    font-family: -apple-system, Segoe UI, Roboto, sans-serif;
    background: #0f1115;
    color: #e6e6e6;
    margin: 0;
    padding: 32px;
  }}
  h1 {{ margin-bottom: 4px; }}
  .meta {{ color: #9aa0a6; margin-bottom: 24px; font-size: 14px; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: #171a21;
    border-radius: 8px;
    overflow: hidden;
  }}
  th, td {{
    text-align: left;
    padding: 10px 14px;
    border-bottom: 1px solid #262a33;
    vertical-align: top;
  }}
  th {{
    background: #1d212b;
    color: #9aa0a6;
    text-transform: uppercase;
    font-size: 12px;
    letter-spacing: 0.05em;
  }}
  tr.detail-row td {{
    background: #12141a;
    padding-top: 0;
  }}
  .explanation {{ color: #c9ccd1; font-size: 14px; line-height: 1.5; padding: 6px 0; }}
  .chain {{ color: #7fb3ff; font-size: 13px; margin-top: 4px; font-family: monospace; }}
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
  }}
  .badge.critical {{ background: #4a1418; color: #ff6b6b; }}
  .badge.high {{ background: #4a3a14; color: #ffc86b; }}
  .empty {{ text-align: center; color: #6fcf97; padding: 24px; }}
</style>
</head>
<body>
  <h1>IAM Privilege-Escalation Findings</h1>
  <div class="meta">Generated {html.escape(generated_at)} &middot; {len(findings)} finding(s) &middot; offline synthetic dataset</div>
  <table>
    <thead>
      <tr>
        <th>Principal</th>
        <th>Technique</th>
        <th>Severity</th>
        <th>Permissions Involved</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
