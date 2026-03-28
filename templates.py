"""
templates.py — Load and save custom email templates.

Templates are stored in templates.toml next to the executable/script.
Each section is keyed by error code (e.g. ["E-997-REJ"]).

Supported placeholders in subject and body:
  {error_code}  {severity}  {tx_type}  {description}  {filename}
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore


def templates_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "templates.toml"
    return Path(__file__).parent / "templates.toml"


def load_templates(path: Optional[Path] = None) -> dict:
    """Load templates.toml. Returns dict of error_code -> {subject, body}."""
    target = path or templates_path()
    if not target.exists():
        return {}
    with open(target, "rb") as f:
        return tomllib.load(f)


def save_templates(templates: dict, path: Optional[Path] = None) -> None:
    """Write templates dict back to templates.toml."""
    target = path or templates_path()

    def _esc(s: str) -> str:
        """Escape a value for use in a TOML basic string."""
        return (
            s.replace("\\", "\\\\")
             .replace('"', '\\"')
             .replace("\n", "\\n")
             .replace("\r", "")
        )

    lines = [
        "# EDI Router — Custom Email Templates",
        "# Placeholders: {error_code}  {severity}  {tx_type}  {description}  {filename}",
        "",
    ]
    for error_code, tmpl in sorted(templates.items()):
        ec = error_code.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'["{ec}"]')
        lines.append(f'subject = "{_esc(tmpl.get("subject", ""))}"')
        lines.append(f'body = "{_esc(tmpl.get("body", ""))}"')
        lines.append("")

    target.write_text("\n".join(lines), encoding="utf-8")


def render(
    template: dict,
    error_code: str,
    severity: str,
    tx_type: str,
    description: str,
    filename: str = "",
) -> tuple[str, str]:
    """
    Substitute placeholders in subject and body.
    Returns (subject, body).
    Unknown placeholders are left as-is rather than raising an error.
    """
    ctx = {
        "error_code": error_code,
        "severity": severity,
        "tx_type": tx_type or "?",
        "description": description or "",
        "filename": filename or "",
    }
    try:
        subject = template.get("subject", "").format_map(ctx)
    except (KeyError, ValueError):
        subject = template.get("subject", "")
    try:
        body = template.get("body", "").format_map(ctx)
    except (KeyError, ValueError):
        body = template.get("body", "")
    return subject, body
