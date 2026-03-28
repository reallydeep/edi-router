"""
ui_textual.py — EDI Exception Auto-Router TUI dashboard.

3 tabs:
  1. Live Queue  — real-time exception table with severity badges and filters
  2. Parser      — paste raw X12 EDI, parse and inspect segments inline
  3. Rules       — view routing rules and last batch send times

Drains the event_queue from EDIWatcher every 2 seconds.
Refreshes the exception table from the DB every 30 seconds.
All widget mutations happen on the main thread via set_interval callbacks.
"""

from __future__ import annotations

import queue
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

from demo import run_demo as _run_demo_process

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
    TextArea,
)

from config import AppConfig, save_config
from db import get_exceptions_for_dashboard, get_last_batch_sent, get_routing_log
from parser import parse_raw, get_element
from templates import load_templates, save_templates, render as render_template


# ---------------------------------------------------------------------------
# Severity styling
# ---------------------------------------------------------------------------

SEVERITY_BADGE = {
    "CRITICAL": "[bold red]CRITICAL[/]",
    "HIGH":     "[bold yellow]HIGH    [/]",
    "MEDIUM":   "[bold cyan]MEDIUM  [/]",
    "LOW":      "[dim]LOW     [/]",
}

STATUS_BADGE = {
    "pending":    "[yellow]pending[/]",
    "sent":       "[green]sent[/]",
    "batched":    "[cyan]batched[/]",
    "suppressed": "[dim]suppressed[/]",
}

ROUTE_STATUS_OPTIONS = [
    ("All statuses", ""),
    ("Pending",      "pending"),
    ("Sent",         "sent"),
    ("Batched",      "batched"),
]

SEVERITY_OPTIONS = [
    ("All severities", ""),
    ("Critical",       "CRITICAL"),
    ("High",           "HIGH"),
    ("Medium",         "MEDIUM"),
    ("Low",            "LOW"),
]

TX_TYPE_OPTIONS = [
    ("All TX types", ""),
    ("850 – PO",     "850"),
    ("856 – ASN",    "856"),
    ("810 – Invoice","810"),
    ("997 – Ack",    "997"),
    ("855 – PO Ack", "855"),
    ("860 – PO Chg", "860"),
]


# ---------------------------------------------------------------------------
# Live Queue Tab
# ---------------------------------------------------------------------------

class LiveQueueTab(Container):
    def compose(self) -> ComposeResult:
        yield Horizontal(
            Label("Severity:", id="lbl-sev"),
            Select(SEVERITY_OPTIONS, id="filter-severity", allow_blank=False),
            Label("TX Type:", id="lbl-tx"),
            Select(TX_TYPE_OPTIONS, id="filter-tx", allow_blank=False),
            Button("Refresh", id="btn-refresh", variant="primary"),
            Button("▶ Run Demo", id="btn-demo"),
            id="queue-filters",
        )
        yield DataTable(id="exception-table", cursor_type="row")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("ID", "Code", "Severity", "TX", "Status", "File", "Detected", "Description")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-refresh":
            self.app.refresh_table()
        elif event.button.id == "btn-demo":
            self.app.action_run_demo()

    @property
    def severity_filter(self) -> str:
        sel = self.query_one("#filter-severity", Select)
        v = sel.value
        return "" if v is Select.BLANK else (v or "")

    @property
    def tx_filter(self) -> str:
        sel = self.query_one("#filter-tx", Select)
        v = sel.value
        return "" if v is Select.BLANK else (v or "")


# ---------------------------------------------------------------------------
# Parser Tab
# ---------------------------------------------------------------------------

class ParserTab(Container):
    def compose(self) -> ComposeResult:
        yield Label("Paste raw X12 EDI below, then click Parse:", id="parser-label")
        yield TextArea(id="raw-edi-input")
        yield Horizontal(
            Button("Parse", id="btn-parse", variant="primary"),
            Button("Clear", id="btn-clear"),
            id="parser-buttons",
        )
        yield RichLog(id="parse-output", highlight=True, markup=True, wrap=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-parse":
            self._run_parse()
        elif event.button.id == "btn-clear":
            self.query_one("#raw-edi-input", TextArea).clear()
            self.query_one("#parse-output", RichLog).clear()

    def _run_parse(self) -> None:
        log = self.query_one("#parse-output", RichLog)
        log.clear()

        text = self.query_one("#raw-edi-input", TextArea).text.strip()
        if not text:
            log.write("[yellow]No input — paste raw X12 EDI above.[/]")
            return

        result = parse_raw(text, "<manual input>")

        if result.parse_errors:
            log.write(f"[bold red]Parse errors ({len(result.parse_errors)}):[/]")
            for err in result.parse_errors:
                log.write(f"  [red]✗[/] {err}")
            log.write("")

        log.write(f"[bold]Transactions found: {len(result.transactions)}[/]")
        for i, tx in enumerate(result.transactions, 1):
            log.write(f"\n[bold cyan]──── Transaction {i}: {tx.tx_type} ────[/]")
            log.write(f"  ISA Control:  [green]{tx.isa_control}[/]")
            log.write(f"  ST Control:   [green]{tx.control_number}[/]")
            log.write(f"  Sender:       {tx.sender_id}")
            log.write(f"  Receiver:     {tx.receiver_id}")
            log.write(f"  Date/Time:    {tx.date} {tx.time}")
            log.write(f"  Segments:     {len(tx.segments)}")
            log.write("")
            log.write("  [dim]Seg ID   Elements (first 6)[/]")
            log.write("  [dim]" + "─" * 60 + "[/]")
            for seg in tx.segments:
                elems = " | ".join(seg.elements[:6])
                # Highlight exception-relevant segments
                color = ""
                if seg.segment_id in ("AK5", "AK3", "AK4") and any(
                    get_element(seg, 0) not in ("A", "") for _ in [None]
                ):
                    color = "red"
                elif seg.segment_id in ("ISA", "GS", "ST", "SE", "GE", "IEA"):
                    color = "dim"
                elif seg.segment_id in ("BEG", "BSN", "BIG", "BAK", "BCH", "TDS"):
                    color = "bold"

                if color:
                    log.write(f"  [{color}]{seg.segment_id:<8}[/] {elems}")
                else:
                    log.write(f"  {seg.segment_id:<8} {elems}")

        # Also run classifier and show any exceptions found
        from classifier import classify
        excs = classify(result)
        if excs:
            log.write(f"\n[bold yellow]Exceptions detected ({len(excs)}):[/]")
            for exc in excs:
                badge = SEVERITY_BADGE.get(exc.severity, exc.severity)
                log.write(f"  {badge}  [bold]{exc.error_code}[/]  {exc.description}")
        else:
            log.write("\n[bold green]No exceptions detected.[/]")


# ---------------------------------------------------------------------------
# Rules Tab
# ---------------------------------------------------------------------------

ROUTING_RULES = [
    ("1", "E-ENV-* (any)",  "CRITICAL", "ops_manager",         "Immediate"),
    ("2", "Any",            "CRITICAL", "ops_manager",         "Immediate"),
    ("3", "997",            "HIGH",     "edi_team + team_lead", "Immediate"),
    ("4", "Any (non-997)",  "HIGH",     "wms_team",            "Immediate"),
    ("5", "Any",            "MEDIUM",   "edi_team",            "Hourly batch"),
    ("6", "Any",            "LOW",      "edi_team",            "Daily digest"),
]


class RulesTab(Container):
    def __init__(self, config: AppConfig, conn: sqlite3.Connection):
        super().__init__()
        self._config = config
        self._conn = conn

    def compose(self) -> ComposeResult:
        yield Label("[bold]Routing Rules[/] (first match wins)", id="rules-title", markup=True)
        yield DataTable(id="rules-table", cursor_type="none")
        yield Label("\n[bold]Batch Queue Status[/]", id="batch-title", markup=True)
        yield Static(id="batch-status")

    def on_mount(self) -> None:
        table = self.query_one("#rules-table", DataTable)
        table.add_columns("Pri", "TX Type", "Severity", "Recipients", "Delivery")
        for row in ROUTING_RULES:
            table.add_row(*row)
        self._refresh_batch_status()

    def _refresh_batch_status(self) -> None:
        static = self.query_one("#batch-status", Static)
        r = self._config.routing

        hourly_last = get_last_batch_sent(self._conn, "hourly")
        daily_last = get_last_batch_sent(self._conn, "daily")

        hourly_str = hourly_last.strftime("%Y-%m-%d %H:%M UTC") if hourly_last else "never"
        daily_str = daily_last.strftime("%Y-%m-%d %H:%M UTC") if daily_last else "never"

        text = (
            f"  Hourly batch → {r.edi_team or '(not configured)'}  |  last sent: {hourly_str}\n"
            f"  Daily digest → {r.edi_team or '(not configured)'}  |  last sent: {daily_str}\n\n"
            f"  ops_manager  → {r.ops_manager or '(not configured)'}\n"
            f"  wms_team     → {r.wms_team or '(not configured)'}\n"
            f"  team_lead    → {r.team_lead or '(not configured)'}"
        )
        static.update(text)


# ---------------------------------------------------------------------------
# Email Log Tab
# ---------------------------------------------------------------------------

class EmailLogTab(Container):
    def __init__(self, conn: sqlite3.Connection):
        super().__init__()
        self._conn = conn

    def compose(self) -> ComposeResult:
        yield Horizontal(
            Label("[bold]Email Send Log[/]", id="log-title", markup=True),
            Button("Refresh", id="btn-log-refresh", variant="primary"),
            id="log-header",
        )
        yield DataTable(id="log-table", cursor_type="row")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Time", "Error Code", "Severity", "TX", "Recipient", "Rule", "Status")
        self._load_log()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-log-refresh":
            self._load_log()

    def _load_log(self) -> None:
        table = self.query_one("#log-table", DataTable)
        table.clear()
        rows = get_routing_log(self._conn, limit=100)
        for row in rows:
            sent_at = (row.get("sent_at") or "")[:16]
            error_code = row.get("error_code") or "—"
            sev = row.get("severity") or "—"
            sev_badge = SEVERITY_BADGE.get(sev, sev) if sev != "—" else "[dim]—[/]"
            tx = row.get("tx_type") or "—"
            recipient = row.get("recipient") or "—"
            rule = row.get("route_rule") or "—"
            success = row.get("success")
            if success == 1:
                status = "[green]✓ sent[/]"
            elif success == 0:
                err = row.get("error_message") or "failed"
                status = f"[red]✗ {err[:30]}[/]"
            else:
                status = "[dim]—[/]"
            table.add_row(sent_at, error_code, sev_badge, tx, recipient, rule, status)


# ---------------------------------------------------------------------------
# Templates Tab
# ---------------------------------------------------------------------------

KNOWN_ERROR_CODES = [
    "E-ENV-001", "E-ENV-002", "E-ENV-003", "E-ENV-004", "E-ENV-005",
    "E-997-REJ", "E-810-AMT", "E-856-STR", "E-850-STR", "E-855-STR", "E-860-STR",
    "E-UNK-TX", "E-DUP-ISA", "E-STALE",
]

DEFAULT_SUBJECT = {
    "CRITICAL": "[CRITICAL] EDI Alert — {error_code} | TX {tx_type}",
    "HIGH":     "[HIGH] EDI Alert — {error_code} | TX {tx_type}",
}
DEFAULT_SUBJECT_FALLBACK = "[EDI Alert] — {error_code} | TX {tx_type}"

DEFAULT_BODY = (
    "EDI EXCEPTION ALERT\n"
    "==================================================\n\n"
    "Severity:    {severity}\n"
    "Error Code:  {error_code}\n"
    "TX Type:     {tx_type}\n"
    "File:        {filename}\n\n"
    "Description:\n"
    "{description}\n\n"
    "==================================================\n"
    "Sent by EDI Exception Auto-Router"
)


class TemplatesTab(VerticalScroll):
    def __init__(self, templates: dict):
        super().__init__()
        self._templates = templates  # shared mutable dict

    def compose(self) -> ComposeResult:
        # ── Saved templates table ────────────────────────────────────────
        yield Label("[bold]Saved Custom Templates[/]", classes="section-title", markup=True)
        yield Label(
            "Click a row to load it into the editor below.",
            classes="routing-hint",
        )
        yield DataTable(id="tmpl-saved-table", cursor_type="row")

        # ── Editor ───────────────────────────────────────────────────────
        yield Label("[bold]Edit Template[/]", classes="section-title", markup=True)
        yield Label(
            "Placeholders:  {error_code}  {severity}  {tx_type}  {description}  {filename}",
            id="tmpl-placeholders",
        )
        yield _field_row("Error Code:", Input(
            placeholder="e.g. E-997-REJ", id="tmpl-code",
        ))
        yield _field_row("Subject:", Input(
            placeholder="Leave blank to use default subject", id="tmpl-subject",
        ))
        yield Label("Body:", classes="field-label", id="tmpl-body-label")
        yield TextArea(id="tmpl-body")
        yield Label(
            "Leave body blank to use the default body.",
            classes="routing-hint",
        )
        yield Horizontal(
            Button("Save Template", id="btn-tmpl-save", variant="primary"),
            Button("Delete Template", id="btn-tmpl-delete"),
            Button("Reset Fields", id="btn-tmpl-reset"),
            Static("", id="tmpl-result", classes="test-result"),
            classes="field-row save-row",
        )

    def on_mount(self) -> None:
        table = self.query_one("#tmpl-saved-table", DataTable)
        table.add_columns("Error Code", "Custom Subject")
        self._refresh_saved_table()

    def _refresh_saved_table(self) -> None:
        table = self.query_one("#tmpl-saved-table", DataTable)
        table.clear()
        if not self._templates:
            table.add_row("(none saved)", "")
        else:
            for code, tmpl in sorted(self._templates.items()):
                subj_preview = (tmpl.get("subject") or "")[:60] or "[dim](no subject)[/]"
                table.add_row(code, subj_preview, key=code)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "tmpl-saved-table":
            return
        row_key = event.row_key.value if event.row_key else None
        if not row_key or row_key == "(none saved)":
            return
        self._load_code(row_key)

    def _load_code(self, code: str) -> None:
        self.query_one("#tmpl-code", Input).value = code
        tmpl = self._templates.get(code, {})
        self.query_one("#tmpl-subject", Input).value = tmpl.get("subject", "")
        self.query_one("#tmpl-body", TextArea).load_text(tmpl.get("body", ""))
        self.query_one("#tmpl-result", Static).update("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-tmpl-save":
            self._save()
        elif event.button.id == "btn-tmpl-delete":
            self._delete()
        elif event.button.id == "btn-tmpl-reset":
            self._reset_fields()

    def _save(self) -> None:
        result = self.query_one("#tmpl-result", Static)
        code = self.query_one("#tmpl-code", Input).value.strip().upper()
        if not code:
            result.update("[red]✗ Enter an error code first[/]")
            return

        subject = self.query_one("#tmpl-subject", Input).value.strip()
        body = self.query_one("#tmpl-body", TextArea).text.strip()

        self._templates[code] = {"subject": subject, "body": body}
        try:
            save_templates(self._templates)
            result.update("[green]✓ Saved[/]")
            self._refresh_saved_table()
        except Exception as e:
            result.update(f"[red]✗ {e}[/]")

    def _delete(self) -> None:
        result = self.query_one("#tmpl-result", Static)
        code = self.query_one("#tmpl-code", Input).value.strip().upper()
        if not code:
            result.update("[red]✗ Enter an error code first[/]")
            return
        if code not in self._templates:
            result.update("[yellow]No custom template for that code[/]")
            return
        del self._templates[code]
        try:
            save_templates(self._templates)
            result.update(f"[green]✓ Deleted template for {code}[/]")
            self._reset_fields()
            self._refresh_saved_table()
        except Exception as e:
            result.update(f"[red]✗ {e}[/]")

    def _reset_fields(self) -> None:
        self.query_one("#tmpl-code", Input).value = ""
        self.query_one("#tmpl-subject", Input).value = ""
        self.query_one("#tmpl-body", TextArea).load_text("")
        self.query_one("#tmpl-result", Static).update("")


# ---------------------------------------------------------------------------
# Settings Tab
# ---------------------------------------------------------------------------

PROTOCOL_OPTIONS = [("SFTP — SSH (port 22)", "sftp"), ("FTP — plain (port 21)", "ftp")]


def _field_row(label: str, widget) -> Horizontal:
    """Helper: one label + one input widget in a horizontal row."""
    return Horizontal(
        Label(label, classes="field-label"),
        widget,
        classes="field-row",
    )


class SettingsTab(VerticalScroll):
    def __init__(self, config: AppConfig):
        super().__init__()
        self._config = config

    def compose(self) -> ComposeResult:
        c = self._config.connection
        s = self._config.smtp
        r = self._config.routing

        # ── Connection ───────────────────────────────────────────────────
        yield Label("Connection", classes="section-title")
        yield _field_row("Protocol:", Select(
            PROTOCOL_OPTIONS, value=c.protocol, id="conn-protocol", allow_blank=False,
        ))
        yield _field_row("Host:", Input(
            value=c.host, placeholder="sftp.sml.example.com", id="conn-host",
        ))
        yield _field_row("Port:", Input(
            value=str(c.port), placeholder="22", id="conn-port",
        ))
        yield _field_row("Username:", Input(
            value=c.username, placeholder="edi_user", id="conn-username",
        ))
        yield _field_row("Password:", Input(
            value=c.password, placeholder="••••••••", password=True, id="conn-password",
        ))
        yield _field_row("Remote Path:", Input(
            value=c.remote_path, placeholder="/edi/inbound", id="conn-remote-path",
        ))
        yield _field_row("Poll Interval (s):", Input(
            value=str(c.poll_interval_seconds), placeholder="300", id="conn-poll",
        ))
        yield Horizontal(
            Label("Verify Host Key:", classes="field-label"),
            Switch(value=c.verify_host_key, id="conn-verify-key"),
            Label(" (enable in production with known_hosts)", classes="field-hint"),
            classes="field-row",
        )
        yield Horizontal(
            Button("Test Connection", id="btn-test-conn"),
            Static("", id="conn-test-result", classes="test-result"),
            classes="field-row",
        )

        # ── SMTP ─────────────────────────────────────────────────────────
        yield Label("SMTP / Email", classes="section-title")
        yield _field_row("Host:", Input(
            value=s.host, placeholder="smtp.bergen.com", id="smtp-host",
        ))
        yield _field_row("Port:", Input(
            value=str(s.port), placeholder="587", id="smtp-port",
        ))
        yield _field_row("Username:", Input(
            value=s.username, placeholder="alerts@bergen.com", id="smtp-username",
        ))
        yield _field_row("Password:", Input(
            value=s.password, placeholder="App Password / SMTP password",
            password=True, id="smtp-password",
        ))
        yield _field_row("From Address:", Input(
            value=s.from_address, placeholder="edi-router@bergen.com", id="smtp-from",
        ))
        yield Horizontal(
            Label("Use SSL (port 465):", classes="field-label"),
            Switch(value=s.use_ssl, id="smtp-ssl"),
            Label(" (off = STARTTLS port 587, on = SSL port 465)", classes="field-hint"),
            classes="field-row",
        )
        yield Horizontal(
            Button("Test SMTP", id="btn-test-smtp"),
            Static("", id="smtp-test-result", classes="test-result"),
            classes="field-row",
        )

        # ── Routing ───────────────────────────────────────────────────────
        yield Label("Routing Addresses", classes="section-title")
        yield Label(
            "CRITICAL + envelope errors → ops_manager (immediate)",
            classes="routing-hint",
        )
        yield _field_row("Ops Manager:", Input(
            value=r.ops_manager, placeholder="ops-manager@bergen.com", id="route-ops",
        ))
        yield Label(
            "HIGH (997 rejections) → edi_team + team_lead (immediate)",
            classes="routing-hint",
        )
        yield _field_row("EDI Team:", Input(
            value=r.edi_team, placeholder="edi-team@bergen.com", id="route-edi",
        ))
        yield Label(
            "HIGH (non-997) → wms_team (immediate)",
            classes="routing-hint",
        )
        yield _field_row("WMS Team:", Input(
            value=r.wms_team, placeholder="wms-team@bergen.com", id="route-wms",
        ))
        yield Label(
            "HIGH (997) cc → team_lead (immediate)",
            classes="routing-hint",
        )
        yield _field_row("Team Lead:", Input(
            value=r.team_lead, placeholder="team-lead@bergen.com", id="route-lead",
        ))
        yield Label(
            "MEDIUM → edi_team hourly digest  |  LOW → edi_team daily digest",
            classes="routing-hint",
        )

        # ── Save ─────────────────────────────────────────────────────────
        yield Horizontal(
            Button("Save Settings", id="btn-save-settings", variant="primary"),
            Static("", id="save-result", classes="test-result"),
            classes="field-row save-row",
        )

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save-settings":
            self._save()
        elif event.button.id == "btn-test-conn":
            self._test_connection()
        elif event.button.id == "btn-test-smtp":
            self._test_smtp()

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _save(self) -> None:
        result_widget = self.query_one("#save-result", Static)

        try:
            # Collect and validate all fields
            protocol = self._select_value("conn-protocol", "sftp")
            conn_host = self._input_value("conn-host")
            conn_port = self._int_value("conn-port", 22)
            conn_user = self._input_value("conn-username")
            conn_pass = self._input_value("conn-password")
            conn_path = self._input_value("conn-remote-path") or "/edi/inbound"
            conn_poll = self._int_value("conn-poll", 300)
            conn_verify = self.query_one("#conn-verify-key", Switch).value

            smtp_host = self._input_value("smtp-host")
            smtp_port = self._int_value("smtp-port", 587)
            smtp_user = self._input_value("smtp-username")
            smtp_pass = self._input_value("smtp-password")
            smtp_from = self._input_value("smtp-from")
            smtp_ssl  = self.query_one("#smtp-ssl", Switch).value

            route_ops  = self._input_value("route-ops")
            route_edi  = self._input_value("route-edi")
            route_wms  = self._input_value("route-wms")
            route_lead = self._input_value("route-lead")

        except ValueError as e:
            result_widget.update(f"[red]✗ {e}[/]")
            return

        # Update config dataclass in-place so the running watcher picks up changes
        c = self._config.connection
        c.protocol              = protocol
        c.host                  = conn_host
        c.port                  = conn_port
        c.username              = conn_user
        c.password              = conn_pass
        c.remote_path           = conn_path
        c.poll_interval_seconds = conn_poll
        c.verify_host_key       = conn_verify

        s = self._config.smtp
        s.host         = smtp_host
        s.port         = smtp_port
        s.username     = smtp_user
        s.password     = smtp_pass
        s.from_address = smtp_from
        s.use_ssl      = smtp_ssl

        r = self._config.routing
        r.ops_manager = route_ops
        r.edi_team    = route_edi
        r.wms_team    = route_wms
        r.team_lead   = route_lead

        # Write to config.toml
        try:
            save_config(self._config)
            result_widget.update("[green]✓ Saved to config.toml[/]")
            self.app.notify(
                "Settings saved. Connection and email changes take effect on the next poll cycle.",
                title="Settings Saved",
                severity="information",
                timeout=5,
            )
        except Exception as e:
            result_widget.update(f"[red]✗ Write failed: {e}[/]")

    # ------------------------------------------------------------------
    # Test Connection
    # ------------------------------------------------------------------

    def _test_connection(self) -> None:
        result = self.query_one("#conn-test-result", Static)
        result.update("[yellow]Testing...[/]")
        self.query_one("#btn-test-conn", Button).disabled = True

        protocol = self._select_value("conn-protocol", "sftp")
        host     = self._input_value("conn-host")
        port     = self._int_value("conn-port", 22)
        username = self._input_value("conn-username")
        password = self._input_value("conn-password")
        path     = self._input_value("conn-remote-path") or "/edi/inbound"

        if not host:
            result.update("[red]✗ Host is empty[/]")
            self.query_one("#btn-test-conn", Button).disabled = False
            return

        def _run():
            try:
                if protocol == "sftp":
                    import paramiko
                    t = paramiko.Transport((host, port))
                    t.connect(username=username, password=password)
                    sftp = paramiko.SFTPClient.from_transport(t)
                    files = sftp.listdir(path)
                    sftp.close()
                    t.close()
                    msg = f"[green]✓ SFTP connected — {len(files)} item(s) in {path}[/]"
                else:
                    import ftplib
                    ftp = ftplib.FTP()
                    ftp.connect(host, port, timeout=15)
                    ftp.login(username, password)
                    ftp.cwd(path)
                    files = ftp.nlst()
                    ftp.quit()
                    msg = f"[green]✓ FTP connected — {len(files)} item(s) in {path}[/]"
            except Exception as e:
                msg = f"[red]✗ {e}[/]"
            self.app.call_from_thread(_update_conn_result, msg)

        def _update_conn_result(msg: str) -> None:
            result.update(msg)
            self.query_one("#btn-test-conn", Button).disabled = False

        threading.Thread(target=_run, daemon=True).start()

    # ------------------------------------------------------------------
    # Test SMTP
    # ------------------------------------------------------------------

    def _test_smtp(self) -> None:
        result = self.query_one("#smtp-test-result", Static)
        result.update("[yellow]Testing...[/]")
        self.query_one("#btn-test-smtp", Button).disabled = True

        host    = self._input_value("smtp-host")
        port    = self._int_value("smtp-port", 587)
        use_ssl = self.query_one("#smtp-ssl", Switch).value
        user    = self._input_value("smtp-username")
        passwd  = self._input_value("smtp-password")

        if not host:
            result.update("[red]✗ Host is empty[/]")
            self.query_one("#btn-test-smtp", Button).disabled = False
            return

        def _run():
            import smtplib
            try:
                if use_ssl:
                    with smtplib.SMTP_SSL(host, port, timeout=10) as srv:
                        if user:
                            srv.login(user, passwd)
                        msg = "[green]✓ SMTP SSL connection successful[/]"
                else:
                    with smtplib.SMTP(host, port, timeout=10) as srv:
                        srv.ehlo()
                        srv.starttls()
                        srv.ehlo()
                        if user:
                            srv.login(user, passwd)
                        msg = "[green]✓ SMTP STARTTLS connection successful[/]"
            except Exception as e:
                msg = f"[red]✗ {e}[/]"
            self.app.call_from_thread(_update_smtp_result, msg)

        def _update_smtp_result(msg: str) -> None:
            result.update(msg)
            self.query_one("#btn-test-smtp", Button).disabled = False

        threading.Thread(target=_run, daemon=True).start()

    # ------------------------------------------------------------------
    # Field helpers
    # ------------------------------------------------------------------

    def _input_value(self, widget_id: str) -> str:
        return self.query_one(f"#{widget_id}", Input).value.strip()

    def _int_value(self, widget_id: str, default: int) -> int:
        raw = self._input_value(widget_id)
        try:
            val = int(raw)
            if val <= 0:
                raise ValueError
            return val
        except ValueError:
            raise ValueError(f"{widget_id}: must be a positive integer (got {raw!r})")

    def _select_value(self, widget_id: str, default: str) -> str:
        sel = self.query_one(f"#{widget_id}", Select)
        v = sel.value
        return default if v is Select.BLANK else (v or default)


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

INLINE_CSS = """
Screen {
    background: #0d0d0d;
}

Header {
    background: #1a1a1a;
    color: #ff8c00;
    text-style: bold;
}

Footer {
    background: #1a1a1a;
    color: #555555;
}

TabbedContent {
    background: #0d0d0d;
}

TabPane {
    background: #0d0d0d;
    padding: 1 2;
}

DataTable {
    background: #111111;
    color: #cccccc;
    height: 1fr;
}

DataTable > .datatable--header {
    background: #1a1a1a;
    color: #ff8c00;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #2a2a2a;
}

#queue-filters {
    height: 3;
    margin-bottom: 1;
    align: left middle;
}

#queue-filters Label {
    color: #888888;
    margin-right: 1;
    width: auto;
}

#queue-filters Select {
    width: 20;
    margin-right: 2;
}

#queue-filters Button {
    width: auto;
}

#parser-label {
    color: #888888;
    margin-bottom: 1;
}

TextArea {
    height: 8;
    background: #111111;
    color: #cccccc;
    border: solid #333333;
    margin-bottom: 1;
}

#parser-buttons {
    height: 3;
    margin-bottom: 1;
}

#parse-output {
    background: #111111;
    border: solid #333333;
    height: 1fr;
    color: #cccccc;
}

#rules-title, #batch-title {
    color: #ff8c00;
    margin-bottom: 1;
}

#rules-table {
    height: auto;
    max-height: 12;
    margin-bottom: 1;
}

#batch-status {
    color: #888888;
    background: #111111;
    padding: 1 2;
    border: solid #2a2a2a;
}

Button.-primary {
    background: #ff8c00;
    color: #000000;
    border: none;
}

Button {
    background: #1a1a1a;
    color: #aaaaaa;
    border: solid #333333;
    margin-right: 1;
}

#btn-demo {
    background: #1a3a1a;
    color: #44ff44;
    border: solid #2a5a2a;
}

#btn-demo:hover {
    background: #2a5a2a;
}

#btn-demo:disabled {
    background: #111111;
    color: #444444;
    border: solid #222222;
}

/* ── Settings tab ─────────────────────────────────────────── */

SettingsTab {
    background: #0d0d0d;
    padding: 1 2;
}

.section-title {
    color: #ff8c00;
    text-style: bold;
    margin-top: 1;
    margin-bottom: 1;
    padding: 0 0 0 1;
    border-bottom: solid #2a2a2a;
    width: 1fr;
}

.field-row {
    height: auto;
    margin-bottom: 1;
    align: left middle;
}

.field-label {
    width: 22;
    color: #888888;
    padding: 0 1 0 1;
    text-align: right;
}

.field-hint {
    color: #555555;
    padding: 0 1;
    width: 1fr;
}

.routing-hint {
    color: #555555;
    padding: 0 0 0 23;
    margin-bottom: 0;
}

SettingsTab Input {
    width: 40;
    background: #111111;
    color: #cccccc;
    border: tall #2a2a2a;
}

SettingsTab Input:focus {
    border: tall #ff8c00;
}

SettingsTab Select {
    width: 40;
}

SettingsTab Switch {
    margin: 0 1;
}

.test-result {
    color: #888888;
    padding: 0 1;
    width: 1fr;
}

.save-row {
    margin-top: 2;
    border-top: solid #2a2a2a;
    padding-top: 1;
}

/* ── Email Log tab ────────────────────────────────────────── */

#log-header {
    height: 3;
    margin-bottom: 1;
    align: left middle;
}

#log-title {
    color: #ff8c00;
    margin-right: 2;
    width: auto;
}

#log-table {
    height: 1fr;
    background: #111111;
}

/* ── Templates tab ────────────────────────────────────────── */

#tmpl-saved-table {
    height: auto;
    max-height: 10;
    margin-bottom: 1;
    background: #111111;
}

#tmpl-placeholders {
    color: #555555;
    padding: 0 0 1 23;
}

#tmpl-body-label {
    width: 22;
    color: #888888;
    padding: 0 1 0 1;
    text-align: right;
}

TemplatesTab TextArea {
    height: 10;
    background: #111111;
    color: #cccccc;
    border: solid #333333;
    margin-bottom: 1;
    margin-left: 22;
    width: 1fr;
}

TemplatesTab TextArea:focus {
    border: solid #ff8c00;
}

TemplatesTab Input {
    width: 40;
    background: #111111;
    color: #cccccc;
    border: tall #2a2a2a;
}

TemplatesTab Input:focus {
    border: tall #ff8c00;
}
"""


class EDIRouterApp(App):
    TITLE = "EDI Exception Auto-Router"
    CSS = INLINE_CSS
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "manual_refresh", "Refresh"),
        Binding("1", "focus_tab('tab-queue')", "Queue"),
        Binding("2", "focus_tab('tab-parser')", "Parser"),
        Binding("3", "focus_tab('tab-rules')", "Rules"),
        Binding("4", "focus_tab('tab-settings')", "Settings"),
        Binding("5", "focus_tab('tab-emaillog')", "Email Log"),
        Binding("6", "focus_tab('tab-templates')", "Templates"),
    ]

    def __init__(
        self,
        config: AppConfig,
        conn: sqlite3.Connection,
        event_queue: queue.Queue,
        templates: Optional[dict] = None,
    ):
        super().__init__()
        self._config = config
        self._conn = conn
        self._event_queue = event_queue
        self._templates = templates if templates is not None else {}
        self._status_message = "Ready"
        self._demo_running = False

    def action_run_demo(self) -> None:
        """Launch the demo pipeline in a background thread."""
        if self._demo_running:
            self.notify("Demo is already running — wait for it to finish.", severity="warning")
            return
        self._demo_running = True
        try:
            btn = self.query_one("#btn-demo", Button)
            btn.label = "⏳ Running..."
            btn.disabled = True
        except Exception:
            pass
        threading.Thread(
            target=_run_demo_process,
            args=(self._conn, self._event_queue, self._config),
            daemon=True,
        ).start()

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Live Queue [1]", id="tab-queue"):
                yield LiveQueueTab()
            with TabPane("Parser [2]", id="tab-parser"):
                yield ParserTab()
            with TabPane("Rules [3]", id="tab-rules"):
                yield RulesTab(self._config, self._conn)
            with TabPane("Settings [4]", id="tab-settings"):
                yield SettingsTab(self._config)
            with TabPane("Email Log [5]", id="tab-emaillog"):
                yield EmailLogTab(self._conn)
            with TabPane("Templates [6]", id="tab-templates"):
                yield TemplatesTab(self._templates)
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(2, self._drain_queue)
        self.set_interval(30, self.refresh_table)
        self.refresh_table()

    def refresh_table(self) -> None:
        """Reload exceptions from DB and update the DataTable."""
        try:
            queue_tab = self.query_one(LiveQueueTab)
            sev = queue_tab.severity_filter
            tx = queue_tab.tx_filter
        except Exception:
            sev, tx = "", ""

        rows = get_exceptions_for_dashboard(
            self._conn,
            severity_filter=sev or None,
            tx_type_filter=tx or None,
        )

        try:
            table = self.query_one("#exception-table", DataTable)
            table.clear()
            for row in rows:
                sev_badge = SEVERITY_BADGE.get(row["severity"], row["severity"])
                status_badge = STATUS_BADGE.get(row["route_status"], row["route_status"])
                detected = row["detected_at"][:16] if row["detected_at"] else ""
                desc = (row["description"] or "")[:60]
                table.add_row(
                    str(row["id"]),
                    row["error_code"],
                    sev_badge,
                    row["tx_type"] or "?",
                    status_badge,
                    row["filename"] or "?",
                    detected,
                    desc,
                    key=str(row["id"]),
                )
        except Exception:
            pass  # widget may not be mounted yet on first call

    def _refresh_email_log(self) -> None:
        try:
            self.query_one(EmailLogTab)._load_log()
        except Exception:
            pass

    def action_manual_refresh(self) -> None:
        self.refresh_table()
        self._refresh_email_log()

    def action_focus_tab(self, tab_id: str) -> None:
        try:
            self.query_one(TabbedContent).active = tab_id
        except Exception:
            pass

    def _drain_queue(self) -> None:
        """Process pending events from the watcher thread."""
        count = 0
        while count < 20:  # process at most 20 events per tick
            try:
                event = self._event_queue.get_nowait()
                self._handle_event(event)
                count += 1
            except queue.Empty:
                break

    def _handle_event(self, event: dict) -> None:
        etype = event.get("type", "")

        if etype == "exception_detected":
            # Refresh table on new exceptions
            self.refresh_table()
            self.sub_title = f"Exception: {event.get('error_code')} ({event.get('severity')})"

        elif etype == "poll_complete":
            files = event.get("files_processed", 0)
            excs = event.get("exceptions_found", 0)
            now = datetime.now(timezone.utc).strftime("%H:%M")
            if files > 0:
                self.sub_title = f"Poll {now}: {files} file(s), {excs} exception(s)"
            else:
                self.sub_title = f"Last poll: {now} — no new files"

        elif etype == "connection_error":
            self.sub_title = f"[ERROR] {event.get('message', '')[:60]}"

        elif etype == "email_sent":
            rule = event.get("rule", "")
            code = event.get("error_code", "")
            self.sub_title = f"Email sent: {code} via {rule}"
            self._refresh_email_log()

        elif etype == "demo_start":
            total = event.get("total", 0)
            self.sub_title = f"Demo running — processing {total} sample files..."
            self.notify(
                f"Processing {total} sample EDI files through the full pipeline.",
                title="Demo Mode Started",
                severity="information",
                timeout=4,
            )

        elif etype == "demo_file_clean":
            filename = event.get("filename", "")
            tx = event.get("tx_type", "")
            self.sub_title = f"Demo: {filename} ({tx}) — no exceptions ✓"

        elif etype == "demo_email_preview":
            sev       = event.get("severity", "")
            code      = event.get("error_code", "")
            tx        = event.get("tx_type", "")
            recipients = event.get("recipients", [])
            delivery  = event.get("delivery", "")
            subject   = event.get("subject", "")
            to_str    = ", ".join(recipients)

            # Map severity to Textual notification severity level
            notif_sev = {
                "CRITICAL": "error",
                "HIGH":     "warning",
                "MEDIUM":   "information",
                "LOW":      "information",
            }.get(sev, "information")

            self.notify(
                f"To: {to_str}\n{delivery}\nSubject: {subject}",
                title=f"[DEMO EMAIL] {code} | {sev}",
                severity=notif_sev,
                timeout=6,
            )
            self.sub_title = f"Demo: would email {code} → {to_str}"
            self.refresh_table()

        elif etype == "demo_complete":
            files = event.get("files", 0)
            excs  = event.get("exceptions", 0)
            self._demo_running = False
            try:
                btn = self.query_one("#btn-demo", Button)
                btn.label = "▶ Run Demo"
                btn.disabled = False
            except Exception:
                pass
            self.refresh_table()
            self.sub_title = f"Demo complete — {files} files, {excs} exceptions detected"
            self.notify(
                f"Processed {files} sample files and detected {excs} exceptions.\n"
                "All exceptions are now in the Live Queue. No real emails were sent.",
                title="Demo Complete",
                severity="information",
                timeout=8,
            )


# ---------------------------------------------------------------------------
# CLI launch (for testing without the full daemon)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from config import load_config
    from db import init_db

    cfg = load_config()
    conn = init_db()
    eq: queue.Queue = queue.Queue()
    app = EDIRouterApp(cfg, conn, eq)
    app.run()
    conn.close()
