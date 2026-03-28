# EDI Exception Auto-Router

```
  ███████╗██████╗ ██╗      ██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗
  ██╔════╝██╔══██╗██║      ██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗
  █████╗  ██║  ██║██║      ███████╗██║   ██║██║   ██║   ██║   █████╗  ██████╔╝
  ██╔══╝  ██║  ██║██║      ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗
  ███████╗██████╔╝██║      ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║
  ╚══════╝╚═════╝ ╚═╝      ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝

                 EDI EXCEPTION AUTO-ROUTER  ⚡
         X12 Parsing · Exception Detection · Email Routing
```

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)
![UI](https://img.shields.io/badge/UI-Textual%20TUI-orange?style=flat-square)
![Storage](https://img.shields.io/badge/Storage-SQLite%20%28local%29-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)
![Security](https://img.shields.io/badge/Data-On--Premises%20Only-red?style=flat-square)

---

A production-grade Python desktop application that monitors an SFTP/FTP server for incoming X12 EDI files, parses every transaction in real time, classifies exceptions by severity, and routes email alerts to the right team — automatically, without anyone having to manually open a file.

Built for warehouse operations teams that receive high volumes of EDI from trading partners and need instant visibility into rejections, invoice discrepancies, shipment errors, and envelope failures before they cascade into fulfillment problems.

**Runs entirely on-premises. No cloud. No SaaS. No data leaves your building.**

---

## Table of Contents

- [Screenshots](#screenshots)
- [Features](#features)
- [Security & Privacy](#security--privacy)
- [How It Works](#how-it-works)
- [Exception Reference](#exception-reference)
- [Routing Rules](#routing-rules)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Demo Mode](#demo-mode)
- [Windows Deployment](#windows-deployment)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Development](#development)

---

## Screenshots

### Live Queue — Real-Time Exception Monitor

```
┌─ EDI Exception Auto-Router ─────────────────── Poll 14:32 — 3 files, 2 exceptions ─┐
│                                                                                       │
│  Live Queue [1] │ Parser [2] │ Rules [3] │ Settings [4]                              │
│ ─────────────────────────────────────────────────────────────────────────────────── │
│  Severity: [All severities ▼]  TX Type: [All TX types ▼]  [Refresh]  [▶ Run Demo]  │
│                                                                                       │
│  ID │ Code        │ Severity         │ TX  │ Status   │ File                    │ Detected         │ Description                     │
│ ────┼─────────────┼──────────────────┼─────┼──────────┼─────────────────────────┼──────────────────┼─────────────────────────────── │
│   1 │ E-997-REJ   │ CRITICAL         │ 997 │ sent     │ AMZN_997_0328_001.edi    │ 2026-03-28 14:31 │ 997 Rejected: trading partner.. │
│   2 │ E-810-AMT   │ HIGH             │ 810 │ sent     │ AMZN_810_0328_001.edi    │ 2026-03-28 14:31 │ Invoice amount mismatch: TDS01= │
│   3 │ E-856-STR   │ HIGH             │ 856 │ sent     │ AMZN_856_0328_001.edi    │ 2026-03-28 14:30 │ 856 ASN missing required BSN se │
│   4 │ E-DUP-ISA   │ MEDIUM           │ 850 │ batched  │ AMZN_850_0328_002.edi    │ 2026-03-28 11:20 │ Duplicate ISA control number: 0 │
│   5 │ E-STALE     │ LOW              │ 856 │ batched  │ AMZN_856_0327_001.edi    │ 2026-03-28 09:15 │ Transaction 52h old (ISA date 2 │
│                                                                                       │
│ ^q Quit  r Refresh  1 Queue  2 Parser  3 Rules  4 Settings                           │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Severity badges are color-coded — **CRITICAL** in red, **HIGH** in amber, **MEDIUM** in cyan, **LOW** in dim. The table refreshes automatically every 30 seconds and immediately on any new exception detected by the background watcher.

---

### Parser Tab — Inspect Any X12 File

```
┌─ EDI Exception Auto-Router ──────────────────────────────────────────────────────────┐
│                                                                                        │
│  Live Queue [1] │ Parser [2] │ Rules [3] │ Settings [4]                               │
│ ──────────────────────────────────────────────────────────────────────────────────── │
│  Paste raw X12 EDI below, then click Parse:                                           │
│                                                                                        │
│  ┌───────────────────────────────────────────────────────────────────────────────┐   │
│  │ ISA*00*          *00*          *ZZ*GOOGLE01       *ZZ*AMZN000001     *260328*  │   │
│  │ 1000*^*00501*000000042*0*P*>~                                                  │   │
│  │ GS*FA*AMZN000001*GOOGLE01*20260328*1005*2*X*005010~                            │   │
│  │ ST*997*0001~                                                                   │   │
│  │ AK1*PO*1~  AK2*850*0001~  AK3*PO1*6**8~  AK5*R*5~  AK9*R*1*1*0~  SE*6*0001~ │   │
│  └───────────────────────────────────────────────────────────────────────────────┘   │
│  [Parse]  [Clear]                                                                     │
│                                                                                        │
│  Transactions found: 1                                                                 │
│  ──── Transaction 1: 997 ────                                                          │
│  ISA Control:  000000042                                                               │
│  ST Control:   0001        Sender: AMZN000001    Receiver: GOOGLE01                   │
│  Date/Time:    260328 1005     Segments: 8                                             │
│                                                                                        │
│  ISA      00 |           | 00 |           | ZZ | GOOGLE01        (envelope)           │
│  GS       FA | AMZN000.. | GOOGLE01 | 20260328                    (envelope)           │
│  ST       997 | 0001                                                                   │
│  AK1      PO | 1                                                                       │
│  AK5      R  | 5                          ← rejection flag                             │
│  AK9      R  | 1 | 1 | 0                                                              │
│  SE       8  | 0001                       (envelope)                                  │
│                                                                                        │
│  Exceptions detected (1):                                                              │
│  CRITICAL  E-997-REJ  997 Rejected: trading partner rejected TX group 'PO'. AK501=R  │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Paste any raw X12 directly from an email, FTP client, or EDI portal. The parser auto-detects the ISA element delimiter and segment terminator, renders every segment with its elements, highlights exception-relevant segments (AK5, AK3, TDS) in red/bold, and runs the full classifier inline — no polling cycle required.

---

### Routing Rules Tab — Rule Engine Overview

```
┌─ EDI Exception Auto-Router ──────────────────────────────────────────────────────────┐
│                                                                                        │
│  Live Queue [1] │ Parser [2] │ Rules [3] │ Settings [4]                               │
│ ──────────────────────────────────────────────────────────────────────────────────── │
│  Routing Rules  (first match wins)                                                     │
│                                                                                        │
│  Pri │ TX Type       │ Severity  │ Recipients              │ Delivery                 │
│ ─────┼───────────────┼───────────┼─────────────────────────┼────────────────────────  │
│   1  │ E-ENV-* (any) │ CRITICAL  │ ops_manager             │ Immediate                │
│   2  │ Any           │ CRITICAL  │ ops_manager             │ Immediate                │
│   3  │ 997           │ HIGH      │ edi_team + team_lead    │ Immediate                │
│   4  │ Any (non-997) │ HIGH      │ wms_team                │ Immediate                │
│   5  │ Any           │ MEDIUM    │ edi_team                │ Hourly batch             │
│   6  │ Any           │ LOW       │ edi_team                │ Daily digest             │
│                                                                                        │
│  Batch Queue Status                                                                    │
│  ┌────────────────────────────────────────────────────────────────────────────────┐  │
│  │  Hourly batch → edi-team@google.com   │  last sent: 2026-03-28 14:00 UTC      │  │
│  │  Daily digest → edi-team@google.com   │  last sent: 2026-03-28 08:00 UTC      │  │
│  │                                                                                 │  │
│  │  ops_manager  → ops-manager@google.com                                         │  │
│  │  wms_team     → wms-team@google.com                                            │  │
│  │  team_lead    → team-lead@google.com                                           │  │
│  └────────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

### Settings Tab — No Config File Editing Required

```
┌─ EDI Exception Auto-Router ──────────────────────────────────────────────────────────┐
│                                                                                        │
│  Live Queue [1] │ Parser [2] │ Rules [3] │ Settings [4]                               │
│ ──────────────────────────────────────────────────────────────────────────────────── │
│                                                                                        │
│  Connection ─────────────────────────────────────────────────────────────────────    │
│  Protocol:           [SFTP — SSH (port 22)               ▼]                           │
│  Host:               [sftp.sml.example.com                 ]                          │
│  Port:               [22      ]                                                        │
│  Username:           [edi_google                           ]                          │
│  Password:           [••••••••••••                         ]                          │
│  Remote Path:        [/edi/inbound                         ]                          │
│  Poll Interval (s):  [300     ]                                                        │
│  Verify Host Key:    ○  (enable in production with known_hosts)                       │
│                      [Test Connection]  ✓ SFTP connected — 7 item(s) in /edi/inbound │
│                                                                                        │
│  SMTP / Email ───────────────────────────────────────────────────────────────────    │
│  Host:               [smtp.office365.com                   ]                          │
│  Port:               [587     ]                                                        │
│  Username:           [edi-alerts@google.com                ]                          │
│  Password:           [••••••••••••••••••                   ]   ← App Password (M365) │
│  From Address:       [edi-router@google.com                ]                          │
│  Use SSL (465):      ○  (off = STARTTLS port 587)                                     │
│                      [Test SMTP]  ✓ SMTP STARTTLS connection successful               │
│                                                                                        │
│  Routing Addresses ──────────────────────────────────────────────────────────────    │
│  CRITICAL + envelope errors → ops_manager (immediate)                                 │
│  Ops Manager:        [ops-manager@google.com               ]                          │
│  HIGH (997) → edi_team + team_lead (immediate)                                        │
│  EDI Team:           [edi-team@google.com                  ]                          │
│  HIGH (non-997) → wms_team (immediate)                                                │
│  WMS Team:           [wms-team@google.com                  ]                          │
│  Team Lead:          [team-lead@google.com                 ]                          │
│  MEDIUM → edi_team hourly digest  │  LOW → edi_team daily digest                     │
│ ──────────────────────────────────────────────────────────────────────────────────── │
│  [    Save Settings    ]  ✓ Saved to config.toml                                      │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

### Demo Mode — See the Full Pipeline Without Live Credentials

```
┌─ EDI Exception Auto-Router ──────────── Demo complete — 7 files, 8 exceptions ───────┐
│                                                                                        │
│  Severity: [All severities ▼]  TX Type: [All TX types ▼]  [Refresh]  [▶ Run Demo]   │
│                                                                                        │
│  ID │ Code        │ Severity  │ TX  │ Status  │ File                       │ Detected │
│ ────┼─────────────┼───────────┼─────┼─────────┼────────────────────────────┼───────── │
│   1 │ E-ENV-005   │ CRITICAL  │ N/A │ sent    │ DEMO_850_CLEAN.edi         │ 14:45:01 │
│   2 │ E-997-REJ   │ CRITICAL  │ 997 │ sent    │ DEMO_997_REJECTION.edi     │ 14:45:02 │
│   3 │ E-810-AMT   │ HIGH      │ 810 │ sent    │ DEMO_810_AMT_MISMATCH.edi  │ 14:45:03 │
│   4 │ E-856-STR   │ HIGH      │ 856 │ sent    │ DEMO_856_MISSING_BSN.edi   │ 14:45:04 │
│   5 │ E-850-STR   │ HIGH      │ 850 │ sent    │ DEMO_850_NO_LINES.edi      │ 14:45:05 │
│   6 │ E-ENV-004   │ CRITICAL  │ N/A │ sent    │ DEMO_810_ENV_ERROR.edi     │ 14:45:06 │
│   7 │ E-810-AMT   │ HIGH      │ 810 │ sent    │ DEMO_810_ENV_ERROR.edi     │ 14:45:06 │
│   8 │ E-UNK-TX    │ MEDIUM    │ 999 │ batched │ DEMO_UNKNOWN_TX.edi        │ 14:45:07 │
│                                                                                        │
│  ┌─── [DEMO EMAIL] E-997-REJ | CRITICAL ──────────────────────────────────────────┐  │
│  │  To: ops-manager@google.com (demo)                                              │  │
│  │  Immediate email                                                                 │  │
│  │  Subject: [CRITICAL] EDI Alert — E-997-REJ | TX 997                            │  │
│  └─────────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Toast notifications appear for each routed exception — recipient, subject line, routing rule, and delivery type — in real time as the pipeline runs. No credentials needed to run a demo.

---

## Features

**Parsing**
- Auto-detects ISA element delimiter and segment terminator from the file header — no configuration needed
- Handles all standard X12 transaction types: `850` PO, `856` ASN, `810` Invoice, `997` Functional Ack, `855` PO Acknowledgment, `860` PO Change Order
- Decodes UTF-8 with automatic fallback to Latin-1 for legacy EDI files
- State machine parser validates ISA→GS→ST→SE→GE→IEA envelope structure

**Exception Classification**
- 12 error codes covering envelope errors, structural problems, business rule violations, and data quality issues
- Per-transaction severity scoring: CRITICAL, HIGH, MEDIUM, LOW
- Duplicate ISA control number detection across all previously processed files
- Stale transaction detection (configurable age threshold, default 48h)

**Routing Engine**
- First-match-wins rule engine with 6 priority tiers
- Immediate email dispatch for CRITICAL and HIGH severity (envelope errors always escalate to ops regardless of severity)
- Hourly digest batching for MEDIUM exceptions
- Daily digest batching for LOW exceptions
- All routing activity logged to SQLite with success/failure tracking

**SFTP / FTP Watcher**
- Polls on a configurable interval (default 5 minutes)
- Supports both SFTP (paramiko, SSH-encrypted) and plain FTP (ftplib) via a config toggle
- Filename-based dedup prevents reprocessing files across restarts
- Connection failures are caught and reported to the UI — the watcher recovers automatically on the next cycle

**TUI Dashboard**
- Dark amber terminal aesthetic (runs in any terminal, no GPU required)
- Live Queue with severity-colored badges, filters by severity and TX type, auto-refresh every 30 seconds
- Parser tab for ad-hoc inspection of raw X12 — paste directly from email or FTP client
- Routing Rules tab shows the live rule table and last batch flush timestamps
- Settings tab — full configuration UI with masked password fields, Test Connection and Test SMTP buttons, writes directly to `config.toml`

**Demo Mode**
- Single button runs 7 realistic fake EDI files through the full pipeline
- Email dispatch is intercepted — toast notifications show exactly what would be sent, to whom, and via which rule
- No SFTP credentials or SMTP server required
- Exceptions appear in the Live Queue exactly as they would in production

**Deployment**
- Ships as a single `.exe` via PyInstaller (GitHub Actions builds on `windows-latest`)
- `config.toml` and `edi_router.db` live next to the `.exe` — no installer, no registry keys
- Settings persist across restarts; configuration changes take effect on the next poll cycle without restarting

---

## Security & Privacy

> **TL;DR:** This application is entirely self-hosted. It makes two types of outbound connections: one to your SFTP/FTP server to download files, and one to your SMTP relay to send alert emails. All EDI data is parsed locally and stored in a SQLite file on the same machine. Nothing is uploaded to any third-party service.

### Data Flow

```
                   Your Network Only
  ┌────────────────────────────────────────────────────────────┐
  │                                                            │
  │  SFTP/FTP Server  ──pulls──►  EDI Router (this app)       │
  │  (Amazon drop zone)          │                            │
  │                              ├── SQLite DB (local file)   │
  │                              │   exceptions, routing log  │
  │                              │                            │
  │                              └──sends──►  SMTP Relay      │
  │                                          (your mail server)│
  │                                               │            │
  │                                               ▼            │
  │                                        Email recipients    │
  │                                        (Google staff)      │
  └────────────────────────────────────────────────────────────┘

  No telemetry. No analytics. No cloud APIs. No internet required.
```

### Credential Storage

Credentials (SFTP password, SMTP password) are stored in `config.toml` as plaintext. This is a deliberate trade-off for simplicity on a dedicated, access-controlled machine. To harden this:

1. **Restrict file permissions** on the EDI machine so only the service account can read `config.toml`:
   ```
   # Windows (icacls)
   icacls config.toml /inheritance:r /grant:r "EDI_SERVICE_ACCOUNT:(R)"

   # Linux/macOS
   chmod 600 config.toml
   chown ediservice:ediservice config.toml
   ```

2. **Use a Microsoft 365 App Password** rather than your primary account password for SMTP. App Passwords are scoped to a single application and can be revoked independently in the M365 admin portal without affecting the account.

3. **Never commit `config.toml` with real credentials to git.** The `.gitignore` in this repo excludes `*.db` files but intentionally keeps `config.toml` as a blank template. The committed version has all fields set to empty strings.

4. **SFTP is strongly preferred over FTP.** SFTP runs over SSH (port 22) and encrypts the entire session including credentials and file content. Plain FTP transmits everything in cleartext. If your trading partner supports SFTP, use it.

5. **STARTTLS is preferred over plain SMTP.** The default configuration uses port 587 with STARTTLS, which upgrades the SMTP connection to TLS before any credentials are sent. SSL on port 465 is equally secure. Plain SMTP on port 25 is not supported.

### What This Application Does NOT Do

| Concern | Status |
|---|---|
| Send EDI content to the internet | ✗ Never — only alert summaries are emailed |
| Upload data to a cloud service | ✗ Never |
| Require an internet connection | ✗ Fully offline except for your own servers |
| Phone home / send telemetry | ✗ Never |
| Store credentials in the Windows Registry | ✗ `config.toml` only |
| Require elevated / admin privileges | ✗ Runs as a standard user |
| Open any inbound network ports | ✗ All connections are outbound only |
| Modify or delete files on the SFTP server | ✗ Read-only — files are downloaded, never moved or deleted |

### EDI Data Residency

All parsed EDI content is stored in `edi_router.db` — a SQLite file on the local machine. This includes the raw file content, parsed transaction metadata, detected exceptions, and routing history. The file never leaves the machine unless you explicitly copy it. Back it up with the same procedures you use for any sensitive business data.

---

## How It Works

```
  ┌─────────────┐   poll every N min   ┌──────────────┐
  │  SFTP / FTP │ ──────────────────► │   watcher.py  │
  │  Drop Zone  │                      │  (bg thread)  │
  └─────────────┘                      └──────┬────────┘
                                              │ new .edi files
                                              ▼
                                       ┌──────────────┐
                                       │   parser.py   │
                                       │  X12 → structs│
                                       └──────┬────────┘
                                              │ ParseResult
                                              ▼
                                       ┌──────────────┐
                                       │ classifier.py │
                                       │ 12 error codes│
                                       └──────┬────────┘
                                              │ EDIException list
                                              ▼
                                       ┌──────────────┐
                                       │   router.py   │
                                       │ first-match   │
                                       │ rules engine  │
                                       └──────┬────────┘
                              ┌───────────────┼────────────────┐
                              ▼               ▼                ▼
                       ┌────────────┐  ┌──────────┐  ┌──────────────┐
                       │ mailer.py  │  │   db.py   │  │  event queue │
                       │ immediate  │  │  SQLite   │  │  → TUI toast │
                       │ or batched │  │   log     │  │  → subtitle  │
                       └────────────┘  └──────────┘  └──────────────┘
```

### Exception Lifecycle

1. **Watcher** polls the remote server, downloads any new `.edi` files
2. **Parser** reads raw bytes, auto-detects delimiters, walks the ISA envelope, extracts each ST/SE transaction
3. **Classifier** runs 12 checks per transaction — structural, business rule, and data quality
4. **Router** matches the first applicable rule, either calls `send_immediate()` or enqueues for the next batch flush
5. **DB** records every file, exception, and routing decision with timestamps
6. **TUI** drains the event queue every 2 seconds and refreshes the table every 30 seconds

---

## Exception Reference

| Code | Severity | Trigger | Default Route |
|---|---|---|---|
| `E-ENV-001` | CRITICAL | ISA segment missing or malformed | ops_manager |
| `E-ENV-002` | CRITICAL | GS functional group missing after ISA | ops_manager |
| `E-ENV-003` | CRITICAL | ST/SE transaction set boundary broken | ops_manager |
| `E-ENV-004` | CRITICAL | ISA13 ≠ IEA02 or GS06 ≠ GE02 (control # mismatch) | ops_manager |
| `E-ENV-005` | CRITICAL | SE01 segment count doesn't match actual count | ops_manager |
| `E-997-REJ` | CRITICAL | 997 AK5 ≠ `A` — trading partner rejected your EDI | ops_manager |
| `E-810-AMT` | HIGH | 810 TDS01 total ≠ sum of IT1 line amounts | wms_team |
| `E-856-STR` | HIGH | 856 missing BSN segment or zero HL loops | wms_team |
| `E-850-STR` | HIGH | 850 missing BEG segment or zero PO1 line items | wms_team |
| `E-UNK-TX`  | MEDIUM | ST01 is not a recognized transaction type | edi_team (batched) |
| `E-DUP-ISA` | MEDIUM | ISA control number already processed (resent file) | edi_team (batched) |
| `E-STALE`   | LOW | Transaction ISA date is more than 48 hours old | edi_team (daily digest) |

> Envelope errors (`E-ENV-*`) always route to `ops_manager` immediately regardless of the exception's assigned severity — rule 1 fires before severity rules.

---

## Routing Rules

Rules are evaluated top-down. The first matching rule wins.

| Priority | Condition | Delivery | Recipients |
|---|---|---|---|
| 1 | Error code starts with `E-ENV-` | Immediate | `ops_manager` |
| 2 | Severity = CRITICAL | Immediate | `ops_manager` |
| 3 | Severity = HIGH and TX type = 997 | Immediate | `edi_team` + `team_lead` |
| 4 | Severity = HIGH | Immediate | `wms_team` |
| 5 | Severity = MEDIUM | Hourly batch digest | `edi_team` |
| 6 | Severity = LOW | Daily digest | `edi_team` |

---

## Quick Start

**Prerequisites:** Python 3.9+ and pip.

```bash
# 1. Clone the repo
git clone https://github.com/your-org/edi-router.git
cd edi-router

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the app
python main.py

# The Settings tab (press 4) opens immediately.
# Fill in your connection and email details, click Save, then Test Connection / Test SMTP.
# Press 1 to return to the Live Queue — the watcher starts polling on the next cycle.
```

**Want to see it without any credentials?** Press `1` for Live Queue, then click **▶ Run Demo**. Seven realistic EDI files are processed in real time — exceptions appear in the table and toast notifications show every email that would be sent.

---

## Configuration

All configuration is managed from the **Settings tab** (press `4`). You never need to edit `config.toml` manually, though you can — it's a standard TOML file and the app reads it on every launch.

### Connection

| Field | Description | Default |
|---|---|---|
| Protocol | `sftp` (SSH, encrypted) or `ftp` (plaintext) | `sftp` |
| Host | SFTP/FTP hostname or IP of your trading partner's server | — |
| Port | 22 for SFTP, 21 for FTP | `22` |
| Username | Service account username | — |
| Password | Password (stored locally in `config.toml`) | — |
| Remote Path | Directory on the server where EDI files are dropped | `/edi/inbound` |
| Poll Interval | How often to check for new files, in seconds | `300` |
| Verify Host Key | Validate the server's SSH fingerprint (recommended for production) | `false` |

Click **Test Connection** to verify the credentials before saving. The test connects, lists the remote directory, and reports how many files it found.

### SMTP / Email

| Field | Description |
|---|---|
| Host | Your SMTP relay hostname (e.g. `smtp.office365.com`) |
| Port | 587 for STARTTLS (default), 465 for SSL |
| Username | Usually your full email address |
| Password | Your SMTP password or M365 App Password |
| From Address | The `From:` address that appears in alert emails |
| Use SSL | Off = STARTTLS (port 587). On = SSL (port 465) |

**Microsoft 365 users:** Do not use your primary account password. Generate an App Password:
1. Sign into the M365 admin portal
2. Go to **Security → Authentication methods → App Passwords**
3. Create a new App Password named "EDI Router"
4. Paste it into the Password field in Settings

Click **Test SMTP** to verify — the app connects, negotiates TLS, optionally logs in, and reports success or the exact SMTP error.

### Routing Addresses

| Field | Who gets alerted | When |
|---|---|---|
| Ops Manager | Envelope errors and all CRITICAL exceptions | Immediately |
| EDI Team | HIGH 997 rejections, MEDIUM batch, LOW digest | Immediately (997) or batched |
| WMS Team | HIGH exceptions on 810, 856, 850 | Immediately |
| Team Lead | HIGH 997 rejections (cc'd alongside EDI Team) | Immediately |

---

## Demo Mode

Demo mode runs the full parse → classify → route pipeline against seven built-in EDI files. It requires no SFTP server, no SMTP credentials, and sends no real emails.

**To run a demo:**
1. Press `1` to open the Live Queue tab
2. Click **▶ Run Demo** (green button)
3. Watch as files are processed one by one — exceptions appear in the table and toast notifications show each email that would have been dispatched

**Demo scenarios:**

| File | What it tests |
|---|---|
| `DEMO_850_CLEAN.edi` | A valid Purchase Order with no exceptions — shows normal flow |
| `DEMO_997_REJECTION.edi` | 997 with `AK5=R` → **E-997-REJ** CRITICAL → ops_manager |
| `DEMO_810_AMT_MISMATCH.edi` | Invoice where IT1 line totals don't match TDS01 → **E-810-AMT** HIGH → wms_team |
| `DEMO_856_MISSING_BSN.edi` | ASN with no BSN segment → **E-856-STR** HIGH → wms_team |
| `DEMO_850_NO_LINES.edi` | Purchase Order with zero PO1 line items → **E-850-STR** HIGH → wms_team |
| `DEMO_810_ENV_ERROR.edi` | 810 where ISA13 ≠ IEA02 → **E-ENV-004** CRITICAL → ops_manager |
| `DEMO_UNKNOWN_TX.edi` | File with an unrecognized ST01 type → **E-UNK-TX** MEDIUM → edi_team (batched) |

Demo uses unique ISA control numbers on every run so re-running it always produces a fresh set of exceptions.

---

## Windows Deployment

The app ships as a single `.exe` with no Python installation required on the target machine.

### Building the .exe

The GitHub Actions workflow at `.github/workflows/build.yml` builds the `.exe` automatically on every push to `main`:

1. Push your code to GitHub
2. Go to **Actions → Build Windows .exe**
3. Wait ~3 minutes for the build to complete
4. Download `edi-router-windows` artifact — it contains `edi-router.exe`

To build manually on a Windows machine:
```cmd
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --name edi-router --noconsole --collect-all textual main.py
```

The `.exe` is in the `dist/` directory.

### Deploying to the EDI Machine

1. Copy `edi-router.exe` and `config.toml` into the same folder on the Windows Server
2. Double-click `edi-router.exe` — a terminal window opens with the TUI
3. Press `4` (Settings), fill in your credentials, click Save
4. Press `1` (Live Queue) — the watcher begins polling

**To run as a Windows Service** (so it starts automatically and runs without a logged-in user), use [NSSM](https://nssm.cc):
```cmd
nssm install EDIRouter "C:\EDI\edi-router.exe"
nssm set EDIRouter AppDirectory "C:\EDI"
nssm start EDIRouter
```

---

## Project Structure

```
edi-router/
│
├── main.py           # Entry point — wires daemon thread + Textual TUI + shutdown
├── config.py         # TOML loader/writer, dataclasses, PyInstaller-safe path helpers
├── config.toml       # Configuration template (all values empty — safe to commit)
├── db.py             # SQLite schema, WAL mode, thread-safe read/write helpers
├── parser.py         # X12 segment parser — ISA delimiter detection, state machine
├── classifier.py     # 12 exception detection rules + severity scoring
├── router.py         # First-match-wins routing engine (6 rules)
├── mailer.py         # smtplib immediate emails + hourly/daily batch digests
├── watcher.py        # Background daemon — SFTP/FTP poll loop + event queue
├── demo.py           # 7 built-in EDI samples + demo pipeline runner
├── ui_textual.py     # Textual TUI — 4 tabs: Live Queue, Parser, Rules, Settings
├── requirements.txt
│
└── .github/
    └── workflows/
        └── build.yml # GitHub Actions → Windows .exe via PyInstaller
```

---

## Tech Stack

| Component | Library | Why |
|---|---|---|
| TUI | [Textual](https://github.com/Textualize/textual) | GPU-free, runs in any terminal, identical on Mac and Windows Server |
| SFTP | [paramiko](https://www.paramiko.org) | Battle-tested SSH implementation, pure Python |
| FTP | `ftplib` (stdlib) | No extra dependency for plain FTP fallback |
| Config | `tomllib` (3.11+) / `tomli` (backport) | Clean TOML parsing, stdlib on modern Python |
| Email | `smtplib` (stdlib) | Direct SMTP with STARTTLS/SSL, no external dependency |
| Database | `sqlite3` (stdlib) | Zero-config, runs anywhere, WAL mode for concurrent access |
| Packaging | [PyInstaller](https://pyinstaller.org) | Single `.exe`, no Python required on Windows Server |

All runtime dependencies are either Python stdlib or have no transitive dependencies that touch the network. The only outbound connections this application ever makes are the ones you explicitly configure.

---

## Development

```bash
# Install all dependencies
pip install -r requirements.txt

# Run the app
python main.py

# Run individual module tests
python parser.py --test       # Parser smoke tests
python classifier.py          # Classifier tests
python config.py              # Print loaded config
python db.py                  # Schema creation + round-trip test

# Parse a real EDI file from the command line
python parser.py path/to/file.edi
```

### Running the full demo pipeline headlessly (CI-friendly)

```python
import queue, tempfile, os
from demo import run_demo
from config import AppConfig, ConnectionConfig, SMTPConfig, RoutingConfig
from db import init_db

cfg = AppConfig(
    connection=ConnectionConfig("sftp", "", 22, "", "", "/edi", 300, False),
    smtp=SMTPConfig("", "", 587, "", "", False),
    routing=RoutingConfig("ops@test.com", "edi@test.com", "wms@test.com", "lead@test.com"),
)
conn = init_db(":memory:")   # in-memory SQLite for tests
eq = queue.Queue()
run_demo(conn, eq, cfg, delay_between_files=0)
# Drain and assert on events...
```

### Adding a new exception code

1. Add the error code, severity, and trigger description to the table in this README
2. Implement the detection logic in `classifier.py` — add a new `_check_*` function or extend an existing one
3. Add a recommended action string in `mailer.py` → `_recommended_action()`
4. Add a test case in `classifier.py`'s `__main__` block
5. Add a demo EDI sample in `demo.py` if the new code has a distinct structure worth demonstrating

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built for modern EDI operations teams

*Parse it. Classify it. Route it. Before it becomes a problem.*

</div>
