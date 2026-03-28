# EDI Exception Auto-Router — Local Test Setup Guide

This guide walks through testing the full pipeline on your own machine — no access to SML's SFTP server or Bergen's corporate email required. Everything runs locally using a software SFTP server and a Gmail account.

---

## Prerequisites

- The router app is installed and launches without errors (`python3 main.py` or the `.exe`).
- You have a Gmail account you can use for testing (a personal account is fine).
- You are on the same machine where the router is installed.

---

## Section 1 — Local SFTP Server

The router needs an SFTP endpoint to poll for `.edi` files. Below are instructions for both Windows and Mac to stand up a local SFTP server on your own machine.

---

### Windows — Enable OpenSSH Server (built into Windows 10/11)

OpenSSH is already included in Windows 10 and 11. You just need to turn on the server component.

**Step 1 — Install the OpenSSH Server feature**

1. Open **Settings** → **Apps** → **Optional Features**.
2. Click **Add a feature**.
3. Search for **OpenSSH Server**, select it, and click **Install**.
4. Wait for the installation to complete (usually under a minute).

**Step 2 — Start the SSH service**

Open **PowerShell as Administrator** and run:

```powershell
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

This starts the SFTP/SSH server and sets it to start automatically on reboot.

**Step 3 — Create the EDI watch folder**

In File Explorer (or PowerShell), create the folder the router will watch:

```powershell
New-Item -ItemType Directory -Path "C:\edi-test\inbound" -Force
```

**Step 4 — Confirm the server is running**

```powershell
Get-Service sshd
```

The status column should show `Running`.

**Step 5 — Configure the router**

Open the **Settings** tab in the TUI (or edit `config.toml` directly) and set:

```toml
[connection]
protocol = "sftp"
host     = "localhost"
port     = 22
username = "YOUR_WINDOWS_USERNAME"
password = "YOUR_WINDOWS_PASSWORD"
remote_path = "/C:/edi-test/inbound"
```

> Note: OpenSSH on Windows maps paths starting from the drive root. Use forward slashes and include the drive letter, e.g. `/C:/edi-test/inbound`.

---

### Mac — Enable the Built-In SSH Server

macOS ships with an SSH/SFTP daemon (sshd). It just needs to be enabled.

**Step 1 — Turn on Remote Login**

1. Open **System Settings** (macOS Ventura 13+) or **System Preferences** (older macOS).
2. Go to **General** → **Sharing** (Ventura+) or just **Sharing** (older).
3. Toggle **Remote Login** to **On**.
4. In the "Allow access for" dropdown, choose **All users** or add your own account specifically.

**Step 2 — Create the EDI watch folder**

Open **Terminal** and run:

```bash
mkdir -p ~/edi-test/inbound
```

**Step 3 — Confirm SSH is accepting connections**

```bash
ssh localhost
```

It should ask for your password and log you in. Type `exit` to close the test session.

**Step 4 — Configure the router**

Open the **Settings** tab in the TUI (or edit `config.toml`) and set:

```toml
[connection]
protocol = "sftp"
host     = "localhost"
port     = 22
username = "YOUR_MAC_USERNAME"
password = "YOUR_MAC_PASSWORD"
remote_path = "/Users/YOUR_MAC_USERNAME/edi-test/inbound"
```

Replace `YOUR_MAC_USERNAME` with the short username shown in Terminal (e.g. `deeppatel`). You can confirm it by running `whoami` in Terminal.

---

### Dropping Test Files to Trigger Processing

Once the router is running and connected, copy any `.edi` file into the watch folder:

**Windows:**
```powershell
Copy-Item "C:\path\to\test-file.edi" "C:\edi-test\inbound\"
```

**Mac:**
```bash
cp /path/to/test-file.edi ~/edi-test/inbound/
```

The router polls every 5 minutes by default (`poll_interval_seconds = 300` in `config.toml`). To get faster feedback during testing, temporarily change that value to `10` (10 seconds) in the Settings tab or directly in `config.toml`, then restart the app.

A minimal valid test `.edi` file you can create in any text editor:

```
ISA*00*          *00*          *ZZ*SMLSENDER     *ZZ*BERGENRCVR   *230101*1200*^*00501*000000001*0*T*>~
GS*PO*SMLSENDER*BERGENRCVR*20230101*1200*1*X*005010~
ST*850*0001~
BEG*00*SA*TEST-PO-001**20230101~
PO1*1*10*EA*25.00**BP*WIDGET-A~
CTT*1~
SE*5*0001~
GE*1*1~
IEA*1*000000001~
```

Save this as `test-850.edi`.

---

### What Success Looks Like in the TUI

After the router picks up the file, you should see in the TUI:

- The **Activity Log** panel shows a `file_received` entry with the filename and transaction type (e.g. `850`).
- If the file has no exceptions, the status updates to `parsed` with no alerts.
- If the file triggers an exception rule, an `exception_detected` entry appears in the log with the error code and severity (e.g. `CRITICAL`, `HIGH`).
- For CRITICAL or HIGH exceptions, an `email_sent` line appears immediately after.
- The **Stats** panel updates its file and exception counters.

If you see a `connection_error` entry instead, double-check the host, port, username, and remote path in Settings.

---

## Section 2 — Test Email via Gmail

The router uses SMTP to send alerts. For local testing, a Gmail account with an App Password is the most reliable free option.

---

### Step 1 — Enable 2-Step Verification on Your Google Account

App Passwords require 2-Step Verification to be active.

1. Go to [myaccount.google.com](https://myaccount.google.com).
2. Click **Security** in the left sidebar.
3. Under "How you sign in to Google," click **2-Step Verification**.
4. Follow the prompts to enable it (takes about 2 minutes).

---

### Step 2 — Generate a Gmail App Password

1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
   (If you don't see this page, make sure 2-Step Verification is enabled from Step 1.)
2. In the **App name** field, type: `EDI Router`
3. Click **Create**.
4. Google shows you a 16-character password in a yellow box, like: `abcd efgh ijkl mnop`
5. **Copy it now** — it will not be shown again.
6. Remove the spaces when you paste it into the router. The actual password is: `abcdefghijklmnop` (16 characters, no spaces).

---

### Step 3 — Enter SMTP Settings in the Router

Open the **Settings** tab in the TUI and fill in the SMTP section exactly as follows:

| Field          | Value                        |
|----------------|------------------------------|
| SMTP Host      | `smtp.gmail.com`             |
| Port           | `587`                        |
| Username       | `youraddress@gmail.com`      |
| Password       | The 16-character App Password (no spaces) |
| From Address   | `youraddress@gmail.com`      |
| Use SSL        | Off (leave unchecked — port 587 uses STARTTLS, not SSL) |

Or edit `config.toml` directly:

```toml
[smtp]
host         = "smtp.gmail.com"
port         = 587
username     = "youraddress@gmail.com"
password     = "abcdefghijklmnop"
from_address = "youraddress@gmail.com"
use_ssl      = false
```

---

### Step 4 — Point All Routing Addresses to Your Gmail

For testing, set every recipient address to your own Gmail so all alert types land in one inbox. In the Settings tab or `config.toml`:

```toml
[routing]
ops_manager = "youraddress@gmail.com"
edi_team    = "youraddress@gmail.com"
wms_team    = "youraddress@gmail.com"
team_lead   = "youraddress@gmail.com"
```

---

### Step 5 — Trigger a CRITICAL Email and Confirm It Arrives

1. In the TUI, click the **Run Demo** button (or press the keyboard shortcut shown next to it).
2. The demo injects a synthetic CRITICAL exception into the pipeline — you do not need a real `.edi` file for this step.
3. Watch the Activity Log for an `email_sent` entry with `rule: rule-1` (CRITICAL alerts go to `ops_manager` via Rule 1).
4. Check your Gmail inbox. The email should arrive within 30–60 seconds.
5. The subject line will look like: `[CRITICAL] EDI Alert — E-ENV-001 | TX 850` (exact error code may vary by demo scenario).

If the email does not arrive:
- Check your Gmail Spam folder first.
- Verify the App Password has no spaces.
- Confirm `use_ssl = false` (not `true`) — port 587 requires STARTTLS, not SSL.
- The TUI Activity Log will show a `connection_error` event with the specific SMTP error if the send failed.

---

## Section 3 — Full End-to-End Test

This section combines the SFTP and email setup into a single run-through that exercises every part of the pipeline.

---

### Step-by-Step Walkthrough

**1. Start the application**

```bash
python3 main.py
```

Or launch the `.exe`. The TUI appears. The watcher daemon starts in the background.

**2. Configure SFTP (Settings tab)**

- Protocol: `sftp`
- Host: `localhost`
- Port: `22`
- Username and Password: your local OS credentials
- Remote Path:
  - Windows: `/C:/edi-test/inbound`
  - Mac: `/Users/YOUR_USERNAME/edi-test/inbound`

Save the settings.

**3. Configure Gmail SMTP (Settings tab)**

- SMTP Host: `smtp.gmail.com`
- Port: `587`
- Username: `youraddress@gmail.com`
- Password: your 16-character App Password
- From Address: `youraddress@gmail.com`
- Use SSL: Off

**4. Set all routing addresses to your Gmail (Settings tab)**

Set `ops_manager`, `edi_team`, `wms_team`, and `team_lead` all to `youraddress@gmail.com`.

Save the settings.

**5. Run the Demo — confirm CRITICAL email**

Click **Run Demo** in the TUI. Within 60 seconds, a `[CRITICAL] EDI Alert` email should arrive in your Gmail inbox. This confirms the immediate-alert path works end to end.

**6. Drop a test file — confirm file processing**

Copy the `test-850.edi` file from Section 1 into the watch folder:

- Windows: `C:\edi-test\inbound\`
- Mac: `~/edi-test/inbound/`

Wait for the next poll (up to 5 minutes at default settings, or 10 seconds if you lowered `poll_interval_seconds`). The Activity Log should show `file_received` for `test-850.edi`.

---

### Testing the Batch Digest (Hourly Email)

The hourly digest collects MEDIUM-severity exceptions and sends them as a single summary email once per hour. To test this without waiting an hour:

**Step 1 — Temporarily shorten the flush interval**

Open `watcher.py` in a text editor. Find this line (around line 228):

```python
if now - self._last_hourly_flush >= timedelta(hours=1):
```

Change it to:

```python
if now - self._last_hourly_flush >= timedelta(minutes=2):
```

Save the file and restart the app (`Ctrl+C` to quit the TUI, then `python3 main.py` again).

**Step 2 — Generate a MEDIUM exception**

Drop a test `.edi` file into the watch folder that will produce a MEDIUM exception, or use Run Demo if it includes a MEDIUM scenario. MEDIUM exceptions are queued in the batch rather than sent immediately — you will not see an instant email for them.

**Step 3 — Wait 2 minutes**

After approximately 2 minutes, the watcher flushes the batch. The Activity Log shows `email_sent` with `rule: batch-hourly`. Check your Gmail inbox for a subject line like:

```
[EDI Hourly Digest] 1 exception(s)
```

The email body lists each queued MEDIUM exception with its error code, TX type, and filename.

**Step 4 — Restore the original interval**

Change `timedelta(minutes=2)` back to `timedelta(hours=1)` in `watcher.py` before using the router in production.

---

### End-to-End Checklist

Five things that confirm the system is working correctly:

- [ ] **SFTP connection succeeds** — The Activity Log shows a `poll_start` followed by `poll_complete` with no `connection_error` entries. Even if zero files are processed, a successful poll with no errors means the SFTP connection is working.

- [ ] **File is picked up and parsed** — After dropping `test-850.edi` into the watch folder, the Activity Log shows `file_received: test-850.edi | TX 850`. The file is not re-processed on the next poll (the router tracks seen files in its database).

- [ ] **CRITICAL alert email arrives in Gmail** — Running the Demo produces a `[CRITICAL] EDI Alert` email in your inbox within 60 seconds. Subject line includes the error code and TX type.

- [ ] **Hourly digest email arrives** — After temporarily setting the flush interval to 2 minutes and generating a MEDIUM exception, a `[EDI Hourly Digest]` email arrives in your inbox with the exception details listed inside.

- [ ] **No SMTP errors in the Activity Log** — Throughout all the above steps, zero `connection_error` events appear that mention "SMTP" or "Connection error." Any SMTP error will appear in red in the Activity Log with a specific error message to help you diagnose it.

---

## Quick Reference — Config Values for Local Testing

```toml
[connection]
protocol            = "sftp"
host                = "localhost"
port                = 22
username            = "your-os-username"
password            = "your-os-password"
remote_path         = "/Users/your-username/edi-test/inbound"   # Mac
# remote_path       = "/C:/edi-test/inbound"                    # Windows
poll_interval_seconds = 10    # set to 10 for testing, 300 for production
verify_host_key     = false

[smtp]
host         = "smtp.gmail.com"
port         = 587
username     = "youraddress@gmail.com"
password     = "abcdefghijklmnop"    # 16-char App Password, no spaces
from_address = "youraddress@gmail.com"
use_ssl      = false

[routing]
ops_manager = "youraddress@gmail.com"
edi_team    = "youraddress@gmail.com"
wms_team    = "youraddress@gmail.com"
team_lead   = "youraddress@gmail.com"
```

Remember to restore `poll_interval_seconds = 300` and the real routing addresses before going live.
