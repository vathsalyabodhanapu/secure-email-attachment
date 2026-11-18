# SmartShield Secure Email Attachment Scanner — Advanced Edition

This upgrade keeps the original Flask scanner and adds an authenticated security console, safer archive inspection, optional local ClamAV scanning, optional VirusTotal hash reputation, sender-domain DNS posture checks, quarantine management, analytics, user administration and PDF/CSV/JSON exports.

## New capabilities

- **Authentication and permissions:** first-run administrator setup, password hashing, login/logout, session-based access, admin-only user/settings/quarantine-delete controls, analyst/viewer role labels.
- **CSRF protection:** session token validation on authenticated POST requests; tokens are included in project forms.
- **Safer uploads:** existing 25 MB request cap, generated storage names, filename sanitization and extension allow-list remain in place.
- **Archive inspection:** ZIP metadata inspection without extracting or executing members; flags path traversal candidates, nested executable/script members, extreme compression ratios and oversized archives.
- **ClamAV:** optional local `clamscan` invocation with timeout. Install ClamAV separately and ensure `clamscan` is on PATH.
- **VirusTotal:** optional SHA-256 hash lookup only (does not upload the file). Set `VIRUSTOTAL_API_KEY` in the environment. A hash not found by VirusTotal is not a clean verdict. Review your organization's privacy policy before using a cloud reputation provider.
- **Email security:** SPF, DMARC and MX DNS presence checks for a sender domain. This is domain posture only, not proof that a particular message passed SPF/DKIM/DMARC. Individual DKIM verification requires the selector and signed headers from the original email.
- **Quarantine Center:** lists quarantined scan records. Permanent deletion is administrator-only; there is deliberately no automatic release/restore button.
- **Analytics:** scan counts and file-type distribution.
- **Security reports:** export all scan history as PDF, CSV or JSON; per-scan PDF and JSON remain available.
- **System settings:** stores non-secret local policy values. API secrets belong in environment variables, not the SQLite database.

## Setup (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SECRET_KEY = [Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }))
# Optional, only if you have a VirusTotal API key:
$env:VIRUSTOTAL_API_KEY = "YOUR_API_KEY"
python app.py
```

Open `http://127.0.0.1:5000`. On first launch, choose **First time? Set up administrator** and create a username and password of at least 12 characters. The first account is the administrator.

## Optional ClamAV setup

Install ClamAV using its official package for your operating system, update its signatures, and ensure `clamscan` is available on PATH. The scanner reports `NOT_CONFIGURED` if it is absent. Keep ClamAV signatures updated.

## Optional SPF/DMARC/MX DNS checks

`dnspython` is included in requirements. Open **Email Security**, enter a sender domain and run the DNS check. DKIM is shown as `NOT_CHECKED` because DNS DKIM records are selector-specific and cannot be reliably checked without the original email's DKIM-Signature header.

## Run

```powershell
python app.py
```

For local development only. Do not expose the built-in Flask development server directly to the public internet. For deployment, use a production WSGI server behind HTTPS, set a persistent random `SECRET_KEY`, use secure cookie settings, restrict network access, and use managed secret storage.

## Important limitations / safety

- This is a defensive prototype, not a certified antivirus or production email gateway. A LOW result is not a safety guarantee.
- **No live sandbox detonation is included.** The application never executes uploaded attachments. Safe sandboxing requires a separate disposable VM or dedicated detonation service with strict network, filesystem and credential isolation; it is intentionally not simulated in-process.
- Gmail and Microsoft 365 OAuth/mailbox ingestion are not included. Connectors require provider OAuth registration, least-privilege scopes, consent, token protection and provider-specific testing.
- MFA is not included in this build. Enable it before production use; current authentication is username/password plus server-side session.
- The SPF/DMARC feature checks DNS record presence, not message-level authentication results. DKIM signature validation is not implemented.
- VirusTotal performs hash lookups only; it does not upload files. Do not treat an unknown hash as clean.
- ZIP files are inspected by metadata only; nested files are not extracted or recursively scanned.
- File signatures are checked for supported common types; this is not comprehensive format validation.
- Upload size is capped at 25 MB. Keep the app on a trusted local network while testing.
- Use a production server, HTTPS, secure cookies, rate limiting, backups, audit logging and formal security review before handling real mail or sensitive attachments.
