import os, re, uuid, hashlib, math, mimetypes, sqlite3, socket, json, io, csv, zipfile, secrets, shutil, subprocess, socket as dns_socket
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

try:
    import qrcode
except ImportError:
    qrcode = None

try:
    from PIL import Image
    import pytesseract
except ImportError:
    Image = None
    pytesseract = None

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(days=14)
if not os.environ.get("SECRET_KEY"):
    print("[SECURITY] No SECRET_KEY configured; a temporary key was generated. Set SECRET_KEY in production.")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
QUARANTINE_FOLDER = BASE_DIR / "quarantine"
STATIC_FOLDER = BASE_DIR / "static"
DB_PATH = BASE_DIR / "scanner.db"
for folder in (UPLOAD_FOLDER, QUARANTINE_FOLDER, STATIC_FOLDER):
    folder.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf","doc","docx","xls","xlsx","ppt","pptx","txt","zip","jpg","jpeg","png",
    "exe","js","bat","cmd","vbs","ps1","scr","dll","gif","bmp","webp"
}
DANGEROUS_EXTENSIONS = {"exe","js","bat","cmd","vbs","ps1","scr","dll"}
SUSPICIOUS_EXTENSIONS = {"zip","docm","xlsm","pptm"}
SUSPICIOUS_STRINGS = [
    b"powershell", b"wscript", b"cscript", b"ransom", b"decrypt", b"bitcoin",
    b"wallet", b"encrypt", b"vssadmin", b"shadow copy", b"disable antivirus",
    b"your files have been encrypted"
]
RANSOMWARE_EXTENSIONS = {".locked",".encrypted",".enc",".crypt",".lockbit",".ryuk",".wannacry",".conti"}
PHISHING_TERMS = [
    "urgent", "verify your account", "click here", "password", "bank account",
    "account suspended", "payment required", "gift card", "crypto", "claim prize",
    "limited time", "immediately", "confirm your identity", "otp", "one time password"
]

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'file',
            file_type TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            action TEXT NOT NULL,
            sha256 TEXT,
            file_size INTEGER,
            entropy REAL,
            indicators TEXT,
            scan_time TEXT NOT NULL,
            stored_path TEXT,
            sender_domain TEXT, sender_checks TEXT, engine_result TEXT
        )
        """)
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        # Safe additive migration for databases created by earlier versions.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)")}
        for name, typ in (("sender_domain","TEXT"),("sender_checks","TEXT"),("engine_result","TEXT")):
            if name not in cols: conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {typ}")

def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def calculate_entropy(path):
    counts = [0] * 256
    total = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            total += len(chunk)
            for byte in chunk:
                counts[byte] += 1
    if not total:
        return 0.0
    entropy = -sum((c/total) * math.log2(c/total) for c in counts if c)
    return round(entropy, 2)

def read_sample(path, limit=2*1024*1024):
    with open(path, "rb") as f:
        return f.read(limit).lower()

def detect_file_type_mismatch(path, original_name):
    ext = Path(original_name).suffix.lower()
    with open(path, "rb") as f:
        header = f.read(16)
    signatures = {
        ".pdf": header.startswith(b"%PDF"),
        ".png": header.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": header.startswith(b"\xff\xd8\xff"),
        ".jpeg": header.startswith(b"\xff\xd8\xff"),
        ".zip": header.startswith(b"PK"),
        ".docx": header.startswith(b"PK"),
        ".xlsx": header.startswith(b"PK"),
        ".pptx": header.startswith(b"PK"),
    }
    if ext in signatures and not signatures[ext]:
        return True, "File extension does not match the expected signature."
    return False, ""

def inspect_archive(path, max_members=250, max_uncompressed=100*1024*1024):
    """Inspect ZIP metadata only; never extract or execute members."""
    findings=[]
    try:
        with zipfile.ZipFile(path) as zf:
            infos=zf.infolist()
            if len(infos)>max_members: findings.append(f"Archive contains more than {max_members} entries")
            total=sum(i.file_size for i in infos)
            if total>max_uncompressed: findings.append("Archive expands beyond the 100 MB inspection limit")
            for info in infos[:max_members]:
                name=info.filename.replace('\\','/')
                parts=[x for x in name.split('/') if x]
                if name.startswith('/') or '..' in parts or re.match(r'^[A-Za-z]:',name): findings.append(f"Archive path traversal candidate: {name[:100]}")
                ext=Path(name).suffix.lower().lstrip('.')
                if ext in DANGEROUS_EXTENSIONS: findings.append(f"Executable/script inside archive: {name[:100]}")
                if info.file_size and info.compress_size and info.file_size/max(1,info.compress_size)>1000: findings.append(f"Extreme compression ratio in: {name[:100]}")
    except zipfile.BadZipFile:
        findings.append("File has ZIP extension but is not a valid ZIP archive")
    except Exception as exc:
        findings.append(f"Archive inspection issue: {type(exc).__name__}")
    return findings

def run_clamav(path):
    """Optional local ClamAV check. Returns an honest unavailable status."""
    binary=shutil.which('clamscan')
    if not binary: return {"status":"NOT_CONFIGURED","detail":"clamscan not installed"}
    try:
        proc=subprocess.run([binary,'--no-summary',str(path)],capture_output=True,text=True,timeout=45,check=False)
        if proc.returncode==0: return {"status":"CLEAN","detail":"ClamAV reported no detection"}
        if proc.returncode==1: return {"status":"DETECTED","detail":(proc.stdout or proc.stderr).strip()[:500]}
        return {"status":"ERROR","detail":(proc.stderr or proc.stdout).strip()[:300]}
    except subprocess.TimeoutExpired: return {"status":"TIMEOUT","detail":"ClamAV scan exceeded 45 seconds"}

def check_sender_domain(domain):
    """DNS-based presence checks; these do not authenticate an individual message."""
    domain=(domain or '').strip().lower().strip('.')
    if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?",domain) or '.' not in domain:
        return {"domain":domain,"error":"Enter a valid domain name."}
    results={"domain":domain,"spf":"NOT_FOUND","dmarc":"NOT_FOUND","mx":"UNKNOWN","dkim":"NOT_CHECKED"}
    try:
        import dns.resolver
        def txt(name):
            try: return [b''.join(r.strings).decode(errors='ignore') for r in dns.resolver.resolve(name,'TXT', lifetime=3)]
            except Exception: return []
        spf=[x for x in txt(domain) if x.lower().startswith('v=spf1')]
        dmarc=[x for x in txt('_dmarc.'+domain) if x.lower().startswith('v=dmarc1')]
        results['spf']='FOUND' if spf else 'NOT_FOUND'; results['spf_record']=spf[:2]
        results['dmarc']='FOUND' if dmarc else 'NOT_FOUND'; results['dmarc_record']=dmarc[:2]
        try: dns.resolver.resolve(domain,'MX',lifetime=3); results['mx']='FOUND'
        except Exception: results['mx']='NOT_FOUND'
    except ImportError:
        results['error']='Install dnspython to enable DNS record checks.'
    return results

def scan_file(path, original_name):
    sample = read_sample(path)
    ext = Path(original_name).suffix.lower()
    indicators, score = [], 0
    if ext in DANGEROUS_EXTENSIONS:
        indicators.append(f"Dangerous executable/script extension: {ext}")
        score += 30
    elif ext in SUSPICIOUS_EXTENSIONS:
        indicators.append(f"Potentially risky macro/archive extension: {ext}")
        score += 15

    if re.search(r"\.(pdf|docx?|xlsx?|pptx?)\.(exe|scr|bat|cmd|js|vbs|ps1)$",
                 original_name.lower()):
        indicators.append("Suspicious double-extension filename")
        score += 25

    found = [s.decode(errors="ignore") for s in SUSPICIOUS_STRINGS if s in sample]
    if found:
        indicators.append("Suspicious strings: " + ", ".join(found[:6]))
        score += min(25, 5 * len(found))

    entropy = calculate_entropy(path)
    if entropy >= 7.5:
        indicators.append(f"High entropy: {entropy}/8")
        score += 20
    elif entropy >= 7.0:
        indicators.append(f"Elevated entropy: {entropy}/8")
        score += 10

    mismatch, reason = detect_file_type_mismatch(path, original_name)
    if mismatch:
        indicators.append(reason)
        score += 30

    archive_findings = inspect_archive(path) if ext == '.zip' else []
    for finding in archive_findings:
        indicators.append(finding); score += 25
    clam = run_clamav(path)
    if clam['status'] == 'DETECTED':
        indicators.append('ClamAV detection: ' + clam['detail']); score = 100
    vt = {"status":"NOT_CONFIGURED","detail":"Set VIRUSTOTAL_API_KEY to enable hash reputation lookup"}
    api_key=os.environ.get("VIRUSTOTAL_API_KEY")
    if api_key:
        try:
            import requests
            resp=requests.get("https://www.virustotal.com/api/v3/files/"+calculate_sha256(path),headers={"x-apikey":api_key},timeout=12)
            if resp.status_code==200:
                stats=resp.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                malicious=int(stats.get("malicious",0)); suspicious=int(stats.get("suspicious",0))
                vt={"status":"FOUND","malicious":malicious,"suspicious":suspicious,"detail":stats}
                if malicious: indicators.append(f"VirusTotal: {malicious} engine(s) marked this hash malicious"); score=100
                elif suspicious: indicators.append(f"VirusTotal: {suspicious} engine(s) marked this hash suspicious"); score+=15
            elif resp.status_code==404: vt={"status":"NOT_FOUND","detail":"Hash not present in VirusTotal database; not proof of safety"}
            else: vt={"status":"ERROR","detail":f"VirusTotal returned HTTP {resp.status_code}"}
        except Exception as exc: vt={"status":"ERROR","detail":type(exc).__name__}
    score = min(100, score)
    level = "HIGH" if score >= 70 else "SUSPICIOUS" if score >= 30 else "LOW"
    return {
        "risk_score": score, "risk_level": level, "sha256": calculate_sha256(path),
        "file_size": os.path.getsize(path), "entropy": entropy,
        "file_type": mimetypes.guess_type(original_name)[0] or "Unknown",
        "extension": ext.lstrip(".").upper() or "Unknown",
        "indicators": indicators, "type_mismatch": mismatch, "clamav": clam, "virustotal": vt, "archive_findings": archive_findings
    }


def build_scan_guidance(data):
    """Create explainable, risk-tiered recommendations from this scan's evidence."""
    indicators = data.get("indicators") or []
    level = data.get("risk_level", "LOW")
    score = int(data.get("risk_score") or 0)
    text_indicators = " ".join(str(x).lower() for x in indicators)

    explanations = []
    explanation_rules = [
        (("dangerous executable/script extension",), "The filename uses an executable or script extension. Such files can run commands or code when opened; only accept them from a verified sender and expected workflow."),
        (("double-extension",), "The filename contains more than one extension (for example, report.pdf.exe). This can disguise an executable as an ordinary document."),
        (("suspicious strings",), "The file contains text associated with scripting, encryption, ransom demands, or disabling protections. These strings are warning signals, not proof that the file executed."),
        (("high entropy", "elevated entropy"), "The file data is unusually random or compressed. Encryption and packed files can have high entropy, but legitimate archives and media can too."),
        (("signature", "extension does not match"), "The file's internal header does not match its filename extension. It may be mislabeled, malformed, or deliberately disguised."),
        (("potentially risky macro/archive extension",), "This format can contain macros or bundled content. Treat it cautiously, especially if it arrived unexpectedly."),
        (("suspicious phrases",), "The extracted message contains common social-engineering phrases that pressure a recipient to act, verify an account, or disclose information."),
        (("found ",), "The message contains one or more URLs. The scanner only detects their presence; it does not establish that a destination is safe."),
        (("possible request for a verification code",), "The message may be asking for a one-time code or credentials. Never share OTPs, passwords, or recovery codes through a message link."),
    ]
    for keys, explanation in explanation_rules:
        if any(k in text_indicators for k in keys):
            explanations.append(explanation)
    if not explanations:
        explanations.append("No configured threat indicators were detected. This is a limited static check and does not prove the attachment is harmless.")

    if level == "HIGH":
        actions = [
            "Do not open, preview, extract, or run this attachment.",
            "Keep the file quarantined; do not restore it unless it has been independently verified.",
            "Confirm the sender using a separate trusted channel and request a clean copy if needed.",
            "If the file was already opened, disconnect the affected device from the network and run a trusted endpoint security scan.",
            "Report the message to your email/security administrator and preserve the original email for investigation."
        ]
        rescan = "Rescan only after obtaining a fresh copy from a verified source or after an updated security tool/signature set is available."
    elif level == "SUSPICIOUS":
        actions = [
            "Do not open the attachment or follow links until its source and purpose are verified.",
            "Contact the sender through a known phone number or separate conversation.",
            "Check whether the file type and requested action are expected; ask for a safer format if possible.",
            "Use an updated endpoint security product or an isolated analysis environment for a second opinion."
        ]
        rescan = "Rescan after verifying the sender, receiving a replacement copy, or updating your security tools. Compare the new SHA-256 hash."
    else:
        actions = [
            "Proceed only if you expected this attachment and independently trust the sender.",
            "Keep operating system, office software, browser, and endpoint protection updated.",
            "Open documents with macros disabled unless the macros are essential and verified.",
            "Avoid enabling content, macros, or permissions prompted by an unexpected document."
        ]
        rescan = "Rescan if the file changes, comes from a different source, or your security tools receive updates. A LOW result is not a safety guarantee."

    # Evidence-based checklist: checks actually represented by this scanner.
    checklist = [
        {"name": "SHA-256 fingerprint calculated", "done": bool(data.get("sha256")), "detail": "A hash was calculated to identify this exact file."},
        {"name": "File size and entropy measured", "done": data.get("file_size") is not None and data.get("entropy") is not None, "detail": "Basic file properties were measured."},
        {"name": "Filename extension reviewed", "done": True, "detail": "The extension was checked against configured risky-extension rules."},
        {"name": "Known suspicious strings checked", "done": data.get("scan_type") == "file", "detail": "Configured byte-string indicators were checked for file scans; OCR scans use message-pattern checks instead."},
        {"name": "File signature compared", "done": data.get("scan_type") == "file", "detail": "Supported file headers were compared with their extensions for file scans."},
        {"name": "Sender independently verified", "done": False, "detail": "This scanner cannot verify the sender's identity."},
        {"name": "Live antivirus / cloud reputation check", "done": False, "detail": "No live antivirus or reputation service is configured in this project."},
        {"name": "Attachment opened in a sandbox", "done": False, "detail": "The scanner does not execute or sandbox attachments."},
    ]
    return {"explanations": explanations, "actions": actions, "rescan": rescan,
            "checklist": checklist, "completed_checks": sum(x["done"] for x in checklist),
            "pending_checks": sum(not x["done"] for x in checklist)}


def save_scan(data):
    with db() as conn:
        cur = conn.execute("""
        INSERT INTO scans(filename,scan_type,file_type,risk_score,risk_level,action,
        sha256,file_size,entropy,indicators,scan_time,stored_path)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            data["filename"], data.get("scan_type","file"), data.get("file_type","Unknown"),
            data["risk_score"], data["risk_level"], data["action"], data.get("sha256",""),
            data.get("file_size",0), data.get("entropy",0), json.dumps(data.get("indicators",[])),
            data["scan_time"], data.get("stored_path","")
        ))
        data["id"] = cur.lastrowid
    return data["id"]

def get_scans():
    with db() as conn:
        return conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()

def get_scan(scan_id):
    with db() as conn:
        return conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

def stats():
    scans = get_scans()
    return {
        "total": len(scans),
        "low": sum(s["risk_level"] == "LOW" for s in scans),
        "suspicious": sum(s["risk_level"] == "SUSPICIOUS" for s in scans),
        "high": sum(s["risk_level"] == "HIGH" for s in scans),
        "quarantined": sum(s["action"] == "QUARANTINED" for s in scans)
    }

def local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"

def generate_qr():
    if qrcode is None:
        return None
    mobile_url = f"http://{local_ip()}:5000/mobile"
    qr = qrcode.make(mobile_url)
    qr_path = STATIC_FOLDER / "mobile_qr.png"
    qr.save(qr_path)
    return mobile_url

def classify_text(text):
    text_l = text.lower()
    hits = [term for term in PHISHING_TERMS if term in text_l]
    urls = re.findall(r"https?://[^\s]+|www\.[^\s]+", text, flags=re.I)
    indicators = []
    score = min(75, len(hits) * 12)
    if hits:
        indicators.append("Suspicious phrases: " + ", ".join(hits[:8]))
    if urls:
        indicators.append(f"Found {len(urls)} URL(s); verify them before opening.")
        score += min(20, len(urls) * 5)
    if re.search(r"\b\d{4,8}\b", text) and any(k in text_l for k in ("otp","password","bank","verify")):
        indicators.append("Possible request for a verification code or credential.")
        score += 15
    score = min(100, score)
    level = "HIGH" if score >= 70 else "SUSPICIOUS" if score >= 30 else "LOW"
    return score, level, indicators, urls

def extract_ocr(image_path):
    if Image is None or pytesseract is None:
        raise RuntimeError("OCR libraries are missing. Install Pillow and pytesseract.")
    # Set TESSERACT_CMD in .env if the executable is installed in a custom location.
    tess_cmd = os.environ.get("TESSERACT_CMD")
    if tess_cmd:
        pytesseract.pytesseract.tesseract_cmd = tess_cmd
    return pytesseract.image_to_string(Image.open(image_path)).strip()

@app.route("/")
def dashboard():
    scans = get_scans()
    return render_template("dashboard.html", stats=stats(), scans=scans[:8])

@app.route("/scan", methods=["POST"])
def scan_route():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Select a file to scan.")
        return redirect(url_for("dashboard"))
    safe_name = secure_filename(file.filename)
    if not safe_name or not allowed_file(safe_name):
        flash("Unsupported file extension.")
        return redirect(url_for("dashboard"))
    saved_name = f"{uuid.uuid4().hex}_{safe_name}"
    path = UPLOAD_FOLDER / saved_name
    file.save(path)
    try:
        result = scan_file(path, safe_name)
        action = "QUARANTINED" if result["risk_level"] == "HIGH" else "WARNING" if result["risk_level"] == "SUSPICIOUS" else "ALLOWED"
        final_path = path
        if action == "QUARANTINED":
            final_path = QUARANTINE_FOLDER / saved_name
            os.replace(path, final_path)
        data = {
            **result, "filename": safe_name, "scan_type": "file", "action": action,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stored_path": str(final_path)
        }
        scan_id = save_scan(data)
        return redirect(url_for("result", scan_id=scan_id))
    except Exception as e:
        if path.exists():
            path.unlink(missing_ok=True)
        flash(f"Scan failed: {e}")
        return redirect(url_for("dashboard"))

@app.route("/result/<int:scan_id>")
def result(scan_id):
    record = get_scan(scan_id)
    if not record:
        flash("Scan result not found.")
        return redirect(url_for("history"))
    data = dict(record)
    data["indicators"] = json.loads(data["indicators"] or "[]")
    data["guidance"] = build_scan_guidance(data)
    return render_template("result.html", result=data)

@app.route("/rescan/<int:scan_id>", methods=["POST"])
def rescan_scan(scan_id):
    record = get_scan(scan_id)
    if not record:
        flash("Original scan record was not found.")
        return redirect(url_for("history"))
    old = dict(record)
    old_path = Path(old.get("stored_path") or "")
    if not old_path.is_file():
        flash("The original file is no longer available. Upload it again to rescan.")
        return redirect(url_for("result", scan_id=scan_id))
    try:
        if old.get("scan_type") == "file":
            result_data = scan_file(old_path, old["filename"])
            action = "QUARANTINED" if result_data["risk_level"] == "HIGH" else "WARNING" if result_data["risk_level"] == "SUSPICIOUS" else "ALLOWED"
            final_path = old_path
            if action == "QUARANTINED" and old_path.parent != QUARANTINE_FOLDER:
                final_path = QUARANTINE_FOLDER / old_path.name
                os.replace(old_path, final_path)
            elif action != "QUARANTINED" and old_path.parent == QUARANTINE_FOLDER:
                final_path = UPLOAD_FOLDER / old_path.name
                os.replace(old_path, final_path)
            new_data = {**result_data, "filename": old["filename"], "scan_type": "file",
                        "action": action, "stored_path": str(final_path)}
        else:
            extracted = extract_ocr(old_path)
            score, level, indicators, urls = classify_text(extracted)
            new_data = {"filename": old["filename"], "scan_type": old["scan_type"],
                        "file_type": old["file_type"], "risk_score": score, "risk_level": level,
                        "action": "WARNING" if level != "LOW" else "ALLOWED",
                        "sha256": calculate_sha256(old_path), "file_size": os.path.getsize(old_path),
                        "entropy": calculate_entropy(old_path),
                        "indicators": indicators + (["OCR_TEXT: " + extracted[:1500]] if extracted else []),
                        "stored_path": str(old_path)}
        new_data["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_id = save_scan(new_data)
        flash("Rescan completed. A new history record was created; the previous result was kept.")
        return redirect(url_for("result", scan_id=new_id))
    except Exception as e:
        flash(f"Rescan could not be completed: {e}")
        return redirect(url_for("result", scan_id=scan_id))


@app.route("/history")
def history():
    return render_template("history.html", scans=get_scans(), stats=stats())

@app.route("/history/clear", methods=["POST"])
def clear_history():
    with db() as conn:
        conn.execute("DELETE FROM scans")
    flash("Scan history cleared. Uploaded/quarantined files were not deleted.")
    return redirect(url_for("history"))

@app.route("/download/<int:scan_id>/<format>")
def download_report(scan_id, format):
    record = get_scan(scan_id)
    if not record:
        flash("Report not found.")
        return redirect(url_for("history"))
    data = dict(record)
    data["indicators"] = json.loads(data["indicators"] or "[]")
    data["guidance"] = build_scan_guidance(data)
    if format == "json":
        buf = io.BytesIO(json.dumps(data, indent=2).encode("utf-8"))
        return send_file(buf, mimetype="application/json", as_attachment=True,
                         download_name=f"scan_report_{scan_id}.json")
    if format == "pdf":
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
        except ImportError:
            flash("PDF export unavailable. Run pip install reportlab.")
            return redirect(url_for("result", scan_id=scan_id))
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        y = 750
        c.setFont("Helvetica-Bold", 16); c.drawString(50, y, "Attachment Security Scan Report"); y -= 35
        c.setFont("Helvetica", 10)
        lines = [
            f"Scan ID: {data['id']}", f"Filename: {data['filename']}",
            f"Scan type: {data['scan_type']}", f"Risk: {data['risk_level']} ({data['risk_score']}/100)",
            f"Action: {data['action']}", f"Date: {data['scan_time']}",
            f"SHA-256: {data['sha256']}", f"File size: {data['file_size']} bytes",
            f"Entropy: {data['entropy']}", "Indicators:"
        ] + [x for x in data["indicators"] if not str(x).startswith("OCR_TEXT:")]
        lines += ["", "Threat explanations:"] + data["guidance"]["explanations"]
        lines += ["", "Security checklist:"]
        lines += [("[DONE] " if x["done"] else "[PENDING] ") + x["name"] for x in data["guidance"]["checklist"]]
        lines += ["", "Recommended actions:"] + data["guidance"]["actions"]
        lines += ["Rescan recommendation: " + data["guidance"]["rescan"]]
        for line in lines:
            for wrapped in [line[i:i+95] for i in range(0, len(line), 95)]:
                if y < 60:
                    c.showPage(); y = 750; c.setFont("Helvetica", 10)
                c.drawString(50, y, wrapped); y -= 16
        c.save(); buf.seek(0)
        return send_file(buf, mimetype="application/pdf", as_attachment=True,
                         download_name=f"scan_report_{scan_id}.pdf")
    flash("Unsupported report format.")
    return redirect(url_for("result", scan_id=scan_id))

@app.route("/mobile")
def mobile():
    return render_template("mobile.html")

@app.route("/mobile/scan", methods=["POST"])
def mobile_scan():
    image = request.files.get("image")
    if not image or not image.filename:
        flash("Choose an image from your phone.")
        return redirect(url_for("mobile"))
    safe_name = secure_filename(image.filename)
    ext = Path(safe_name).suffix.lower()
    if ext not in {".png",".jpg",".jpeg",".bmp",".gif",".webp"}:
        flash("Upload a PNG, JPG, JPEG, BMP, GIF or WEBP image.")
        return redirect(url_for("mobile"))
    saved = f"{uuid.uuid4().hex}_{safe_name}"
    path = UPLOAD_FOLDER / saved
    image.save(path)
    try:
        extracted = extract_ocr(path)
        if not extracted:
            extracted = "(No readable text detected by OCR.)"
        score, level, indicators, urls = classify_text(extracted)
        action = "WARNING" if level != "LOW" else "ALLOWED"
        data = {
            "filename": safe_name, "scan_type": "mobile OCR screenshot",
            "file_type": "Image / OCR text", "risk_score": score, "risk_level": level,
            "action": action, "sha256": calculate_sha256(path), "file_size": os.path.getsize(path),
            "entropy": calculate_entropy(path), "indicators": indicators,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stored_path": str(path), "ocr_text": extracted, "urls": urls
        }
        scan_id = save_scan(data)
        # Save OCR text separately in the report's indicator field for history compatibility.
        with db() as conn:
            conn.execute("UPDATE scans SET indicators=? WHERE id=?",
                         (json.dumps(indicators + ["OCR_TEXT: " + extracted[:1500]]), scan_id))
        return redirect(url_for("result", scan_id=scan_id))
    except Exception as e:
        flash(f"OCR could not run: {e}. Check README for Tesseract setup.")
        return redirect(url_for("mobile"))

@app.route("/mobile-qr")
def mobile_qr():
    url = generate_qr()
    if not url:
        return jsonify({"error":"QR library unavailable. Install qrcode[pil]."}), 500
    return jsonify({"url": url, "qr_image": url_for("static", filename="mobile_qr.png")})

@app.route("/api/stats")
def api_stats():
    return jsonify(stats())


# ---------------- Advanced security console ----------------
def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'): return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get('role') != 'admin': abort(403)
        return fn(*args, **kwargs)
    return wrapped

@app.context_processor
def inject_security_context(): return {'csrf_token': session.get('csrf_token',''), 'current_user':session.get('username')}

@app.before_request
def enforce_session_and_csrf():
    open_endpoints={'login','setup','static'}
    if request.endpoint in open_endpoints or request.endpoint is None: return
    if not session.get('user_id'):
        if request.endpoint in {'dashboard','scan_route','result','rescan_scan','history','clear_history','download_report','mobile','mobile_scan','mobile_qr','api_stats'}:
            return redirect(url_for('login'))
    if request.method=='POST' and session.get('role')=='viewer' and request.endpoint in {'scan_route','mobile_scan','clear_history','rescan_scan'}:
        abort(403)
    if request.method=='POST' and session.get('user_id'):
        token=request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token or not secrets.compare_digest(token,session.get('csrf_token','')): abort(400,'CSRF validation failed')

@app.route('/setup',methods=['GET','POST'])
def setup():
    with db() as conn: count=conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if count: return redirect(url_for('login'))
    if request.method=='POST':
        username=request.form.get('username','').strip(); password=request.form.get('password','')
        if len(username)<3 or len(password)<12: flash('Use a username of at least 3 characters and password of at least 12 characters.'); return redirect(url_for('setup'))
        with db() as conn: conn.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',(username,generate_password_hash(password),'admin',datetime.now().isoformat()))
        flash('Administrator created. Please sign in.'); return redirect(url_for('login'))
    return render_template('auth.html',mode='setup')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        with db() as conn: user=conn.execute('SELECT * FROM users WHERE username=?',(request.form.get('username',''),)).fetchone()
        if user and check_password_hash(user['password_hash'],request.form.get('password','')):
            session.clear(); session['user_id']=user['id']; session['username']=user['username']; session['role']=user['role']; session['csrf_token']=secrets.token_urlsafe(32)
            session.permanent = request.form.get('remember') == 'yes'
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Invalid username or password.')
    return render_template('auth.html',mode='login')

@app.route('/logout',methods=['POST'])
@login_required
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/email-security',methods=['GET','POST'])
@login_required
def email_security():
    result=None
    if request.method=='POST': result=check_sender_domain(request.form.get('domain'))
    return render_template('email_security.html',result=result)

@app.route('/analytics')
@login_required
def analytics():
    scans=get_scans(); bytype={}
    for x in scans: bytype[x['file_type'] or 'Unknown']=bytype.get(x['file_type'] or 'Unknown',0)+1
    return render_template('analytics.html',stats=stats(),bytype=sorted(bytype.items(),key=lambda x:x[1],reverse=True),scans=scans[:30])

@app.route('/quarantine')
@login_required
def quarantine():
    with db() as conn: rows=conn.execute("SELECT * FROM scans WHERE action='QUARANTINED' ORDER BY id DESC").fetchall()
    return render_template('quarantine.html',scans=rows)

@app.route('/quarantine/<int:scan_id>/delete',methods=['POST'])
@admin_required
def quarantine_delete(scan_id):
    record=get_scan(scan_id)
    if record and record['action']=='QUARANTINED':
        path=Path(record['stored_path'] or '')
        if path.is_file() and path.parent.resolve()==QUARANTINE_FOLDER.resolve(): path.unlink()
        with db() as conn: conn.execute("UPDATE scans SET stored_path='', action='DELETED' WHERE id=?",(scan_id,))
    flash('Quarantined file deletion processed.'); return redirect(url_for('quarantine'))

@app.route('/reports/export/<fmt>')
@login_required
def export_all(fmt):
    rows=get_scans()
    if fmt=='json':
        buf=io.BytesIO(json.dumps([dict(r) for r in rows],indent=2).encode()); return send_file(buf,mimetype='application/json',as_attachment=True,download_name='security_scans.json')
    if fmt=='csv':
        buf=io.StringIO(); writer=csv.writer(buf); writer.writerow(['id','filename','scan_type','file_type','risk_score','risk_level','action','sha256','scan_time','indicators'])
        for r in rows: writer.writerow([r['id'],r['filename'],r['scan_type'],r['file_type'],r['risk_score'],r['risk_level'],r['action'],r['sha256'],r['scan_time'],r['indicators']])
        return send_file(io.BytesIO(buf.getvalue().encode('utf-8-sig')),mimetype='text/csv',as_attachment=True,download_name='security_scans.csv')
    if fmt=='pdf':
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        buf=io.BytesIO(); c=canvas.Canvas(buf,pagesize=letter); y=750; c.setFont('Helvetica-Bold',15); c.drawString(45,y,'Security Scan Summary'); y-=30; c.setFont('Helvetica',9)
        for r in rows:
            line=f"#{r['id']} {r['filename']} | {r['risk_level']} ({r['risk_score']}) | {r['action']} | {r['scan_time']}"
            c.drawString(45,y,line[:115]); y-=14
            if y<45: c.showPage(); y=750; c.setFont('Helvetica',9)
        c.save(); buf.seek(0); return send_file(buf,mimetype='application/pdf',as_attachment=True,download_name='security_scans.pdf')
    abort(404)

@app.route('/settings',methods=['GET','POST'])
@admin_required
def settings():
    keys=['CLAMAV_PATH','VIRUSTOTAL_API_KEY','MAX_UPLOAD_MB','SCAN_POLICY','ALERT_EMAIL']
    if request.method=='POST':
        with db() as conn:
            for key in keys:
                value=request.form.get(key,'').strip()
                # API credentials are stored in environment variables, not the database.
                if key=='VIRUSTOTAL_API_KEY': continue
                conn.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(key,value))
        flash('Settings saved. API secrets should be configured through environment variables.'); return redirect(url_for('settings'))
    with db() as conn: values={r['key']:r['value'] for r in conn.execute('SELECT * FROM app_settings')}
    return render_template('settings.html',values=values,clamav=bool(shutil.which('clamscan')),vt_configured=bool(os.environ.get('VIRUSTOTAL_API_KEY')))

@app.route('/users',methods=['GET','POST'])
@admin_required
def users():
    if request.method=='POST':
        username=request.form.get('username','').strip(); password=request.form.get('password',''); role=request.form.get('role','analyst')
        if len(username)<3 or len(password)<12 or role not in {'admin','analyst','viewer'}: flash('Invalid user details. Password must be at least 12 characters.')
        else:
            try:
                with db() as conn: conn.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',(username,generate_password_hash(password),role,datetime.now().isoformat()))
                flash('User created.')
            except sqlite3.IntegrityError: flash('Username already exists.')
    with db() as conn: rows=conn.execute('SELECT id,username,role,created_at FROM users ORDER BY id').fetchall()
    return render_template('users.html',users=rows)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
