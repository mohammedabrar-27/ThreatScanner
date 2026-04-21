import os
import tempfile
from functools import wraps
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from app_helpers import close_db, enrich_scan_result, flash_result, format_scans, init_db, query_all, query_one, save_scan, execute
from clamav_scanner import scan_file_with_clamav
from nuclei_scanner import scan_url_with_nuclei, validate_url

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = Path(tempfile.gettempdir()) / "ThreatScannerUploads"
DATABASE_PATH = INSTANCE_DIR / "database.db"
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "zip", "rar"}


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "change-this-secret-key"),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    CLAMAV_COMMAND=os.environ.get("CLAMAV_COMMAND", r"C:\Program Files\ClamAV\clamscan.exe"),
    CLAMAV_SCAN_TIMEOUT=int(os.environ.get("CLAMAV_SCAN_TIMEOUT", "30")),
    NUCLEI_COMMAND=os.environ.get(
        "NUCLEI_COMMAND",
        r"C:\Users\MOHAMMED ABRAR KHAN\Downloads\nuclei_3.7.1_windows_amd64\nuclei.exe",
    ),
    NUCLEI_SCAN_TIMEOUT=int(os.environ.get("NUCLEI_SCAN_TIMEOUT", "30")),
)

INSTANCE_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
init_db(DATABASE_PATH)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def require_scan_login():
    if session.get("user_id"):
        return None
    flash("Please log in to run scans or view saved history.", "warning")
    return redirect(url_for("login"))


def save_user(username, email, password):
    execute(
        DATABASE_PATH,
        "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, datetime('now'))",
        (username, email, generate_password_hash(password)),
    )


def allowed_file(filename):
    return Path(filename).suffix.lower().lstrip(".") in ALLOWED_EXTENSIONS


def process_result(scan_type, target, result, label):
    save_scan(DATABASE_PATH, scan_type, target, result)
    flash_result(label, result["status"])
    return enrich_scan_result(scan_type, target, result)


@app.teardown_appcontext
def teardown_db(_error=None):
    close_db()


@app.context_processor
def inject_template_data():
    return {
        "is_logged_in": bool(session.get("user_id")),
        "user_name": session.get("username", ""),
        "user_email": session.get("email", ""),
        "url_scanner_name": "Nuclei",
    }


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(_error):
    flash("File is too large. Maximum upload size is 16 MB.", "danger")
    return redirect(url_for("upload_file"))


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
        elif password != confirm_password:
            flash("Passwords must match.", "danger")
        elif query_one(DATABASE_PATH, "SELECT 1 FROM users WHERE username = ?", (username,)):
            flash("Username already exists.", "danger")
        elif query_one(DATABASE_PATH, "SELECT 1 FROM users WHERE email = ?", (email,)):
            flash("Email already registered.", "danger")
        else:
            save_user(username, email, password)
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = query_one(DATABASE_PATH, "SELECT * FROM users WHERE email = ?", (email,))

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        counts = {"file_scans": 0, "url_scans": 0, "threats": 0}
        return render_template("dashboard.html", recent_scans=[], counts=counts)

    user_id = session["user_id"]
    counts = {
        "file_scans": query_one(DATABASE_PATH, "SELECT COUNT(*) AS total FROM scan_history WHERE user_id = ? AND scan_type = 'file'", (user_id,))["total"],
        "url_scans": query_one(DATABASE_PATH, "SELECT COUNT(*) AS total FROM scan_history WHERE user_id = ? AND scan_type = 'url'", (user_id,))["total"],
        "threats": query_one(
            DATABASE_PATH,
            "SELECT COUNT(*) AS total FROM scan_history WHERE user_id = ? AND result IN ('Malware Detected', 'High Risk', 'Medium Risk')",
            (user_id,),
        )["total"],
    }
    recent_scans = format_scans(query_all(DATABASE_PATH, "SELECT * FROM scan_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5", (user_id,)))
    return render_template("dashboard.html", recent_scans=recent_scans, counts=counts)


@app.route("/upload-file", methods=["GET", "POST"])
def upload_file():
    scan_result = None

    if request.method == "POST":
        login_redirect = require_scan_login()
        if login_redirect:
            return login_redirect

        uploaded_file = request.files.get("file")
        filename = secure_filename(uploaded_file.filename if uploaded_file else "")

        if not filename:
            flash("Please choose a file.", "danger")
        elif not allowed_file(filename):
            flash("Only PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT, ZIP, and RAR files are allowed.", "danger")
        else:
            temp_path = UPLOAD_DIR / f"{session['user_id']}_{os.urandom(8).hex()}{Path(filename).suffix.lower()}"
            try:
                uploaded_file.save(temp_path)
                raw_result = scan_file_with_clamav(
                    temp_path,
                    command=app.config["CLAMAV_COMMAND"],
                    timeout_seconds=app.config["CLAMAV_SCAN_TIMEOUT"],
                )
                scan_result = process_result("file", filename, raw_result, "File scan")
            finally:
                if temp_path.exists():
                    temp_path.unlink()

    return render_template("upload_file.html", scan_result=scan_result)


@app.route("/scan-url", methods=["GET", "POST"])
def scan_url():
    scan_result = None

    if request.method == "POST":
        login_redirect = require_scan_login()
        if login_redirect:
            return login_redirect

        target_url = request.form.get("url", "").strip()
        if not validate_url(target_url):
            flash("Enter a valid URL starting with http:// or https://.", "danger")
        else:
            raw_result = scan_url_with_nuclei(
                target_url,
                command=app.config["NUCLEI_COMMAND"],
                timeout_seconds=app.config["NUCLEI_SCAN_TIMEOUT"],
            )
            scan_result = process_result("url", target_url, raw_result, "URL scan")

    return render_template("scan_url.html", scan_result=scan_result)


@app.route("/history")
@login_required
def history():
    scans = format_scans(query_all(DATABASE_PATH, "SELECT * FROM scan_history WHERE user_id = ? ORDER BY created_at DESC", (session["user_id"],)))
    return render_template("history.html", scans=scans)


if __name__ == "__main__":
    app.run(debug=True, threaded=True, use_reloader=False)
