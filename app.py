import os
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, flash, redirect, render_template, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from clamav_scanner import scan_file_with_clamav
from config import Config, INSTANCE_DIR, UPLOAD_DIR
from models import ScanHistory, User, db
from zap_scanner import scan_url_with_zap, validate_url


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=128)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create Account")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data.strip()).first():
            raise ValidationError("Username already exists.")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.strip().lower()).first():
            raise ValidationError("Email already registered.")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class FileScanForm(FlaskForm):
    file = FileField(
        "Upload File",
        validators=[
            FileRequired(),
            FileAllowed(["pdf", "docx", "zip"], "Only PDF, DOCX, and ZIP files are allowed."),
        ],
    )
    submit = SubmitField("Scan File")


class URLScanForm(FlaskForm):
    url = StringField("Target URL", validators=[DataRequired(), Length(max=500)])
    submit = SubmitField("Scan URL")

    def validate_url(self, field):
        if not validate_url(field.data.strip()):
            raise ValidationError("Enter a valid URL starting with http:// or https://.")


login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    INSTANCE_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)

    db.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_file(_error):
        flash("File is too large. Maximum upload size is 16 MB.", "danger")
        return redirect(url_for("upload_file"))

    @app.context_processor
    def inject_layout_data():
        return {"zap_host": urlparse(app.config["ZAP_API_URL"]).netloc}

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = RegistrationForm()
        if form.validate_on_submit():
            user = User(username=form.username.data.strip(), email=form.email.data.strip().lower())
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.strip().lower()).first()
            if user and user.check_password(form.password.data):
                login_user(user)
                flash("Welcome back.", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid email or password.", "danger")
        return render_template("login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        scans = ScanHistory.query.filter_by(user_id=current_user.id)
        recent_scans = scans.order_by(ScanHistory.created_at.desc()).limit(5).all()
        counts = {
            "file_scans": scans.filter_by(scan_type="file").count(),
            "url_scans": scans.filter_by(scan_type="url").count(),
            "threats": scans.filter(ScanHistory.result.in_(["Malware Detected", "High Risk", "Medium Risk"])).count(),
        }
        return render_template("dashboard.html", recent_scans=recent_scans, counts=counts)

    @app.route("/upload-file", methods=["GET", "POST"])
    @login_required
    def upload_file():
        form = FileScanForm()
        scan_result = None

        if form.validate_on_submit():
            uploaded_file = form.file.data
            original_name = secure_filename(uploaded_file.filename or "")
            if not original_name:
                flash("Please choose a valid file.", "danger")
                return render_template("upload_file.html", form=form, scan_result=None)

            temp_path = Path(app.config["UPLOAD_FOLDER"]) / f"{current_user.id}_{os.urandom(8).hex()}{Path(original_name).suffix.lower()}"
            try:
                uploaded_file.save(temp_path)
                scan_result = scan_file_with_clamav(temp_path, command=app.config["CLAMAV_COMMAND"])
                save_scan("file", original_name, scan_result)
                flash_scan_result("File scan", scan_result["status"])
            finally:
                if temp_path.exists():
                    temp_path.unlink()

        return render_template("upload_file.html", form=form, scan_result=scan_result)

    @app.route("/scan-url", methods=["GET", "POST"])
    @login_required
    def scan_url():
        form = URLScanForm()
        scan_result = None

        if form.validate_on_submit():
            target_url = form.url.data.strip()
            scan_result = scan_url_with_zap(
                target_url,
                api_url=app.config["ZAP_API_URL"],
                api_key=app.config["ZAP_API_KEY"],
                timeout_seconds=app.config["ZAP_SCAN_TIMEOUT"],
            )
            save_scan("url", target_url, scan_result)
            flash_scan_result("URL scan", scan_result["status"])

        return render_template("scan_url.html", form=form, scan_result=scan_result)

    @app.route("/history")
    @login_required
    def history():
        scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).all()
        return render_template("history.html", scans=scans)

    @app.route("/settings")
    @login_required
    def settings():
        return render_template("settings.html")

    with app.app_context():
        db.create_all()

    return app


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def save_scan(scan_type, target, scan_result):
    db.session.add(
        ScanHistory(
            user_id=current_user.id,
            scan_type=scan_type,
            target=target,
            result=scan_result["status"],
            details=scan_result["details"],
        )
    )
    db.session.commit()


def flash_scan_result(label, status):
    if status in {"Clean", "Safe"}:
        flash(f"{label} completed successfully.", "success")
    else:
        flash(f"{label} finished with status: {status}", "warning")


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
