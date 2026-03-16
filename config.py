import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = INSTANCE_DIR / "uploads"


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{(INSTANCE_DIR / 'database.db').as_posix()}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_FOLDER = str(UPLOAD_DIR)
    ALLOWED_EXTENSIONS = {"pdf", "docx", "zip"}

    CLAMAV_COMMAND = os.environ.get("CLAMAV_COMMAND", "clamscan")
    ZAP_API_URL = os.environ.get("ZAP_API_URL", "http://127.0.0.1:8080")
    ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
    ZAP_SCAN_TIMEOUT = int(os.environ.get("ZAP_SCAN_TIMEOUT", "180"))
