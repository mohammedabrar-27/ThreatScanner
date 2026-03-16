# ThreatScanner

ThreatScanner is a BCA final year project built with Flask, Bootstrap, and SQLite. It allows users to register, log in, scan uploaded files with ClamAV, scan URLs with OWASP ZAP, and review per-user scan history from a dashboard.

## Features

- User registration, login, logout, and session management with `Flask-Login`
- Password hashing with Werkzeug
- File malware scanning for `PDF`, `DOCX`, and `ZIP`
- URL threat scanning through the OWASP ZAP API
- SQLite database for scan history
- File upload limits and input validation
- Automatic cleanup of uploaded files after scanning

## Project Structure

```text
ThreatScanner/
├── app.py
├── models.py
├── scanner.py
├── zap_scanner.py
├── clamav_scanner.py
├── config.py
├── requirements.txt
├── README.md
├── static/
│   └── css/
│       └── styles.css
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload_file.html
│   ├── scan_url.html
│   ├── history.html
│   └── settings.html
└── instance/
    ├── database.db
    └── uploads/
```

## 1. Install Python

Install Python 3.11 or newer from the official site:

- [Python Downloads](https://www.python.org/downloads/)

During installation on Windows, enable `Add Python to PATH`.

Verify installation:

```powershell
python --version
```

## 2. Create a Virtual Environment

```powershell
python -m venv .venv
.venv\Scripts\activate
```

## 3. Install Project Dependencies

```powershell
pip install -r requirements.txt
```

## 4. Install and Configure ClamAV

### Windows

1. Install ClamAV for Windows.
2. Make sure `clamscan.exe` is available in your system PATH, or set the command manually:

```powershell
$env:CLAMAV_COMMAND="C:\Program Files\ClamAV\clamscan.exe"
```

### Linux

```bash
sudo apt update
sudo apt install clamav clamav-daemon
freshclam
```

### Test ClamAV

```powershell
clamscan --version
```

## 5. Run OWASP ZAP

1. Download and install OWASP ZAP:
   [OWASP ZAP](https://www.zaproxy.org/download/)
2. Start ZAP.
3. Enable the API if needed.
4. By default this project expects ZAP at `http://127.0.0.1:8080`.

Optional environment variables:

```powershell
$env:ZAP_API_URL="http://127.0.0.1:8080"
$env:ZAP_API_KEY="your-api-key-if-configured"
$env:ZAP_SCAN_TIMEOUT="180"
```

## 6. Run the Flask Application

```powershell
$env:FLASK_APP="app.py"
$env:FLASK_ENV="development"
flask run
```

Or:

```powershell
python app.py
```

Open the app in your browser:

- [http://127.0.0.1:5000](http://127.0.0.1:5000)

## 7. How the Scanners Work

### File Scan Flow

1. User uploads a supported file.
2. Flask stores it temporarily in `instance/uploads/`.
3. The backend calls ClamAV using `clamscan`.
4. The result is saved to the database.
5. The uploaded file is deleted immediately after scanning.

### URL Scan Flow

1. User submits a URL.
2. Flask validates the URL.
3. The app calls the OWASP ZAP API to spider and actively scan the site.
4. Alerts are converted into `Safe`, `Medium Risk`, or `High Risk`.
5. The result is saved to the database.

## 8. Security Notes

- Uploaded files are never executed or opened by the app.
- Files are stored outside the `static/` folder.
- Unsupported file types are rejected.
- File size is limited to 16 MB.
- URL input is validated before sending it to ZAP.
- Passwords are hashed before storing them in the database.

## 9. Important Demo Note

If ClamAV or OWASP ZAP are not installed or running, the app still works, but scan results will show `Scanner Unavailable` or another clear error message. This makes it easier to demo the full project structure before setting up external tools.
