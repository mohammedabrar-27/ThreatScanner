# ThreatScanner

ThreatScanner is a BCA final year project built with Flask, Bootstrap, and SQLite. It allows users to register, log in, scan uploaded files with ClamAV, scan URLs with Nuclei, and review scan history from a dashboard.

## Features

- User registration, login, logout, and session management
- Password hashing with Werkzeug
- File malware scanning with ClamAV
- URL threat scanning with Nuclei
- SQLite database for user accounts and scan history
- File upload limits and input validation
- Automatic cleanup of uploaded files after scanning

## Project Structure

```text
ThreatScanner/
├── app.py
├── app_helpers.py
├── clamav_scanner.py
├── nuclei_scanner.py
├── requirements.txt
├── README.md
├── static/
│   └── css/
│       └── styles.css
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── history.html
│   ├── login.html
│   ├── register.html
│   ├── scan_url.html
│   └── upload_file.html
└── instance/
    └── database.db
```

## Setup

1. Install Python 3.11 or newer.
2. Create a virtual environment:

```powershell
python -m venv .venv
```

3. Install dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

4. Install ClamAV on Windows and make sure this exists:

```text
C:\Program Files\ClamAV\clamscan.exe
```

5. Download Nuclei on Windows and update the path in `app.py` if needed.

## Run

```powershell
cd "C:\Users\MOHAMMED ABRAR KHAN\OneDrive\Pictures\Documents\New project"
.\.venv\Scripts\python.exe app.py
```

Open:

- [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Notes

- Uploaded files are stored temporarily in the system temp folder for scanning and then deleted.
- The database stores usernames, emails, password hashes, filenames or URLs, scan results, details, and timestamps.
- Full uploaded file content is not permanently stored in SQLite.
