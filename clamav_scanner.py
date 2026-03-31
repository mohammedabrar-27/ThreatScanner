import shutil
import subprocess
from pathlib import Path


WINDOWS_CANDIDATES = [
    Path("C:/Program Files/ClamAV/clamscan.exe"),
    Path("C:/Program Files/ClamAV/clamdscan.exe"),
    Path.home() / "Downloads",
]
WINDOWS_DATABASE_DIR = Path("C:/Program Files/ClamAV/database")


def resolve_clamav(command):
    if command:
        candidate = Path(command)
        if candidate.exists():
            return str(candidate)
        found = shutil.which(command)
        if found:
            return found

    for candidate in WINDOWS_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
        if candidate.is_dir():
            for exe in candidate.rglob("clamscan.exe"):
                return str(exe)
            for exe in candidate.rglob("clamdscan.exe"):
                return str(exe)

    return None


def build_scan_command(executable, file_path):
    command = [executable, "--no-summary"]
    if WINDOWS_DATABASE_DIR.exists():
        command.append(f"--database={WINDOWS_DATABASE_DIR}")
    command.append(str(file_path))
    return command


def scan_file_with_clamav(file_path, command="clamscan", timeout_seconds=30):
    path = Path(file_path)
    executable = resolve_clamav(command)
    if not executable:
        return {
            "status": "Scanner Unavailable",
            "details": "ClamAV was not found on Windows. Install it or set CLAMAV_COMMAND.",
        }

    try:
        result = subprocess.run(
            build_scan_command(executable, path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "Medium Risk",
            "details": f"ClamAV did not finish scanning within {timeout_seconds} seconds. Treat the file cautiously and rescan it before trusting or sharing it.",
        }
    except OSError as exc:
        return {
            "status": "Scan Error",
            "details": f"Failed to execute ClamAV: {exc}",
        }

    output = (result.stdout or result.stderr or "").strip()

    if "Can't open file" in output and ": 225" in output:
        return {
            "status": "Malware Detected",
            "details": "Windows blocked access to the file during scanning, which usually indicates the EICAR or another detected threat signature was triggered.",
        }

    if result.returncode == 0:
        return {
            "status": "Clean",
            "details": output or "No threats were detected by ClamAV.",
        }

    if result.returncode == 1:
        return {
            "status": "Malware Detected",
            "details": output or "ClamAV reported an infected file.",
        }

    if result.returncode == 2:
        return {
            "status": "Scanner Unavailable",
            "details": output or "ClamAV could not complete the scan. Check that the Windows virus database is installed and healthy.",
        }

    return {
        "status": "Scan Error",
        "details": output or f"ClamAV exited with status code {result.returncode}.",
    }
