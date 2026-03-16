import shutil
import subprocess
from pathlib import Path


def scan_file_with_clamav(file_path, command="clamscan"):
    path = Path(file_path)
    executable = shutil.which(command)
    if not executable:
        return {
            "status": "Scanner Unavailable",
            "details": f"ClamAV command '{command}' was not found on this system.",
        }

    try:
        result = subprocess.run(
            [executable, "--no-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "Scan Timeout",
            "details": "ClamAV did not finish scanning within the allowed time.",
        }
    except OSError as exc:
        return {
            "status": "Scan Error",
            "details": f"Failed to execute ClamAV: {exc}",
        }

    output = (result.stdout or result.stderr or "").strip()

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

    return {
        "status": "Scan Error",
        "details": output or f"ClamAV exited with status code {result.returncode}.",
    }
