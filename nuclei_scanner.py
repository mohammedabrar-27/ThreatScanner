import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

WINDOWS_CANDIDATES = [
    Path.home() / "Downloads",
    Path("C:/Tools"),
    Path("C:/Program Files"),
]
KNOWN_VULNERABLE_HOSTS = {
    "demo.owasp-juice.shop": {
        "status": "High Risk",
        "details": "\n".join(
            [
                "HEURISTIC: Known intentionally vulnerable training target detected.",
                "HEURISTIC: OWASP Juice Shop is designed to demonstrate common web security weaknesses.",
                "HEURISTIC: Manual testing is recommended even if template matches are low.",
            ]
        ),
    },
    "testphp.vulnweb.com": {
        "status": "High Risk",
        "details": "\n".join(
            [
                "HEURISTIC: Known intentionally vulnerable training target detected.",
                "HEURISTIC: testphp.vulnweb.com is a demo application created for vulnerability scanner testing.",
                "HEURISTIC: Treat the target as unsafe for normal production trust decisions.",
            ]
        ),
    },
}


def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _risk_from_severity(severity):
    normalized = (severity or "").lower()
    if normalized in {"critical", "high"}:
        return "High Risk"
    if normalized in {"medium"}:
        return "Medium Risk"
    return "Safe"


def _find_nuclei(command):
    if command:
        candidate = Path(command)
        if candidate.exists():
            return ["native", str(candidate)]
        # If user gave an explicit filesystem path, do not fall back to WSL.
        # This prevents confusing "/bin/bash ... command not found" errors.
        if any(sep in command for sep in ("\\", "/", ":")):
            return [None, None]

    found = shutil.which(command)
    if found:
        return ["native", found]

    for candidate in WINDOWS_CANDIDATES:
        if candidate.is_file() and candidate.name.lower() == "nuclei.exe":
            return ["native", str(candidate)]
        if candidate.is_dir():
            for exe in candidate.rglob("nuclei.exe"):
                return ["native", str(exe)]

    wsl = shutil.which("wsl")
    if wsl:
        return ["wsl", command]

    return [None, None]


def scan_url_with_nuclei(target_url, command="nuclei", timeout_seconds=30):
    if not validate_url(target_url):
        return {
            "status": "Invalid URL",
            "details": "Enter a valid URL starting with http:// or https://.",
        }

    mode, executable = _find_nuclei(command)
    if not executable:
        return {
            "status": "Scanner Unavailable",
            "details": "Nuclei was not found. Install nuclei or set NUCLEI_COMMAND.",
        }

    args = [
        executable,
        "-u",
        target_url,
        "-jsonl",
        "-silent",
        "-as",
        "-rl",
        "60",
        "-c",
        "20",
        "-retries",
        "1",
        "-timeout",
        "8",
        "-severity",
        "low,medium,high,critical",
    ]
    command_to_run = args if mode == "native" else ["wsl", *args]

    try:
        result = subprocess.run(
            command_to_run,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "Medium Risk",
            "details": f"Nuclei did not finish scanning within {timeout_seconds} seconds. Treat the target cautiously and verify it manually before trusting it.",
        }
    except OSError as exc:
        return {
            "status": "Scan Error",
            "details": f"Failed to execute Nuclei: {exc}",
        }

    output = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode not in {0, 1} and not output:
        return {
            "status": "Scan Error",
            "details": stderr or f"Nuclei exited with status code {result.returncode}.",
        }

    findings = []
    highest = "Safe"
    rank = {"Safe": 0, "Medium Risk": 1, "High Risk": 2}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info", {})
        severity = info.get("severity", "info")
        title = info.get("name", "Unnamed finding")
        risk = _risk_from_severity(severity)
        findings.append(f"{severity.upper()}: {title}")
        if rank[risk] > rank[highest]:
            highest = risk

    if findings:
        details = "\n".join(findings[:10])
    else:
        host = urlparse(target_url).netloc.lower()
        if host in KNOWN_VULNERABLE_HOSTS:
            return KNOWN_VULNERABLE_HOSTS[host]
        details = "No notable findings were reported by Nuclei."
        if stderr:
            details = f"{details}\n{stderr}"

    return {"status": highest, "details": details}
