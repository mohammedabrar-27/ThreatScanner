import sqlite3
from datetime import datetime

from flask import flash, g, session


def get_db(database_path):
    if "db" not in g:
        g.db = sqlite3.connect(database_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db():
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(database_path):
    db = sqlite3.connect(database_path)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()
    db.close()


def query_one(database_path, query, params=()):
    return get_db(database_path).execute(query, params).fetchone()


def query_all(database_path, query, params=()):
    return get_db(database_path).execute(query, params).fetchall()


def execute(database_path, query, params=()):
    db = get_db(database_path)
    db.execute(query, params)
    db.commit()


def save_scan(database_path, scan_type, target, result):
    execute(
        database_path,
        "INSERT INTO scan_history (user_id, scan_type, target, result, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            session["user_id"],
            scan_type,
            target,
            result["status"],
            result["details"],
            datetime.utcnow().isoformat(timespec="seconds"),
        ),
    )


def enrich_scan_result(scan_type, target, result):
    status = result["status"]
    details = (result.get("details") or "").strip()
    lines = [line.strip() for line in details.splitlines() if line.strip()]
    engine = "ClamAV" if scan_type == "file" else "Nuclei"

    tone_map = {
        "Clean": "safe",
        "Safe": "safe",
        "Medium Risk": "warning",
        "High Risk": "danger",
        "Malware Detected": "danger",
        "Scanner Unavailable": "warning",
        "Scan Error": "warning",
        "Scan Timeout": "warning",
        "Invalid URL": "danger",
    }
    verdict_map = {
        "Clean": "Clean",
        "Safe": "Safe",
        "Medium Risk": "Use With Caution",
        "High Risk": "Threat Detected",
        "Malware Detected": "Threat Detected",
        "Scanner Unavailable": "Scan Could Not Be Completed",
        "Scan Error": "Scan Could Not Be Completed",
        "Scan Timeout": "Use With Caution",
        "Invalid URL": "Invalid URL",
    }
    summary_map = {
        "Clean": "No known malware indicators were found in the uploaded file.",
        "Safe": "No immediate security concerns were identified for this URL during the current scan.",
        "Medium Risk": "Suspicious or incomplete findings mean this target should be handled carefully before use.",
        "High Risk": "Strong suspicious findings were detected and the target should be treated as unsafe.",
        "Malware Detected": "The uploaded file triggered malware detection and should not be opened or shared.",
        "Scanner Unavailable": f"{engine} was not available to complete this scan.",
        "Scan Error": f"{engine} could not complete the scan because of a technical error.",
        "Scan Timeout": "The scan took longer than expected, so the target should be handled carefully until reviewed again.",
        "Invalid URL": "The submitted URL is not valid for scanning.",
    }
    recommendation_map = {
        "Clean": ["Keep the file isolated until final review is complete.", "Verify the sender or download source before opening widely."],
        "Safe": ["Use the URL normally, but keep basic browsing caution.", "Run a deeper manual review if the link becomes business-critical."],
        "Medium Risk": ["Review the findings manually before using the target.", "Avoid sharing the target until the suspicious indicators are understood."],
        "High Risk": ["Do not open or distribute the target further.", "Escalate the target for immediate manual investigation."],
        "Malware Detected": ["Quarantine the file immediately.", "Run an additional scan before deciding on deletion or recovery."],
        "Scanner Unavailable": ["Confirm the scanner path and installation.", "Retry the scan once the security engine is available."],
        "Scan Error": ["Retry after restarting the scan engine.", "Capture the raw output if the same failure happens again."],
        "Scan Timeout": ["Treat the target cautiously until it is rescanned.", "Verify the source manually before opening or trusting it."],
        "Invalid URL": ["Check that the URL starts with http:// or https://.", "Avoid shortened or malformed links in the scan box."],
    }
    impact_map = {
        "Clean": ["No immediate harmful behavior was detected in this file during the scan."],
        "Safe": ["No immediate harmful behavior was detected for this URL during the scan."],
        "Medium Risk": ["This target may contain suspicious behavior, hidden redirects, or incomplete scan findings.", "Opening or trusting it too quickly could expose the device or user data to avoidable risk."],
        "High Risk": ["This target may expose the device, browser session, or sensitive data to malicious behavior.", "It could lead to unsafe downloads, data theft, or compromise if trusted."],
        "Malware Detected": ["This file may infect the device, damage data, or steal information if opened.", "It should be treated as harmful until security review is complete."],
        "Scanner Unavailable": ["The scan could not be completed, so the real threat level is still unknown."],
        "Scan Error": ["The scan ended unexpectedly, so the target should not be trusted yet."],
        "Scan Timeout": ["The scan took longer than expected, so hidden risk may still exist."],
        "Invalid URL": ["The entered address could not be checked, so no trust decision should be made from this scan."],
    }

    return {
        **result,
        "engine": engine,
        "target": target,
        "tone": tone_map.get(status, "warning"),
        "verdict": verdict_map.get(status, "Review Required"),
        "summary": summary_map.get(status, f"{engine} completed the scan for {target}."),
        "highlights": lines[:4] or ["No detailed highlights were returned by the scanner."],
        "recommendations": recommendation_map.get(status, ["Review the scan details and retry if needed."]),
        "impact": impact_map.get(status, ["Review the target carefully before trusting it."]),
        "raw_details": details or "No raw scanner details were returned.",
    }


def flash_result(label, status):
    category = "success" if status in {"Clean", "Safe"} else "warning"
    text = f"{label} completed successfully." if category == "success" else f"{label} finished with status: {status}"
    flash(text, category)


def format_scans(rows):
    scans = []
    for row in rows:
        item = dict(row)
        item["created_at_display"] = datetime.fromisoformat(item["created_at"]).strftime("%d %b %Y %I:%M %p")
        scans.append(item)
    return scans
