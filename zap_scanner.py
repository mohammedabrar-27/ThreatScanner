from time import sleep, time
from urllib.parse import urlparse

import requests


def _normalize_base_url(base_url):
    return base_url.rstrip("/")


def _parse_risk_level(alerts):
    highest_risk = "Safe"
    ranking = {"Low": 1, "Medium": 2, "High": 3}

    for alert in alerts:
        risk = alert.get("risk", "")
        if ranking.get(risk, 0) > ranking.get(highest_risk, 0):
            highest_risk = risk

    if highest_risk == "High":
        return "High Risk"
    if highest_risk == "Medium":
        return "Medium Risk"
    if highest_risk == "Low":
        return "Safe"
    return "Safe"


def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def scan_url_with_zap(target_url, api_url, api_key="", timeout_seconds=180):
    if not validate_url(target_url):
        return {
            "status": "Invalid URL",
            "details": "Enter a valid URL starting with http:// or https://.",
        }

    base_url = _normalize_base_url(api_url)
    headers = {"X-ZAP-API-Key": api_key} if api_key else {}

    try:
        response = requests.get(f"{base_url}/JSON/core/view/version/", headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        return {
            "status": "Scanner Unavailable",
            "details": f"OWASP ZAP is not reachable at {base_url}: {exc}",
        }

    try:
        spider_response = requests.get(
            f"{base_url}/JSON/spider/action/scan/",
            params={"url": target_url, "recurse": "true"},
            headers=headers,
            timeout=15,
        )
        spider_response.raise_for_status()

        active_response = requests.get(
            f"{base_url}/JSON/ascan/action/scan/",
            params={"url": target_url, "recurse": "true", "inScopeOnly": "false"},
            headers=headers,
            timeout=15,
        )
        active_response.raise_for_status()
        scan_id = active_response.json().get("scan")
    except requests.RequestException as exc:
        return {
            "status": "Scan Error",
            "details": f"Unable to start the ZAP scan: {exc}",
        }

    if not scan_id:
        return {
            "status": "Scan Error",
            "details": "OWASP ZAP did not return a scan identifier.",
        }

    deadline = time() + timeout_seconds
    while time() < deadline:
        try:
            status_response = requests.get(
                f"{base_url}/JSON/ascan/view/status/",
                params={"scanId": scan_id},
                headers=headers,
                timeout=10,
            )
            status_response.raise_for_status()
            progress = int(status_response.json().get("status", "0"))
            if progress >= 100:
                break
        except (requests.RequestException, ValueError):
            break
        sleep(2)
    else:
        return {
            "status": "Scan Timeout",
            "details": "OWASP ZAP did not complete the scan in time.",
        }

    try:
        alerts_response = requests.get(
            f"{base_url}/JSON/core/view/alerts/",
            params={"baseurl": target_url},
            headers=headers,
            timeout=15,
        )
        alerts_response.raise_for_status()
        alerts = alerts_response.json().get("alerts", [])
    except requests.RequestException as exc:
        return {
            "status": "Scan Error",
            "details": f"Unable to fetch ZAP alerts: {exc}",
        }

    status = _parse_risk_level(alerts)
    if alerts:
        detail_lines = [
            f"{alert.get('risk', 'Unknown')}: {alert.get('alert', 'Unnamed alert')}"
            for alert in alerts[:10]
        ]
        details = "\n".join(detail_lines)
    else:
        details = "No notable alerts were reported by OWASP ZAP."

    return {"status": status, "details": details}
