from clamav_scanner import scan_file_with_clamav
from zap_scanner import scan_url_with_zap


def run_file_scan(file_path, command):
    return scan_file_with_clamav(file_path, command=command)


def run_url_scan(target_url, api_url, api_key="", timeout_seconds=180):
    return scan_url_with_zap(
        target_url,
        api_url=api_url,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
    )
