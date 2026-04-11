import argparse
import gzip
import json
import re
from pathlib import Path

import requests


BASE_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

# Map CPE product names (and aliases) to scanner service names.
PRODUCT_TO_SERVICE = {
    "apache_http_server": "http",
    "nginx": "http",
    "internet_information_services": "http",
    "tomcat": "http",
    "openssl": "https",
    "openvpn": "https",
    "openssh": "ssh",
    "dropbear": "ssh",
    "microsoft_remote_desktop": "rdp",
    "remote_desktop": "rdp",
    "mysql": "mysql",
    "mariadb": "mysql",
    "postgresql": "postgresql",
    "postfix": "smtp",
    "exim": "smtp",
    "opensmtpd": "smtp",
    "bind": "dns",
    "windows_dns_server": "dns",
    "samba": "smb",
    "microsoft_server_message_block": "smb",
    "vsftpd": "ftp",
    "proftpd": "ftp",
    "wu-ftpd": "ftp",
    "telnetd": "telnet",
    "realvnc": "vnc",
    "tightvnc": "vnc",
    "ultravnc": "vnc",
    "net-snmp": "snmp",
    "snmpd": "snmp",
}

# Fallback keyword matching from description text.
DESCRIPTION_KEYWORDS = {
    "ftp": "ftp",
    "telnet": "telnet",
    "smb": "smb",
    "http": "http",
    "https": "https",
    "ssl": "https",
    "tls": "https",
    "ssh": "ssh",
    "rdp": "rdp",
    "remote desktop": "rdp",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "dns": "dns",
    "smtp": "smtp",
    "vnc": "vnc",
    "snmp": "snmp",
}


def _feed_url(feed: str) -> str:
    return f"{BASE_FEED_URL}/nvdcve-2.0-{feed}.json.gz"


def _download_feed(feed: str, timeout: int) -> dict:
    url = _feed_url(feed)
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()

    decompressed = gzip.decompress(response.content)
    return json.loads(decompressed.decode("utf-8"))


def _pick_cvss_score(metrics: dict) -> float | None:
    ordered_keys = [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    best = None
    for key in ordered_keys:
        for metric in metrics.get(key, []):
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            if isinstance(score, (int, float)):
                best = float(score) if best is None else max(best, float(score))

    return best


def _extract_english_description(descriptions: list[dict]) -> str:
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"].strip()
    return "No description provided by NVD."


def _service_from_cpe_match(match_string: str) -> str | None:
    # CPE 2.3 format example: cpe:2.3:a:apache:apache_http_server:2.4.58:*:*:*:*:*:*:*
    if not match_string.startswith("cpe:2.3:"):
        return None

    parts = match_string.split(":")
    if len(parts) < 6:
        return None

    vendor = parts[3].lower()
    product = parts[4].lower()
    candidates = [product, f"{vendor}_{product}"]

    for candidate in candidates:
        if candidate in PRODUCT_TO_SERVICE:
            return PRODUCT_TO_SERVICE[candidate]

    return None


def _extract_services(vuln: dict, description: str) -> set[str]:
    services: set[str] = set()

    configurations = vuln.get("cve", {}).get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                service = _service_from_cpe_match(criteria)
                if service:
                    services.add(service)

    if services:
        return services

    lowered = description.lower()
    for keyword, service in DESCRIPTION_KEYWORDS.items():
        if re.search(rf"\b{re.escape(keyword)}\b", lowered):
            services.add(service)

    return services


def _build_service_best_entries(feed_data: dict) -> list[dict]:
    service_best: dict[str, dict] = {}

    for vuln in feed_data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        description = _extract_english_description(cve.get("descriptions", []))
        cvss = _pick_cvss_score(cve.get("metrics", {}))
        if cvss is None:
            continue

        services = _extract_services(vuln, description)
        for service in services:
            current = service_best.get(service)
            if current is None or cvss > current["cvss"]:
                service_best[service] = {
                    "service": service,
                    "cve_id": cve_id,
                    "cvss": round(cvss, 1),
                    "description": description,
                }

    return sorted(service_best.values(), key=lambda x: x["service"])


def get_nvd_service_entries(feed: str = "recent", timeout: int = 60) -> list[dict]:
    feed_data = _download_feed(feed, timeout=timeout)
    return _build_service_best_entries(feed_data)


def export_nvd_feed(feed: str = "recent", timeout: int = 60, out_path: Path | None = None) -> tuple[int, Path]:
    if out_path is None:
        raise ValueError("out_path is required for export_nvd_feed.")

    target_path = out_path
    entries = get_nvd_service_entries(feed=feed, timeout=timeout)

    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)

    return len(entries), target_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Download NVD JSON 2.0 feed and extract service-level CVE mappings. "
            "No file is written unless --out is provided."
        )
    )
    parser.add_argument(
        "--feed",
        default="recent",
        help=(
            "Feed name: 'recent', 'modified', or a year like '2024'. "
            "Default: recent"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="HTTP timeout in seconds for feed download (default: 60).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional output JSON path. If omitted, no file is created.",
    )
    args = parser.parse_args()

    entries = get_nvd_service_entries(feed=args.feed, timeout=args.timeout)
    print(f"Fetched {len(entries)} service-level CVE entries from NVD feed '{args.feed}'.")

    if args.out is not None:
        count, output_file = export_nvd_feed(
            feed=args.feed,
            timeout=args.timeout,
            out_path=args.out,
        )
        print(f"Saved to: {output_file}")
    else:
        print("No file written. Use --out <path> to export.")


if __name__ == "__main__":
    main()
