import json
import os
import time

from nvd_importer import get_nvd_service_entries

# ── Paths to data files ────────────────────────────────────────────────────────
_BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
_HEURISTICS_PATH = os.path.join(_BASE_DIR, "data", "heuristics.json")

# ── Risk level → numeric score mapping ────────────────────────────────────────
_RISK_LEVEL_SCORE = {
    "low":      2,
    "medium":   5,
    "high":     7,
    "critical": 9,
}

_PORT_WEIGHT = {
    21: 1.2,    # FTP
    23: 1.4,    # Telnet
    25: 1.2,    # SMTP
    53: 1.1,    # DNS
    80: 1.0,    # HTTP
    8000: 1.05, # Alt HTTP
    8080: 1.1,  # Proxy/Alt HTTP
    443: 0.9,   # HTTPS
    8443: 1.0,  # Alt HTTPS
    445: 1.4,   # SMB
    3306: 1.2,  # MySQL
    3389: 1.6,  # RDP
    5432: 1.1,  # PostgreSQL
    5900: 1.1,  # VNC
}

_SERVICE_THREAT = {
    "ftp": "Credential Theft",
    "telnet": "Remote Command Hijacking",
    "smb": "Remote Code Execution",
    "http": "Man-in-the-Middle (MITM)",
    "https": "TLS Misconfiguration Abuse",
    "ssh": "Unauthorized Remote Access",
    "rdp": "Remote Service Takeover",
    "mysql": "Database Compromise",
    "postgresql": "Database Compromise",
    "dns": "DNS Poisoning/Abuse",
    "smtp": "Mail Relay Abuse",
    "vnc": "Remote Desktop Takeover",
    "snmp": "Network Device Enumeration",
}

_SERVICE_ATTACK_TYPE = {
    "ftp": "Brute Force",
    "telnet": "RCE",
    "smb": "RCE",
    "http": "MITM",
    "https": "MITM",
    "ssh": "Brute Force",
    "rdp": "Brute Force",
    "mysql": "Enumeration",
    "postgresql": "Enumeration",
    "dns": "Enumeration",
    "smtp": "Enumeration",
    "vnc": "Brute Force",
    "snmp": "Enumeration",
}

_NVD_CACHE = {
    "feed": None,
    "fetched_at": 0.0,
    "entries": [],
}


def _load_json(path: str) -> list:
    with open(path, "r") as f:
        return json.load(f)


def _get_severity_label(score: float) -> str:
    if score >= 8:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def _build_explanation(service: str, heuristic: dict | None, cve: dict | None) -> str:
    parts = []

    if heuristic:
        parts.append(heuristic["description"])

    if cve:
        parts.append(
            f"Linked to {cve['cve_id']} (CVSS {cve['cvss']}): {cve['description']}"
        )

    if not parts:
        return f"Port running '{service}' has no matched rules; treated as low risk."

    return " | ".join(parts)


def _build_structured_explanation(service: str, heuristic: dict | None, cve: dict | None) -> dict:
    threat = _SERVICE_THREAT.get(service, "Service Exposure Risk")
    cause = heuristic["description"] if heuristic else f"Exposed {service} service detected on a reachable port."

    if cve:
        impact = f"Potential exploitation aligned with {cve['cve_id']} may lead to confidentiality, integrity, or availability loss."
    else:
        impact = "Increased attack surface and potential lateral movement opportunities."

    return {
        "threat": threat,
        "cause": cause,
        "impact": impact,
    }


def _build_attack_type(service: str, cve: dict | None) -> str:
    if cve:
        description = cve.get("description", "").lower()
        if any(keyword in description for keyword in ["remote code execution", "rce", "command injection"]):
            return "RCE"
        if any(keyword in description for keyword in ["man-in-the-middle", "mitm", "path traversal", "session hijacking"]):
            return "MITM"
        if any(keyword in description for keyword in ["brute force", "credential", "password", "authentication bypass"]):
            return "Brute Force"
        if any(keyword in description for keyword in ["enumeration", "disclosure", "information disclosure", "reconnaissance"]):
            return "Enumeration"

    return _SERVICE_ATTACK_TYPE.get(service, "Unknown")


def _build_ip_summary(scan_result: dict, findings: list) -> dict:
    if not findings:
        return {
            "aggregate_risk_score": 0.0,
            "weighted_risk_score": 0.0,
            "system_status": "LOW RISK",
            "aggregation_method": "maximum-risk",
            "attack_surface": {
                "total_open_ports": 0,
                "high_risk_ports": 0,
                "critical_risk_ports": 0,
            },
        }

    aggregate_risk = round(max(f["risk_score"] for f in findings), 2)
    system_status = f"{_get_severity_label(aggregate_risk)} RISK"

    weighted_sum = 0.0
    weight_total = 0.0
    for finding in findings:
        weight = _PORT_WEIGHT.get(finding["port"], 1.0)
        weighted_sum += finding["risk_score"] * weight
        weight_total += weight
    weighted_risk = round(weighted_sum / weight_total, 2) if weight_total else 0.0

    high_risk_ports = sum(1 for f in findings if f["risk_score"] >= 6)
    critical_risk_ports = sum(1 for f in findings if f["risk_score"] >= 8)

    return {
        "aggregate_risk_score": aggregate_risk,
        "weighted_risk_score": weighted_risk,
        "system_status": system_status,
        "aggregation_method": "maximum-risk",
        "attack_surface": {
            "total_open_ports": len(scan_result.get("ports", [])),
            "high_risk_ports": high_risk_ports,
            "critical_risk_ports": critical_risk_ports,
        },
    }


def _get_cve_data_from_nvd(feed: str = "recent", timeout: int = 60, force_refresh: bool = False) -> list:
    now = time.time()
    cache_valid = (
        not force_refresh
        and _NVD_CACHE["feed"] == feed
        and (now - _NVD_CACHE["fetched_at"]) < 3600
        and _NVD_CACHE["entries"]
    )

    if cache_valid:
        return _NVD_CACHE["entries"]

    entries = get_nvd_service_entries(feed=feed, timeout=timeout)
    _NVD_CACHE["feed"] = feed
    _NVD_CACHE["fetched_at"] = now
    _NVD_CACHE["entries"] = entries
    return entries


def sync_cve_cache(feed: str = "recent", timeout: int = 60) -> int:
    entries = _get_cve_data_from_nvd(feed=feed, timeout=timeout, force_refresh=True)
    return len(entries)


def analyze_risk(scan_result: dict, cve_feed: str = "recent", cve_timeout: int = 60) -> dict:
    heuristics = _load_json(_HEURISTICS_PATH)
    cve_data   = _get_cve_data_from_nvd(feed=cve_feed, timeout=cve_timeout)

    # Index both datasets by service name for O(1) lookup
    heuristic_map = {rule["service"].lower(): rule for rule in heuristics}
    cve_map        = {entry["service"].lower(): entry for entry in cve_data}

    findings = []

    for port_info in scan_result.get("ports", []):
        port    = port_info["port"]
        service = port_info["service"].lower()

        heuristic = heuristic_map.get(service)
        cve       = cve_map.get(service)

        # ── Score calculation ──────────────────────────────────────────────
        heuristic_score = _RISK_LEVEL_SCORE.get(heuristic["risk_level"], 0) if heuristic else None
        cvss_score      = cve["cvss"] if cve else None

        if heuristic_score is not None and cvss_score is not None:
            base_score = (0.4 * heuristic_score) + (0.6 * cvss_score)
            source_method = "hybrid"
        elif heuristic_score is not None:
            base_score = float(heuristic_score)
            source_method = "heuristic_only"
        elif cvss_score is not None:
            base_score = float(cvss_score)
            source_method = "cvss_only"
        else:
            base_score = 1.0
            source_method = "fallback"

        port_weight = _PORT_WEIGHT.get(port, 1.0)
        weighted_score = base_score * port_weight
        final_score = round(min(10.0, max(0.0, weighted_score)), 2)

        findings.append({
            "port":        port,
            "service":     service,
            "risk_score":  final_score,
            "severity":    _get_severity_label(final_score),
            "cve":         cve["cve_id"] if cve else None,
            "explanation": _build_explanation(service, heuristic, cve),
            "structured_explanation": _build_structured_explanation(service, heuristic, cve),
            "attack_type": _build_attack_type(service, cve),
            "risk_calculation": {
                "source_method": source_method,
                "heuristic_score": heuristic_score,
                "cvss_score": cvss_score,
                "base_score": round(base_score, 2),
                "port_weight": round(port_weight, 2),
                "final_score": final_score,
                "formula": "final_score = min(10, base_score * port_weight)",
                "base_formula": "base_score = 0.4 * heuristic_score + 0.6 * cvss_score (when both exist)",
            },
        })

    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    ip_summary = _build_ip_summary(scan_result, findings)

    return {
        "findings": findings,
        "ip_summary": ip_summary,
        "model": {
            "description": "Risk Score computed using heuristic/CVSS base score and port exposure weighting.",
            "formula": "base_score = 0.4 * heuristic + 0.6 * CVSS (fallbacks apply), final_score = min(10, base_score * port_weight)",
            "ip_aggregation": "Final Risk Score = max(port_score) [maximum-risk method]. Weighted baseline score is also reported for analysis.",
        },
    }