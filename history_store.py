import json
import os
from datetime import datetime, timezone
from tempfile import NamedTemporaryFile
from threading import Lock
from typing import Any


_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_HISTORY_PATH = os.path.join(_BASE_DIR, "data", "history.json")
_IO_LOCK = Lock()


def _ensure_history_file() -> None:
    os.makedirs(os.path.dirname(_HISTORY_PATH), exist_ok=True)
    if not os.path.exists(_HISTORY_PATH):
        with open(_HISTORY_PATH, "w", encoding="utf-8") as file:
            json.dump({}, file, indent=2)


def _safe_load() -> dict[str, Any]:
    _ensure_history_file()
    try:
        with open(_HISTORY_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {}


def _safe_write(data: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(_HISTORY_PATH), exist_ok=True)
    with NamedTemporaryFile("w", delete=False, dir=os.path.dirname(_HISTORY_PATH), encoding="utf-8") as temp:
        json.dump(data, temp, indent=2)
        temp.flush()
        temp_name = temp.name
    os.replace(temp_name, _HISTORY_PATH)


def _normalize_host_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {"favourite": False, "scans": []}

    favourite = bool(record.get("favourite", False))
    scans = record.get("scans", [])
    if not isinstance(scans, list):
        scans = []

    normalized_scans = []
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        timestamp = str(scan.get("timestamp", "")).strip()
        ports = scan.get("ports", [])
        if not isinstance(ports, list):
            ports = []

        normalized_ports = []
        for port_entry in ports:
            if not isinstance(port_entry, dict):
                continue
            port = port_entry.get("port")
            risk = port_entry.get("risk")
            score = port_entry.get("score")
            if not isinstance(port, int):
                continue
            if not isinstance(risk, int):
                continue
            normalized = {"port": port, "risk": max(0, min(4, risk))}
            if isinstance(score, (int, float)):
                normalized["score"] = round(float(score), 2)
            normalized_ports.append(normalized)

        if timestamp:
            normalized_scans.append({"timestamp": timestamp, "ports": normalized_ports})

    return {"favourite": favourite, "scans": normalized_scans}


def _risk_bucket(finding: dict[str, Any]) -> int:
    severity = str(finding.get("severity", "")).upper()
    severity_map = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    if severity in severity_map:
        return severity_map[severity]

    score = finding.get("risk_score", 0)
    try:
        value = float(score)
    except (TypeError, ValueError):
        value = 0

    if value >= 8:
        return 4
    if value >= 6:
        return 3
    if value >= 3:
        return 2
    return 1


def _build_scan_ports(findings: list[dict[str, Any]]) -> list[dict[str, int]]:
    ports = []
    for finding in findings:
        port = finding.get("port")
        if not isinstance(port, int):
            continue
        risk_score = finding.get("risk_score")
        ports.append({
            "port": port,
            "risk": _risk_bucket(finding),
            "score": round(float(risk_score), 2) if isinstance(risk_score, (int, float)) else None,
        })
    return ports


def _append_scan(record: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    record["scans"].append({
        "timestamp": timestamp,
        "ports": _build_scan_ports(findings),
    })
    record["scans"] = record["scans"][-5:]


def get_host_history(host: str) -> dict[str, Any]:
    with _IO_LOCK:
        data = _safe_load()
        record = _normalize_host_record(data.get(host))
        return {
            "ip": host,
            "favourite": record["favourite"],
            "scans": record["scans"][-5:],
        }


def list_favourites() -> list[str]:
    with _IO_LOCK:
        data = _safe_load()
        favourites = []
        for host, raw_record in data.items():
            record = _normalize_host_record(raw_record)
            if record["favourite"]:
                favourites.append(host)
        return sorted(favourites)


def set_or_toggle_favourite(host: str, value: bool | None = None) -> bool:
    with _IO_LOCK:
        data = _safe_load()
        record = _normalize_host_record(data.get(host))

        if value is None:
            record["favourite"] = not record["favourite"]
        else:
            record["favourite"] = bool(value)

        data[host] = record
        _safe_write(data)
        return record["favourite"]


def record_scan_if_favourite(host: str, findings: list[dict[str, Any]]) -> bool:
    with _IO_LOCK:
        data = _safe_load()
        record = _normalize_host_record(data.get(host))

        if not record["favourite"]:
            data[host] = record
            _safe_write(data)
            return False

        _append_scan(record, findings)

        data[host] = record
        _safe_write(data)
        return True


def save_scan_for_host(host: str, findings: list[dict[str, Any]]) -> bool:
    with _IO_LOCK:
        data = _safe_load()
        record = _normalize_host_record(data.get(host))

        if not record["favourite"]:
            data[host] = record
            _safe_write(data)
            return False

        _append_scan(record, findings)
        data[host] = record
        _safe_write(data)
        return True
