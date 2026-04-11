import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from time import perf_counter
from urllib.parse import urlparse
import ipaddress
import re

from scanner import scan_target
from risk_engine import analyze_risk, sync_cve_cache
from history_store import (
    get_host_history,
    list_favourites,
    record_scan_if_favourite,
    save_scan_for_host,
    set_or_toggle_favourite,
)
from utils.port_simulator import PortSimulator

app = Flask(__name__)
CORS(app)

_PORT_SIMULATOR = None


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(localhost|(?!-)[a-zA-Z0-9-]{1,63}(?<!-)|(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+(?:[A-Za-z]{2,63}))$"
)


def _normalize_scan_host(raw_target: str) -> str:
    target = raw_target.strip()
    if not target:
        raise ValueError("Field 'target' is required.")

    if "," in target:
        raise ValueError("Only a single target is supported. Comma-separated targets are not allowed.")

    # Reject CIDR/range-like inputs explicitly.
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", target):
        raise ValueError("CIDR ranges are not supported. Provide one IP, domain, or URL.")

    # Allow URL-like input without scheme, e.g. example.com/login.
    if "://" not in target and "/" in target:
        target = f"http://{target}"

    parsed = urlparse(target if "://" in target else f"//{target}")
    host = parsed.hostname or target

    if not host:
        raise ValueError("Could not extract a host from the provided target.")

    # Validate IPv4/IPv6 directly.
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # Validate domain/hostname forms.
    if not _HOSTNAME_RE.match(host):
        raise ValueError(
            "Target must be a valid IP, domain, or URL (for example: 192.168.1.10, example.com, or https://example.com)."
        )

    return host.lower()


def start_port_simulator() -> PortSimulator:
    global _PORT_SIMULATOR

    if _PORT_SIMULATOR is None:
        ports = os.environ.get("HECTOR_SIMULATOR_PORTS", "8000,8080,8443,5432,3306")
        interval_min = int(os.environ.get("HECTOR_SIMULATOR_INTERVAL_MIN", "10"))
        interval_max = int(os.environ.get("HECTOR_SIMULATOR_INTERVAL_MAX", "20"))

        parsed_ports = []
        for value in ports.split(","):
            value = value.strip()
            if not value:
                continue
            try:
                parsed_ports.append(int(value))
            except ValueError:
                continue

        if not parsed_ports:
            parsed_ports = [8000, 8080, 8443, 5432, 3306]

        if interval_min <= 0 or interval_max <= 0 or interval_min > interval_max:
            interval_min, interval_max = 10, 20

        _PORT_SIMULATOR = PortSimulator(
            port_list=parsed_ports,
            interval_range=(interval_min, interval_max),
        )
        _PORT_SIMULATOR.start_background()

    return _PORT_SIMULATOR


@app.route("/", methods=["GET"])
def health_check():
    return jsonify({"message": "API running"}), 200


@app.route("/scan", methods=["POST"])
def scan():
    # ── 1. Parse incoming JSON ──────────────────────────────────────────────
    body = request.get_json(silent=True)

    if not body:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    raw_target = str(body.get("target", body.get("ip", ""))).strip()
    cve_feed = str(body.get("cve_feed", "recent")).strip().lower() or "recent"
    cve_timeout = body.get("cve_timeout", 60)

    # ── 2. Basic input validation ───────────────────────────────────────────
    try:
        scan_host = _normalize_scan_host(raw_target)
    except ValueError as validation_error:
        return jsonify({"error": str(validation_error)}), 400

    allowed_feeds = {"recent", "modified"}
    if not (cve_feed in allowed_feeds or cve_feed.isdigit()):
        return jsonify({
            "error": "Invalid 'cve_feed'. Use 'recent', 'modified', or a year such as '2024'."
        }), 400

    try:
        cve_timeout = int(cve_timeout)
        if cve_timeout <= 0:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({"error": "'cve_timeout' must be a positive integer."}), 400

    # ── 3. Pipeline execution ───────────────────────────────────────────────
    try:
        start_time = perf_counter()

        # Step A: Scan the target
        scan_result = scan_target(scan_host)

        # Step B: Analyse risk from scan data
        risk_report = analyze_risk(scan_result, cve_feed=cve_feed, cve_timeout=cve_timeout)

        # Step C: Persist scan to temporal history only for favourited hosts
        was_recorded = record_scan_if_favourite(scan_host, risk_report["findings"])
        favourite = get_host_history(scan_host)["favourite"]

        # Step D: Build and return the final response
        scan_time = round(perf_counter() - start_time, 2)
        return jsonify({
            "target": raw_target,
            "scan_host": scan_host,
            "favourite": favourite,
            "history_recorded": was_recorded,
            "results": risk_report["findings"],
            "ip_summary": risk_report["ip_summary"],
            "model": risk_report["model"],
            "performance": {
                "scan_time_seconds": scan_time,
            },
        }), 200

    except NotImplementedError as nie:
        # Raised intentionally by placeholder modules during development
        return jsonify({"error": f"Module not yet implemented: {str(nie)}"}), 501

    except Exception as exc:
        # Catch-all for unexpected failures (Nmap not found, bad data, etc.)
        return jsonify({"error": f"Scan failed: {str(exc)}"}), 500


@app.route("/favourite", methods=["POST"])
def toggle_favourite():
    body = request.get_json(silent=True) or {}
    raw_target = str(body.get("target", body.get("ip", ""))).strip()

    try:
        scan_host = _normalize_scan_host(raw_target)
    except ValueError as validation_error:
        return jsonify({"error": str(validation_error)}), 400

    explicit_value = body.get("favourite", None)
    if explicit_value is not None and not isinstance(explicit_value, bool):
        return jsonify({"error": "'favourite' must be a boolean when provided."}), 400

    updated = set_or_toggle_favourite(scan_host, explicit_value)
    return jsonify({
        "ip": scan_host,
        "favourite": updated,
    }), 200


@app.route("/favourites", methods=["GET"])
def get_favourites():
    favourites = list_favourites()
    return jsonify({"favourites": favourites}), 200


@app.route("/history/<path:host>", methods=["GET"])
def get_history(host: str):
    try:
        scan_host = _normalize_scan_host(host)
    except ValueError:
        # Also allow already-normalized host values passed directly.
        scan_host = host.strip().lower()

    history = get_host_history(scan_host)
    return jsonify(history), 200


@app.route("/history/save", methods=["POST"])
def save_current_scan_to_history():
    body = request.get_json(silent=True) or {}
    raw_target = str(body.get("target", body.get("ip", ""))).strip()
    findings = body.get("findings", [])

    try:
        scan_host = _normalize_scan_host(raw_target)
    except ValueError as validation_error:
        return jsonify({"error": str(validation_error)}), 400

    if not isinstance(findings, list):
        return jsonify({"error": "'findings' must be an array."}), 400

    saved = save_scan_for_host(scan_host, findings)
    return jsonify({
        "ip": scan_host,
        "saved": saved,
    }), 200


@app.route("/cve/sync", methods=["POST"])
def sync_cve_data():
    body = request.get_json(silent=True) or {}
    feed = str(body.get("feed", "recent")).strip().lower() or "recent"
    timeout = body.get("timeout", 60)

    allowed_feeds = {"recent", "modified"}
    if not (feed in allowed_feeds or feed.isdigit()):
        return jsonify({
            "error": "Invalid 'feed'. Use 'recent', 'modified', or a year such as '2024'."
        }), 400

    try:
        timeout = int(timeout)
        if timeout <= 0:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({"error": "'timeout' must be a positive integer."}), 400

    try:
        count = sync_cve_cache(feed=feed, timeout=timeout)
        return jsonify({
            "message": "Live NVD CVE cache synchronized successfully.",
            "feed": feed,
            "entries_imported": count,
        }), 200
    except Exception as exc:
        return jsonify({"error": f"CVE sync failed: {str(exc)}"}), 500


if __name__ == "__main__":
    # debug=True is fine for local development; disable in production
    start_port_simulator()
    app.run(debug=True, host="0.0.0.0", port=5000)