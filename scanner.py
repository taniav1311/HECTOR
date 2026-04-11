import os

import nmap


WINDOWS_NMAP_PATHS = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)


def _init_port_scanner() -> nmap.PortScanner:
    try:
        return nmap.PortScanner()
    except nmap.PortScannerError:
        # Fallback for Windows machines where Nmap is installed but not in PATH.
        for exe_path in WINDOWS_NMAP_PATHS:
            if os.path.exists(exe_path):
                return nmap.PortScanner(nmap_search_path=(exe_path,))
        raise


def scan_target(ip: str) -> dict:
    try:
        nm = _init_port_scanner()
    except nmap.PortScannerError:
        raise Exception(
            "Nmap is not installed or not found in PATH. "
            "Install it from https://nmap.org/download.html and ensure it is accessible system-wide."
        )

    try:
        nm.scan(hosts=ip, arguments="-sS -sV")
    except Exception as e:
        # On some Windows setups SYN scan may require elevated privileges.
        if "administrator" in str(e).lower() or "requires root privileges" in str(e).lower():
            try:
                nm.scan(hosts=ip, arguments="-sT -sV")
            except Exception as retry_error:
                raise Exception(f"Scan execution failed: {str(retry_error)}")
        else:
            raise Exception(f"Scan execution failed: {str(e)}")

    # Host is down or did not respond
    if ip not in nm.all_hosts():
        return {"ip": ip, "ports": []}

    ports = []

    for proto in nm[ip].all_protocols():
        if proto != "tcp":
            continue
        for port in nm[ip][proto]:
            port_data = nm[ip][proto][port]
            if port_data.get("state") == "open":
                ports.append({
                    "port":    port,
                    "service": port_data.get("name", "unknown")
                })

    return {"ip": ip, "ports": ports}