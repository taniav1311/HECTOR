"""
Controlled Port Simulation System
==================================
Dynamically opens and closes ports on localhost (127.0.0.1) to simulate
changing attack surface and enable temporal variation in security scans.

Features:
  - Independent and isolated from core scanning logic
  - Thread-safe state management
  - Graceful shutdown with Ctrl+C
  - Configurable port list and randomization intervals
  - Real HTTP servers for each port (fully bindable)

Usage:
  python port_simulator.py
  # Or programmatically:
  from utils.port_simulator import PortSimulator
  simulator = PortSimulator()
  simulator.start()
"""

import json
import logging
import os
import random
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from tempfile import NamedTemporaryFile
from typing import Dict, List, Set, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# ============================================================================
# HTTP REQUEST HANDLER
# ============================================================================

class SimulatorPortHandler(BaseHTTPRequestHandler):
    """
    Minimal HTTP request handler for simulated ports.
    Responds with a simple 200 OK to keep connections clean.
    """

    def do_GET(self):
        """Handle GET requests"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Port Simulator - Service Active')

    def do_HEAD(self):
        """Handle HEAD requests"""
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def log_message(self, format, *args):
        """Suppress default HTTP server logging (keep output clean)"""
        pass


# ============================================================================
# PORT SIMULATOR CLASS
# ============================================================================

class PortSimulator:
    """
    Controlled Port Simulation System for localhost (127.0.0.1)

    Manages a set of ports that randomly open and close at configurable
    intervals, simulating dynamic changes in attack surface. Integrates
    cleanly with HECTOR scanner.

    Attributes:
        port_list: List of ports available for simulation
        interval_range: Tuple of (min, max) seconds between state changes
        active_ports: Set of currently open ports
    """

    def __init__(
        self,
        port_list: List[int] = None,
        interval_range: Tuple[int, int] = (10, 20),
        max_open_ports: int = 7,
        state_path: str | None = None,
    ):
        """
        Initialize the Port Simulator.

        Args:
            port_list: List of ports to manage. Defaults to:
                      [8000, 8080, 8443, 5432, 3306]
            interval_range: Tuple of (min_seconds, max_seconds) between
                           random port state changes. Default: (10, 20)
            max_open_ports: Maximum number of ports that can be open at once.

        Example:
            >>> simulator = PortSimulator(
            ...     port_list=[8000, 8080, 9000],
            ...     interval_range=(5, 15)
            ... )
        """
        self.port_list = port_list or [8000, 8080, 8443, 5432, 3306]
        self.interval_range = interval_range
        self.max_open_ports = max(1, int(max_open_ports))
        self._project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.state_path = state_path or os.path.join(self._project_dir, "data", "port_simulator_state.json")

        # State tracking
        self.active_ports: Set[int] = set()
        self.servers: Dict[int, HTTPServer] = {}
        self.threads: Dict[int, threading.Thread] = {}

        # Control flags
        self.is_running = True
        self._stop_event = threading.Event()
        self._randomizer_thread: threading.Thread | None = None
        self.lock = threading.RLock()

        logger.info(f"Port Simulator initialized with ports: {self.port_list}")

    def _write_state_snapshot(self, action: str | None = None, port: int | None = None) -> None:
        with self.lock:
            payload = {
                "target": "127.0.0.1",
                "status": "running" if self.is_running else "stopped",
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "active_ports": sorted(self.active_ports),
                "available_ports": list(self.port_list),
                "interval_range": list(self.interval_range),
            }

            if action and port is not None:
                payload["last_event"] = {
                    "action": action,
                    "port": port,
                    "timestamp": payload["updated_at"],
                }

        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with NamedTemporaryFile("w", delete=False, dir=os.path.dirname(self.state_path), encoding="utf-8") as temp_file:
            json.dump(payload, temp_file, indent=2)
            temp_file.flush()
            temp_name = temp_file.name
        os.replace(temp_name, self.state_path)

    # ========================================================================
    # PORT MANAGEMENT
    # ========================================================================

    def open_port(self, port: int) -> bool:
        """
        Open a port by starting an HTTP server.

        Creates an HTTPServer listening on 127.0.0.1:port and runs it in
        a daemon thread. Safe to call multiple times (ignores already-open ports).

        Args:
            port: Port number to open (1-65535)

        Returns:
            bool: True if successfully opened, False if already open or error

        Raises:
            OSError: If port is already in use by another process
        """
        with self.lock:
            # Skip if already open
            if port in self.active_ports:
                return False

            if len(self.active_ports) >= self.max_open_ports:
                logger.info(f"[SKIP] Port {port} not opened because the simulator already has {self.max_open_ports} open ports")
                return False

            try:
                # Create and start HTTP server
                server = HTTPServer(('127.0.0.1', port), SimulatorPortHandler)
                
                server_thread = threading.Thread(
                    target=server.serve_forever,
                    daemon=True,
                    name=f"PortServer-{port}"
                )
                server_thread.start()

                # Track server and thread
                self.servers[port] = server
                self.threads[port] = server_thread
                self.active_ports.add(port)

                logger.info(f"[OPEN] Port {port} started")
                self._write_state_snapshot("open", port)
                return True

            except OSError as e:
                logger.error(f"[ERROR] Failed to open port {port}: {e}")
                return False

    def close_port(self, port: int) -> bool:
        """
        Close a port by shutting down the server.

        Gracefully shuts down the HTTP server and waits for the thread
        to terminate. Safe to call on non-existent ports (returns False).

        Args:
            port: Port number to close

        Returns:
            bool: True if successfully closed, False if not open or error
        """
        with self.lock:
            # Skip if not open
            if port not in self.active_ports:
                return False

            server = self.servers.pop(port, None)
            self.threads.pop(port, None)
            self.active_ports.discard(port)

        try:
            # Shut the server down outside the lock to avoid blocking other state changes.
            if server is not None:
                server.shutdown()
                server.server_close()

            logger.info(f"[CLOSE] Port {port} stopped")
            self._write_state_snapshot("close", port)
            return True

        except Exception as e:
            logger.error(f"[ERROR] Failed to close port {port}: {e}")
            return False

    # ========================================================================
    # STATE & LOGGING
    # ========================================================================

    def print_state(self) -> None:
        """
        Log the current state of all active ports.

        Called after each port change and at startup/shutdown for visibility.
        """
        with self.lock:
            sorted_ports = sorted(list(self.active_ports))
            logger.info(f"[STATE] Active ports: {sorted_ports}")

    def get_active_ports(self) -> List[int]:
        """
        Get a snapshot of currently active ports (thread-safe).

        Returns:
            List of open port numbers, sorted
        """
        with self.lock:
            return sorted(list(self.active_ports))

    # ========================================================================
    # RANDOMIZATION ENGINE
    # ========================================================================

    def _randomization_loop(self) -> None:
        """
        Main randomization loop (runs in background thread).

        Periodically chooses a random port from port_list and toggles it:
        - If open → close it
        - If closed → open it

        Interval between changes is random within interval_range.
        """
        while self.is_running and not self._stop_event.is_set():
            # Wait for random interval
            interval = random.randint(
                self.interval_range[0],
                self.interval_range[1]
            )
            if self._stop_event.wait(timeout=interval):
                break

            with self.lock:
                active_ports = list(self.active_ports)
                closed_ports = [port for port in self.port_list if port not in self.active_ports]

            should_close = bool(active_ports) and (
                len(active_ports) >= self.max_open_ports or random.random() < 0.55
            )

            if should_close:
                self.close_port(random.choice(active_ports))
            elif closed_ports:
                self.open_port(random.choice(closed_ports))
            elif active_ports:
                self.close_port(random.choice(active_ports))

            # Log state after change
            self.print_state()

    # ========================================================================
    # LIFECYCLE
    # ========================================================================

    def start(self) -> None:
        """
        Start the simulator and begin randomization.

        Blocks indefinitely (until Ctrl+C or shutdown() is called).
        Launches randomization in a background daemon thread.
        """
        logger.info("=" * 70)
        logger.info("HECTOR Port Simulator - Started")
        logger.info("=" * 70)
        logger.info(f"Target: 127.0.0.1")
        logger.info(f"Available ports: {self.port_list}")
        logger.info(
            f"Randomization interval: {self.interval_range[0]}-"
            f"{self.interval_range[1]} seconds"
        )
        logger.info("Press Ctrl+C to stop gracefully")
        logger.info("=" * 70)

        self._write_state_snapshot("start", None)

        self.start_background()

        # Keep main thread alive and responsive
        try:
            while self.is_running and not self._stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.shutdown()

    def start_background(self) -> threading.Thread:
        """Start the randomizer in a daemon thread without blocking."""
        if self._randomizer_thread and self._randomizer_thread.is_alive():
            return self._randomizer_thread

        self.is_running = True
        self._stop_event.clear()
        self._write_state_snapshot("start", None)

        self._randomizer_thread = threading.Thread(
            target=self._randomization_loop,
            daemon=True,
            name="PortRandomizer",
        )
        self._randomizer_thread.start()
        return self._randomizer_thread

    def shutdown(self, exit_process: bool = True) -> None:
        """
        Graceful shutdown - close all open ports and exit.

        Called on Ctrl+C or programmatically. Closes all servers, logs state,
        and exits cleanly.
        """
        logger.info("\n" + "=" * 70)
        logger.info("HECTOR Port Simulator - Shutdown in Progress")
        logger.info("=" * 70)

        # Signal threads to stop
        self.is_running = False
        self._stop_event.set()

        # Close all open ports
        with self.lock:
            ports_to_close = list(self.active_ports)

        for port in ports_to_close:
            self.close_port(port)

        logger.info("All ports closed successfully")
        logger.info("Simulator shutdown complete")
        logger.info("=" * 70)
        self._write_state_snapshot("stop", None)

        if exit_process:
            sys.exit(0)


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """
    Entry point for running the simulator as a standalone script.

    Configuration:
      - Ports: [8000, 8080, 8443, 5432, 3306]
      - Interval: 10-20 seconds between random state changes

    Can be customized by editing PORTS and INTERVAL variables below.
    """
    # Configuration
    PORTS = [8000, 8080, 8443, 5432, 3306]
    INTERVAL = (10, 20)  # seconds
    MAX_OPEN_PORTS = 7

    # Create simulator
    simulator = PortSimulator(port_list=PORTS, interval_range=INTERVAL, max_open_ports=MAX_OPEN_PORTS)

    # Handle Ctrl+C (SIGINT) gracefully
    signal.signal(signal.SIGINT, lambda sig, frame: simulator.shutdown())

    # Start the simulator (blocks indefinitely)
    simulator.start()


if __name__ == "__main__":
    main()
