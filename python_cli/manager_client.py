# manager_client.py
import json
import socket
import threading
from typing import Optional

class ManagerClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._enabled = False
        self._error_logged = False

    def connect(self):
        """Call once at startup (optional). Failure is non-fatal."""
        try:
            s = socket.create_connection((self.host, self.port), timeout=1.0)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock = s
            self._enabled = True
            print(f"[MANAGER] Connected to manager at {self.host}:{self.port}")
        except OSError as e:
            print(f"[MANAGER] Could not connect to manager at {self.host}:{self.port}: {e}")
            self._enabled = False

    def _send(self, ev: dict):
        """Low-level: send a JSON event. Safe if manager is absent."""
        if not self._enabled:
            return
        line = (json.dumps(ev) + "\n").encode("utf-8")
        with self._lock:
            if self._sock is None:
                return
            try:
                self._sock.sendall(line)
            except OSError as e:
                if not self._error_logged:
                    print(f"[MANAGER] Error sending to manager: {e}")
                    self._error_logged = True
                # disable further attempts
                self._enabled = False
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    # ===== High-level semantic helpers =====

    def report_link_devices(self,
                            central_addr: str,
                            central_type: str,
                            periph_addr: str,
                            periph_type: str):
        self._send({
            "type": "link_devices",
            "central_addr": central_addr,
            "central_addr_type": central_type,
            "periph_addr": periph_addr,
            "periph_addr_type": periph_type,
        })

    def report_pairing_params(self,
                              key_size_bytes: int,
                              auth_req: int,
                              sc: bool,
                              mitm: bool,
                              bonding: bool):
        self._send({
            "type": "pairing_params",
            "key_size_bytes": key_size_bytes,
            "auth_req": auth_req,
            "sc": sc,
            "mitm": mitm,
            "bonding": bonding,
        })

    def report_pairing_complete(self, direction: str = "PtoC"):
        self._send({
            "type": "pairing_complete",
            "direction": direction,
        })

    def report_enc_material(self, skd_known: bool, iv_known: bool):
        self._send({
            "type": "enc_material",
            "skd_known": skd_known,
            "iv_known": iv_known,
        })

    def report_attack_data_ready(self,
                                 exp_dir: str,
                                 attack_path: str,
                                 key_size_bytes: int):
        self._send({
            "type": "attack_data_ready",
            "exp_dir": exp_dir,
            "attack_path": attack_path,
            "key_size_bytes": key_size_bytes,
        })
