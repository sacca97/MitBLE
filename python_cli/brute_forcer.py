from Crypto.Cipher import AES

def mask_ll_header_first_octet(hdr0: int) -> int:
    # Zero NESN, SN, MD bits (2,3,4)
    return hdr0 & ~0x1C


def ble_ccm_encrypt(key: bytes,
                    nonce: bytes,
                    header_first_octet: int,
                    payload: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt BLE LL payload + compute MIC using AES-CCM.

    Returns (ciphertext_payload, tag) where tag is the 4-byte MIC ciphertext
    (PyCryptodome returns the tag in plaintext form; on the air the tag is XORed
    with S0 keystream, but for analysis you normally stay at the CCM level).
    """
    assert len(key) == 16
    assert 7 <= len(nonce) <= 13      # BLE uses 13
    masked = mask_ll_header_first_octet(header_first_octet)

    cipher = AES.new(key,
                     AES.MODE_CCM,
                     nonce=nonce,
                     mac_len=4)       # BLE MIC length
    cipher.update(bytes([masked]))    # AAD = masked header first octet

    ciphertext = cipher.encrypt(payload)
    tag = cipher.digest()             # 4-byte MIC (plaintext CCM tag)
    return ciphertext, tag

def make_ble_ccm_nonce(iv: bytes, packet_counter: int, direction_bit: int) -> bytes:
    """
    Construct the 13-byte BLE CCM nonce.

    Format (BT Core v5.4, Vol 6, Part E, 2.1):
        Nonce[0]  = packetCounter[7:0]
        Nonce[1]  = packetCounter[15:8]
        Nonce[2]  = packetCounter[23:16]
        Nonce[3]  = packetCounter[31:24]
        Nonce[4]  = bit7: directionBit
                    bits6..0: packetCounter[38:32]
        Nonce[5]  = IV[7:0]
        ...
        Nonce[12] = IV[63:56]

    Args:
        packet_counter: 39-bit packetCounter (0..(1<<39)-1), incremented per
                        *encrypted* data PDU in this direction.
        direction_bit : 0 or 1. Spec: usually 0 = master→slave, 1 = slave→master.
        iv            : 8-byte IV (little-endian as defined by the spec:
                        IV[7:0], IV[15:8], ..., IV[63:56]).

    Returns:
        13-byte nonce suitable for AES-CCM with BLE.
    """
    if not (0 <= packet_counter < (1 << 39)):
        raise ValueError("packet_counter must fit in 39 bits")
    if direction_bit not in (0, 1):
        raise ValueError("direction_bit must be 0 or 1")
    if len(iv) != 8:
        raise ValueError("iv must be exactly 8 bytes")

    # Lower 32 bits of packetCounter
    n0 = (packet_counter >> 0) & 0xFF
    n1 = (packet_counter >> 8) & 0xFF
    n2 = (packet_counter >> 16) & 0xFF
    n3 = (packet_counter >> 24) & 0xFF

    # Upper 7 bits of packetCounter + direction in MSB
    pc_high7 = (packet_counter >> 32) & 0x7F
    n4 = pc_high7 | (direction_bit << 7)

    return bytes([n0, n1, n2, n3, n4]) + iv


def make_ble_ccm_counter_block(nonce: bytes, block_index: int) -> bytes:
    """
    Construct the 16-byte AES-CTR counter block A_i used by AES-CCM in BLE.

    In CCM, keystream blocks S_i are:
        S_i = AES_K(A_i)

    For BLE:
        - nonce is 13 bytes
        - L = 2 (size of counter field in bytes)
        - flags for A_i are 0b000000(L-1), so 0x01

    A_i format:
        A_i[0]      = flags (0x01 in BLE)
        A_i[1..13]  = nonce[0..12]
        A_i[14..15] = counter i, big-endian (0..65535)

    This is used for:
        - i = 0 → S0 (encrypt MIC)
        - i = 1,2,... → S1, S2,... (encrypt payload blocks)
    """
    if len(nonce) != 13:
        raise ValueError("nonce must be exactly 13 bytes for BLE CCM")
    if not (0 <= block_index <= 0xFFFF):
        raise ValueError("block_index must fit in 16 bits (0..65535)")

    L = 15 - len(nonce)   # BLE => 2
    flags = (L - 1)       # BLE => 0x01
    
    ctr_msb = (block_index >> 8) & 0xFF  # A[14]
    ctr_lsb = block_index & 0xFF         # A[15]

    return bytes([flags]) + nonce + bytes([ctr_msb, ctr_lsb])

def compute_mic_ble_raw_with_lib(key: bytes,
                                 nonce: bytes,
                                 header_first_octet: int,
                                 payload: bytes) -> bytes:
    """
    Return the *raw* 4-byte MIC (CBC-MAC output before S0 XOR),
    using the CCM implementation + one extra AES-ECB call.
    """
    assert len(key) == 16
    assert len(nonce) == 13

    aad = bytes([mask_ll_header_first_octet(header_first_octet)])

    # Run CCM to get the (encrypted) tag
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(aad)
    cipher.encrypt(payload)
    tag = cipher.digest()  # encrypted MIC

    # Recompute S0 = AES_K(A0)
    L = 15 - len(nonce)  # BLE => L == 2
    flags = (L - 1)      # for BLE this is 0x01
    a0 = bytes([flags]) + nonce + (0).to_bytes(L, "big")
    s0 = AES.new(key, AES.MODE_ECB).encrypt(a0)

    # raw_mac = tag XOR S0[0:4]
    raw_mic = bytes(tag[i] ^ s0[i] for i in range(4))
    return raw_mic
    

def ble_ccm_decrypt_verify(key: bytes,
                           nonce: bytes,
                           header_first_octet: int,
                           ciphertext: bytes,
                           tag: bytes) -> bytes:
    """
    Decrypt and verify BLE LL payload using AES-CCM.
    Raises ValueError if MIC check fails.
    """
    assert len(key) == 16
    assert len(tag) == 4
    masked = mask_ll_header_first_octet(header_first_octet)

    cipher = AES.new(key,
                     AES.MODE_CCM,
                     nonce=nonce,
                     mac_len=4)
    cipher.update(bytes([masked]))

    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)   # raises if MIC invalid
    return plaintext


from Crypto.Cipher import AES

# you already have these:
# - mask_ll_header_first_octet
# - make_ble_ccm_nonce
# - ble_ccm_encrypt
# - compute_mic_ble_raw_with_lib

def compute_mic_from_encrypted_ll_start_enc_rsp(
        key: bytes,
        iv_c2p: bytes,
        enc_pdu: bytes
    ) -> tuple[bytes, bytes, bytes]:
    """
    Compute the 4-byte MIC for an encrypted LL_START_ENC_RSP Data PDU.

    key    : 16-byte session key for Central -> Peripheral
    iv_c2p : 8-byte IV for Central -> Peripheral (from LL_ENC_REQ/RSP)
    enc_pdu: LL Data PDU without CRC:
             [hdr0, hdr1, encrypted_opcode+MIC, ...]

    Returns (tag_ccm, raw_mic, enc_mic_from_pdu):
      - tag_ccm          : 4-byte CCM tag from AES-CCM (on-air MIC if nonce correct)
      - raw_mic          : 4-byte CBC-MAC output before XOR with S0
      - enc_mic_from_pdu : 4-byte MIC extracted from the encrypted PDU
    """
    assert len(key) == 16
    assert len(iv_c2p) == 8
    if len(enc_pdu) < 2:
        raise ValueError("PDU too short")

    hdr0   = enc_pdu[0]
    length = enc_pdu[1]
    payload = enc_pdu[2:2+length]  # encrypted opcode + MIC

    if len(payload) < 5:
        raise ValueError(f"Encrypted payload too short: {len(payload)}")

    enc_opcode       = payload[0:1]
    enc_mic_from_pdu = payload[1:5]

    # First encrypted C->P packet in this direction:
    nonce = make_ble_ccm_nonce(iv_c2p, packet_counter=0, direction_bit=1)

    # Plaintext payload for LL_START_ENC_RSP is just opcode 0x06
    plain_payload = b"\x06"

    # 1) CCM tag via AES-CCM (this is the on-air MIC)
    _, tag_ccm = ble_ccm_encrypt(
        key=key,
        nonce=nonce,
        header_first_octet=hdr0,
        payload=plain_payload,
    )

    # 2) Raw MIC (CBC-MAC) using your helper
    raw_mic = compute_mic_ble_raw_with_lib(
        key=key,
        nonce=nonce,
        header_first_octet=hdr0,
        payload=plain_payload,
    )

    return tag_ccm, raw_mic, enc_mic_from_pdu

