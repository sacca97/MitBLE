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

from Crypto.Cipher import AES

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

