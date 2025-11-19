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
