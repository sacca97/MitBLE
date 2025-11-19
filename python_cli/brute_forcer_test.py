# test_ble_ccm.py

import os
import secrets
from Crypto.Cipher import AES

from brute_forcer import (  # <-- change to your filename/module
    mask_ll_header_first_octet,
    ble_ccm_encrypt,
    ble_ccm_decrypt_verify,
    compute_mic_ble_raw_with_lib,
)


# ---------------------------------------------------------------------------
# 1. Sanity tests for the header masking
# ---------------------------------------------------------------------------

def test_mask_ll_header_bits_are_cleared():
    # NESN/SN/MD bits (2,3,4) must be cleared
    hdr = 0xFF
    masked = mask_ll_header_first_octet(hdr)
    # bits 4,3,2 are 0
    assert (masked & 0x1C) == 0
    # other bits remain
    assert (masked & 0b11100011) == 0b11100011


def test_mask_ll_header_invariance_for_nesn_sn_md():
    # Flipping NESN/SN/MD must NOT change the masked value
    base = 0b10000011  # LLID=3, bit7=1, bits2..4 arbitrary
    for lower_5 in range(0x20):  # all combos of bits0..4
        h1 = base | lower_5
        h2 = h1 ^ 0x1C  # flip bits 2..4
        assert mask_ll_header_first_octet(h1) == mask_ll_header_first_octet(h2)


# ---------------------------------------------------------------------------
# 2. Reference CCM wrapper using the *same* library directly
#    (to confirm that our wrapper passes the right parameters).
# ---------------------------------------------------------------------------

def lib_ccm_encrypt_direct(key, nonce, header_first_octet, payload):
    """Direct use of AES.MODE_CCM with BLE params, for comparison."""
    assert len(key) == 16
    assert len(nonce) == 13

    aad = bytes([mask_ll_header_first_octet(header_first_octet)])

    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(aad)
    ct = cipher.encrypt(payload)
    tag = cipher.digest()
    return ct, tag


# ---------------------------------------------------------------------------
# 3. Basic functional tests: encrypt/decrypt round-trip
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip_small():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    nonce = bytes.fromhex("0102030405060708090a0b0c0d")  # 13 bytes
    header_first_octet = 0b10101101
    payload = b"hello BLE!"

    ct, tag = ble_ccm_encrypt(key, nonce, header_first_octet, payload)
    pt = ble_ccm_decrypt_verify(key, nonce, header_first_octet, ct, tag)

    assert pt == payload


def test_encrypt_decrypt_roundtrip_random():
    for _ in range(50):
        key = secrets.token_bytes(16)
        nonce = secrets.token_bytes(13)
        header_first_octet = secrets.randbits(8)
        payload_len = secrets.randbelow(252)  # 0..251
        payload = os.urandom(payload_len)

        ct, tag = ble_ccm_encrypt(key, nonce, header_first_octet, payload)
        pt = ble_ccm_decrypt_verify(key, nonce, header_first_octet, ct, tag)

        assert pt == payload


# ---------------------------------------------------------------------------
# 4. Check that wrapper matches direct AES.MODE_CCM usage
# ---------------------------------------------------------------------------

def test_wrapper_matches_direct_ccm():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    # 13 bytes now:
    nonce = bytes.fromhex("0f0e0d0c0b0a09080706050403")
    header_first_octet = 0b01010101
    payload = bytes.fromhex("11223344556677889900aabbccddeeff00")

    ct_direct, tag_direct = lib_ccm_encrypt_direct(
        key, nonce, header_first_octet, payload
    )
    ct_wrap, tag_wrap = ble_ccm_encrypt(
        key, nonce, header_first_octet, payload
    )

    assert ct_wrap == ct_direct
    assert tag_wrap == tag_direct



# ---------------------------------------------------------------------------
# 5. Raw MIC tests: check that compute_mic_ble_raw_with_lib really undoes S0
# ---------------------------------------------------------------------------

def recover_raw_mic_manual(key, nonce, header_first_octet, payload):
    """
    "Manual" version: run CCM, get tag (T), recompute S0 and invert XOR.
    This should match compute_mic_ble_raw_with_lib.
    """
    # encrypted tag from direct CCM
    ct, tag = lib_ccm_encrypt_direct(key, nonce, header_first_octet, payload)

    # S0 = AES_K(A0)
    L = 15 - len(nonce)   # BLE => 2
    flags = (L - 1)       # BLE => 0x01
    a0 = bytes([flags]) + nonce + (0).to_bytes(L, "big")
    s0 = AES.new(key, AES.MODE_ECB).encrypt(a0)

    # raw_mic = tag XOR S0[0:4]
    return bytes(tag[i] ^ s0[i] for i in range(4))


def test_compute_mic_ble_raw_matches_manual():
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(13)
    header_first_octet = secrets.randbits(8)
    payload = b"some test payload bytes..."

    mic_raw_fn = compute_mic_ble_raw_with_lib(
        key, nonce, header_first_octet, payload
    )
    mic_raw_manual = recover_raw_mic_manual(
        key, nonce, header_first_octet, payload
    )

    assert mic_raw_fn == mic_raw_manual


def test_raw_mic_ignores_nesn_sn_md_bits():
    """
    MIC must depend on the masked header byte, so flipping NESN/SN/MD
    (bits 2,3,4) should not change the raw MIC.
    """
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(13)
    payload = b"AA" * 10

    base = secrets.randbits(8) & ~0x1C  # ensure bits 2..4 are 0
    hdr1 = base | 0b00000100      # NESN=1
    hdr2 = base | 0b00011000      # SN=1, MD=1

    mic1 = compute_mic_ble_raw_with_lib(key, nonce, hdr1, payload)
    mic2 = compute_mic_ble_raw_with_lib(key, nonce, hdr2, payload)

    assert mic1 == mic2


def test_raw_mic_changes_if_llid_changes():
    """
    Changing LLID bits (0 and 1) *should* affect the MIC,
    because those bits survive masking.
    """
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(13)
    payload = b"AA" * 10

    # same high bits, different LLID in low 2 bits
    hdr_llid_1 = 0b10000001  # LLID=01
    hdr_llid_2 = 0b10000010  # LLID=10

    mic1 = compute_mic_ble_raw_with_lib(key, nonce, hdr_llid_1, payload)
    mic2 = compute_mic_ble_raw_with_lib(key, nonce, hdr_llid_2, payload)

    # extremely unlikely they'd collide by chance
    assert mic1 != mic2


# ---------------------------------------------------------------------------
# 6. Integrity tests: verify fails if tag or ciphertext is modified
# ---------------------------------------------------------------------------

def test_decrypt_fails_on_tag_corruption():
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(13)
    header_first_octet = secrets.randbits(8)
    payload = b"MIC integrity test"

    ct, tag = ble_ccm_encrypt(key, nonce, header_first_octet, payload)

    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01  # flip one bit
    bad_tag = bytes(bad_tag)

    try:
        ble_ccm_decrypt_verify(key, nonce, header_first_octet, ct, bad_tag)
        assert False, "Expected MIC verification to fail"
    except ValueError:
        pass  # expected


def test_decrypt_fails_on_ciphertext_corruption():
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(13)
    header_first_octet = secrets.randbits(8)
    payload = b"MIC integrity test (ciphertext)"

    ct, tag = ble_ccm_encrypt(key, nonce, header_first_octet, payload)

    bad_ct = bytearray(ct)
    if len(bad_ct) == 0:
        return  # nothing to flip; degenerate case
    bad_ct[0] ^= 0x01
    bad_ct = bytes(bad_ct)

    try:
        ble_ccm_decrypt_verify(key, nonce, header_first_octet, bad_ct, tag)
        assert False, "Expected MIC verification to fail"
    except ValueError:
        pass  # expected


# ---------------------------------------------------------------------------
# 7. Optional: run as a script without pytest
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Just run the key tests with plain asserts
    test_mask_ll_header_bits_are_cleared()
    test_mask_ll_header_invariance_for_nesn_sn_md()
    test_encrypt_decrypt_roundtrip_small()
    test_encrypt_decrypt_roundtrip_random()
    test_wrapper_matches_direct_ccm()
    test_compute_mic_ble_raw_matches_manual()
    test_raw_mic_ignores_nesn_sn_md_bits()
    test_raw_mic_changes_if_llid_changes()
    test_decrypt_fails_on_tag_corruption()
    test_decrypt_fails_on_ciphertext_corruption()
    print("All tests passed.")
