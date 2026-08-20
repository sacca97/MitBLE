#!/usr/bin/env python3
"""
Generate synthetic inputs for aes_bruteforcer_ble_asm.cu.

Modes:
  fast: current v2 masked AES-block/CTR-keystream filter
  ccm:  v3 authenticated BLE-CCM observations with encrypted MIC checks
"""

import argparse
import secrets
import subprocess
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None


def aes_block(key: bytes, block: bytes) -> bytes:
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES key and block must both be 16 bytes")
    if AES is not None:
        return AES.new(key, AES.MODE_ECB).encrypt(block)

    proc = subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-128-ecb",
            "-nosalt",
            "-nopad",
            "-K",
            key.hex(),
        ],
        input=block,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "AES backend unavailable: install pycryptodome or ensure openssl is on PATH"
        )
    if len(proc.stdout) != 16:
        raise RuntimeError("openssl AES backend returned an unexpected block size")
    return proc.stdout


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def parse_hex_payload(value: str) -> bytes:
    value = value.strip().lower()
    if len(value) == 0 or len(value) > 32 or len(value) % 2 != 0:
        raise ValueError("plaintext must be 1-16 bytes of hex")
    payload = bytes.fromhex(value)
    if len(payload) == 0 or len(payload) > 16:
        raise ValueError("plaintext must be 1-16 bytes")
    return payload


def ctr_block(nonce: bytes, counter: int) -> bytes:
    if len(nonce) != 13:
        raise ValueError("BLE CCM nonce must be 13 bytes")
    return b"\x01" + nonce + counter.to_bytes(2, "big")


def pad16(data: bytes) -> bytes:
    if len(data) > 16:
        raise ValueError("data must fit in one AES block")
    return data + b"\x00" * (16 - len(data))


def ccm_blocks_and_ciphertext(session_key: bytes, nonce: bytes, aad: int, plaintext: bytes):
    if not 0 <= aad <= 0xFF:
        raise ValueError("AAD must be one byte")
    if len(plaintext) == 0 or len(plaintext) > 16:
        raise ValueError("this generator supports 1-16 byte payloads")

    # CCM flags: Adata present | M=4 byte tag | L=2 byte length field.
    b0 = bytes([0x49]) + nonce + len(plaintext).to_bytes(2, "big")
    aad_block = b"\x00\x01" + bytes([aad]) + b"\x00" * 13
    plaintext_block = pad16(plaintext)
    a0 = ctr_block(nonce, 0)
    a1 = ctr_block(nonce, 1)

    mac = aes_block(session_key, b0)
    mac = aes_block(session_key, xor_bytes(mac, aad_block))
    mac = aes_block(session_key, xor_bytes(mac, plaintext_block))

    s0 = aes_block(session_key, a0)
    s1 = aes_block(session_key, a1)

    encrypted_payload = xor_bytes(plaintext, s1[: len(plaintext)])
    encrypted_mic = xor_bytes(mac[:4], s0[:4])
    keystream = xor_bytes(plaintext, encrypted_payload)

    return {
        "a1": a1,
        "keystream": pad16(keystream),
        "b0": b0,
        "aad_block": aad_block,
        "plaintext_block": plaintext_block,
        "a0": a0,
        "encrypted_payload": encrypted_payload,
        "encrypted_mic": encrypted_mic,
    }


def make_ltk(key_size: int) -> bytes:
    if key_size < 1 or key_size > 7:
        raise ValueError("key_size must be 1..7 for the current CUDA search")
    return b"\x00" * (16 - key_size) + secrets.token_bytes(key_size)


def obscure_key(key: bytes, key_size: int) -> str:
    visible = key[: 16 - key_size].hex()
    return visible + "XX" * key_size


def write_fast(path: Path, key_size: int, skd: bytes, block: bytes, target: bytes, payload_len: int):
    if len(block) != 16 or len(target) != 16 or len(skd) != 16:
        raise ValueError("invalid v2 fast record")
    path.write_bytes(bytes([key_size, payload_len]) + block + target + skd)


def write_ccm(path: Path, key_size: int, skd: bytes, observations):
    if len(observations) == 0 or len(observations) > 4:
        raise ValueError("v3 supports 1-4 observations")
    out = bytearray()
    out += b"BL3C"
    out += bytes([key_size, len(observations), 0, 0])
    out += skd
    for obs in observations:
        out += bytes([obs["payload_len"], 0, 0, 0])
        out += obs["a1"]
        out += obs["keystream"]
        out += obs["b0"]
        out += obs["aad_block"]
        out += obs["plaintext_block"]
        out += obs["a0"]
        out += obs["encrypted_mic"]
    path.write_bytes(bytes(out))


def main():
    parser = argparse.ArgumentParser(description="Generate BLE brute-force test data")
    parser.add_argument(
        "--mode",
        choices=("fast", "ccm"),
        default="ccm",
        help="Generate v2 fast-filter data or v3 authenticated BLE-CCM data",
    )
    parser.add_argument(
        "-k",
        "--key-size",
        type=int,
        default=3,
        help="Unknown trailing key bytes to brute force (1..7)",
    )
    parser.add_argument(
        "-pt",
        "--plaintext",
        default="06",
        help="Known payload plaintext as hex, default is LL_START_ENC_RSP opcode 06",
    )
    parser.add_argument(
        "--aad",
        default="03",
        help="One-byte BLE CCM AAD as hex, default is masked LL control header 03",
    )
    parser.add_argument(
        "--observations",
        type=int,
        default=2,
        help="Number of authenticated observations for ccm mode (1..4)",
    )
    parser.add_argument(
        "--out",
        default="attack.bin",
        help="Output attack-data file path",
    )

    args = parser.parse_args()

    try:
        key_size = args.key_size
        ltk = make_ltk(key_size)
        skd = secrets.token_bytes(16)
        session_key = aes_block(ltk, skd)
        plaintext = parse_hex_payload(args.plaintext)
        aad_bytes = bytes.fromhex(args.aad)
        if len(aad_bytes) != 1:
            raise ValueError("AAD must be exactly one byte")
        aad = aad_bytes[0]
        out_path = Path(args.out)

        observations = []
        count = 1 if args.mode == "fast" else args.observations
        if count < 1 or count > 4:
            raise ValueError("observations must be 1..4")

        for _ in range(count):
            nonce = secrets.token_bytes(13)
            blocks = ccm_blocks_and_ciphertext(session_key, nonce, aad, plaintext)
            blocks["payload_len"] = len(plaintext)
            blocks["nonce"] = nonce
            observations.append(blocks)

        if args.mode == "fast":
            first = observations[0]
            write_fast(
                out_path,
                key_size,
                skd,
                first["a1"],
                first["keystream"],
                len(plaintext),
            )
        else:
            write_ccm(out_path, key_size, skd, observations)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("\nTEST VECTOR")
    print("=" * 50)
    print(f"Mode:          {args.mode}")
    print(f"Output:        {out_path}")
    print(f"LTK:           {ltk.hex()}")
    print(f"Obscured LTK:  {obscure_key(ltk, key_size)}")
    print(f"Search space:  2^{key_size * 8}")
    print(f"SKD:           {skd.hex()}")
    print(f"Session key:   {session_key.hex()}")
    print(f"Plaintext:     {plaintext.hex()}")
    print(f"AAD:           {aad:02x}")
    for idx, obs in enumerate(observations, 1):
        print(f"Observation {idx}:")
        print(f"  Nonce:      {obs['nonce'].hex()}")
        print(f"  A1:         {obs['a1'].hex()}")
        print(f"  Keystream:  {obs['keystream'][:len(plaintext)].hex()}")
        print(f"  Encrypted:  {obs['encrypted_payload'].hex()}")
        print(f"  Enc MIC:    {obs['encrypted_mic'].hex()}")
    print("\nRun:")
    print(f"  ./aes_bruteforcer_ble_asm {out_path} 1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
