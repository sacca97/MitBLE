# MitBLE

MitBLE is a Bluetooth Low Energy (BLE) security research tool. It uses the
[Sniffle](https://github.com/nccgroup/Sniffle) radio platform on compatible TI CC13xx/CC26xx hardware to capture BLE traffic and run a link-layer Man-in-the-Middle (MitM).

The MitM uses two radios from the `mitble` Python process. One radio connects to the real BLE peripheral. The other copies that peripheral and accepts the real central's connection. MitBLE then forwards packets between both links.

> Use MitBLE only with devices and networks that you own or have permission to test.

## Requirements

- Python 3.9 or newer
- PySerial: `python3 -m pip install pyserial`
- Two Sniffle-compatible devices for MitM
- Sniffle firmware flashed on each radio

Compatible radios include TI CC1352/CC26x2 LaunchPads, the SONOFF CC2652P USB
Dongle Plus, and the CatSniffer v3. 

To build firmware from source, install the ARM GNU toolchain and TI SimpleLink Low Power F2 SDK 8.30.01.01, then run:

```sh
make -C fw
```

For a non-default board, pass a platform listed in `fw/makefile`, for example:

```sh
make -C fw PLATFORM=CC1352P74
```

## Capture BLE traffic

Run commands from the repository root. Set the serial port for your radio:

```sh
python3 python_cli/sniff_receiver.py -s /dev/ttyACM0
```

Capture one device by MAC address and write a PCAP file:

```sh
python3 python_cli/sniff_receiver.py \
  -s /dev/ttyACM0 \
  -m AA:BB:CC:DD:EE:FF \
  -o capture.pcap
```

Use `-i IRK` instead of `-m MAC` for a device that uses resolvable private
addresses. Run the script with `--help` to see all capture options.

## Run the relay

Connect two flashed radios and identify their serial ports. Then select the
target with exactly one of `--mac`, `--irk`, or `--string`:

```sh
python3 python_cli/mitble.py \
  --central-port /dev/ttyACM0 \
  --peripheral-port /dev/ttyACM1 \
  --mac AA:BB:CC:DD:EE:FF \
  --output relay.pcap \
  --quiet
```

`--central-port` is the radio that connects to the real peripheral.
`--peripheral-port` is the radio that copies the target and accepts the real
central's connection. The ports must be different.

Useful relay options:

- `--public`: treat the supplied MAC address as public
- `--preload INTERVAL:DELTA`: preload an encrypted connection update
- `--knob [KEY_SIZE]`: enable the KNOB experiment; the default key size is 7
- `--blerp`: enable the BLERP experiment
- `--no-decode`: reduce relay-side processing
- `--output FILE`: save relayed traffic as PCAP

Run `python3 python_cli/mitble.py --help` for the full option list. Press
Ctrl+C to stop capture or relay mode.

## License

See [LICENSE](LICENSE).
