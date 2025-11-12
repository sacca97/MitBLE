#!/usr/bin/env python3
import sys
import termios
import tty
import serial

PORT = "/dev/ttyACM4"
BAUD = 115200  # as requested

def main():
    ser = None
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        ser = serial.Serial(PORT, BAUD, timeout=1)
        print(f"Opened {PORT} at {BAUD} baud.")
        print("Press 0 or 1 to send over serial. Press q (or Ctrl-C) to quit.")

        # Put terminal in raw mode for single-character reads
        tty.setraw(fd)

        while True:
            ch = sys.stdin.buffer.read(1)  # blocks for a single byte
            if not ch:
                continue  # just in case

            if ch in (b'0', b'1'):
                ser.write(ch)      # send exactly b'0' or b'1'
                ser.flush()
                print(f"\rSent {ch.decode()}", end="", flush=True)
            elif ch in (b'q', b'Q', b'\x03'):  # 'q' or Ctrl-C
                print("\nBye!")
                break
            # ignore everything else (arrow keys produce escape sequences, etc.)

    except serial.SerialException as e:
        print(f"Serial error: {e}")
    finally:
        # Restore terminal and close serial cleanly
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            pass
        if ser is not None:
            try:
                ser.close()
                print("Serial port closed.")
            except Exception:
                pass

if __name__ == "__main__":
    main()
