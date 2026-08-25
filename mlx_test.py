#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mlx_test.py — Testaufnahme MLX90640 als ASCII-Waermebild in der Konsole.

Installation (einmalig, auf dem Pi):
    sudo apt install python3-pip i2c-tools
    pip3 install adafruit-circuitpython-mlx90640 --break-system-packages

Aufruf:
    python3 mlx_test.py            # Live-Ansicht, Strg+C beendet
    python3 mlx_test.py --einmal   # nur eine Aufnahme
"""
import sys
import time

try:
    import board, busio
    import adafruit_mlx90640
except ImportError as e:
    print("Fehlendes Modul:", e)
    print("Bitte installieren:  pip3 install adafruit-circuitpython-mlx90640 --break-system-packages")
    sys.exit(1)

PALETTE = " .:-=+*#%@"      # kalt -> heiss
COLS, ROWS = 32, 24

def zeige_frame(frame):
    lo, hi = min(frame), max(frame)
    span = max(0.1, hi - lo)
    print("\033[H\033[2J", end="")          # Bildschirm loeschen
    print(f"MLX90640 Testbild   min {lo:5.1f} °C   max {hi:5.1f} °C   "
          f"Spanne {span:4.1f} K")
    print("─" * (COLS * 2))
    for r in range(ROWS):
        zeile = ""
        for c in range(COLS):
            t = frame[r * COLS + c]
            idx = int((t - lo) / span * (len(PALETTE) - 1))
            zeile += PALETTE[idx] * 2       # doppelt fuer ~quadratische Pixel
        print(zeile)
    print("─" * (COLS * 2))
    print("Tipp: Hand vor den Sensor halten — sie erscheint als @/#-Fläche.")

def main():
    einmal = "--einmal" in sys.argv
    i2c = busio.I2C(board.SCL, board.SDA, frequency=400000)
    mlx = adafruit_mlx90640.MLX90640(i2c)
    print("Seriennummer:", [hex(x) for x in mlx.serial_number])
    mlx.refresh_rate = adafruit_mlx90640.RefreshRate.REFRESH_2_HZ
    frame = [0.0] * (COLS * ROWS)
    while True:
        try:
            mlx.getFrame(frame)
        except ValueError:
            continue                        # gelegentliche Lesefehler: neu versuchen
        zeige_frame(frame)
        if einmal:
            break
        time.sleep(0.2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBeendet.")
    except OSError as e:
        print(f"\nI2C-Fehler: {e}\nPruefen: i2cdetect -y 1  (Adresse 0x33?), Verkabelung, I2C aktiviert?")
        sys.exit(2)
