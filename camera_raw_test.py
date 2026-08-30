#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mlx_raw_test.py — Zeigt EXAKT die Daten an, die der Seed-Generator verwendet.

Nutzt denselben Rohdaten-Pfad wie btc_seedgen.py (smbus2, RAM-Register 0x0400,
832 Worte pro Frame, unkalibriert — KEINE Adafruit-Bibliothek, keine °C-Werte).

Anzeige pro Frame:
  * Rohbild als ASCII-Heatmap (aus den unkalibrierten ADC-Werten normalisiert)
  * SHA-256 des Frames (genau der Wert, der in den Entropie-Pool eingeht)
  * Rausch-Analyse: wie viele Pixel haben sich zum Vorframe geaendert
    (das Flackern der unteren Bits IST die geerntete Entropie)

Aufruf:
  python3 mlx_raw_test.py            # Live, Strg+C beendet
  python3 mlx_raw_test.py --einmal   # nur ein Frame
Voraussetzung: sudo apt install python3-smbus2  (wie beim Seed-Generator)
"""
import argparse
import hashlib
import sys
import time

# --- identische Konstanten wie btc_seedgen.py -------------------------------
MLX_I2C_BUS  = 1
MLX_I2C_ADDR = 0x33
COLS, ROWS   = 32, 24          # 768 Pixel; RAM-Block enthaelt 832 Worte
PALETTE      = " .:-=+*#%@"

# --- identische Lesefunktion wie btc_seedgen.py -----------------------------
def _mlx_read_words(bus, reg: int, n_words: int) -> bytes:
    """16-Bit-Registeradresse schreiben, dann n_words*2 Bytes lesen."""
    from smbus2 import i2c_msg
    out = bytearray()
    CHUNK = 24
    off = 0
    while off < n_words:
        n = min(CHUNK, n_words - off)
        w = i2c_msg.write(MLX_I2C_ADDR, [(reg + off) >> 8, (reg + off) & 0xFF])
        r = i2c_msg.read(MLX_I2C_ADDR, n * 2)
        bus.i2c_rdwr(w, r)
        out += bytes(r)
        off += n
    return bytes(out)

def lese_frame(bus) -> bytes:
    """Wie in btc_seedgen.py: auf neues Frame warten, RAM lesen, Status loeschen."""
    from smbus2 import i2c_msg
    t0 = time.monotonic()
    while True:
        st = _mlx_read_words(bus, 0x8000, 1)
        if st[1] & 0x08:
            break
        if time.monotonic() - t0 > 5:
            print("FEHLER: Timeout beim Warten auf neues Frame (Adresse 0x33?).")
            sys.exit(2)
        time.sleep(0.02)
    frame = _mlx_read_words(bus, 0x0400, 832)
    wmsg = i2c_msg.write(MLX_I2C_ADDR, [0x80, 0x00, 0x00, 0x30])
    bus.i2c_rdwr(wmsg)
    return frame

# --- Anzeige -----------------------------------------------------------------
def worte(frame: bytes):
    """Rohbytes -> Liste von 16-Bit-Worten (signed, wie der ADC sie liefert)."""
    vals = []
    for i in range(0, len(frame), 2):
        v = (frame[i] << 8) | frame[i + 1]
        if v > 32767:
            v -= 65536
        vals.append(v)
    return vals

def zeige(frame: bytes, nr: int, vorher: bytes | None):
    vals = worte(frame)[:COLS * ROWS]          # die 768 Pixel des Bildes
    lo, hi = min(vals), max(vals)
    span = max(1, hi - lo)
    print("\033[H\033[2J", end="")
    print(f"MLX90640 ROHDATEN-Monitor (Seed-Generator-Pfad)   Frame #{nr}")
    print(f"Roh-ADC min {lo}  max {hi}  (unkalibriert, KEINE Temperaturen)")
    print("─" * (COLS * 2))
    for r in range(ROWS):
        zeile = ""
        for c in range(COLS):
            v = vals[r * COLS + c]
            idx = int((v - lo) / span * (len(PALETTE) - 1))
            zeile += PALETTE[idx] * 2
        print(zeile)
    print("─" * (COLS * 2))
    h = hashlib.sha256(frame).hexdigest()
    print(f"SHA-256 (geht so in den Entropie-Pool): {h}")
    print(f"Erste Rohworte: {frame[:12].hex()}")
    if vorher is not None:
        vv = worte(vorher)[:COLS * ROWS]
        geaendert = sum(1 for a, b in zip(vals, vv) if a != b)
        uniq = len(set(frame))
        print(f"Rausch-Analyse: {geaendert}/768 Pixel gegenueber Vorframe veraendert "
              f"({geaendert/768*100:.0f}%) · {uniq} verschiedene Bytewerte")
        if geaendert == 0:
            print("⚠ WARNUNG: identisch zum Vorframe — der Seed-Generator wuerde ABBRECHEN.")
        else:
            print("✔ Frames unterscheiden sich — dieses Flackern ist die Entropie.")
    print("Strg+C beendet.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--einmal", action="store_true")
    args = ap.parse_args()
    try:
        from smbus2 import SMBus
    except ImportError:
        print("Modul 'smbus2' fehlt:  sudo apt install python3-smbus2")
        sys.exit(1)
    try:
        bus = SMBus(MLX_I2C_BUS)
    except OSError as e:
        print(f"I2C-Bus {MLX_I2C_BUS} nicht verfuegbar: {e} (I2C aktiviert?)")
        sys.exit(2)
    vorher = None
    nr = 0
    try:
        while True:
            frame = lese_frame(bus)
            nr += 1
            zeige(frame, nr, vorher)
            vorher = frame
            if args.einmal:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        try: bus.close()
        except Exception: pass

if __name__ == "__main__":
    main()
