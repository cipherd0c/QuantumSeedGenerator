#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cajoe_test.py — Testet, ob die Zerfallspulse des CAJOE-Boards am GPIO17
des Raspberry Pi 5 ankommen. Zeigt jeden Puls sofort an, dazu laufende
Statistik (Anzahl, CPM, Intervalle).

Installation (einmalig):  sudo apt install python3-lgpio
Aufruf:                   python3 cajoe_test.py          (Strg+C beendet)
Optional anderer Pin:     python3 cajoe_test.py --gpio 27
"""
import argparse
import sys
import time

try:
    import lgpio
except ImportError:
    print("Modul 'lgpio' fehlt:  sudo apt install python3-lgpio")
    sys.exit(1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gpio", type=int, default=17, help="BCM-Nummer (Standard 17)")
    ap.add_argument("--chip", type=int, default=None, help="gpiochip-Nummer erzwingen (sonst Autosuche)")
    args = ap.parse_args()

    chips = [args.chip] if args.chip is not None else list(range(0, 32))
    handle = None
    gefunden = None
    # rp1-Chip (54 Leitungen) bevorzugen
    geordnet = []
    for chip in chips:
        try:
            h = lgpio.gpiochip_open(chip)
        except Exception:
            continue
        try:
            label = str(lgpio.gpio_get_chip_info(h)).lower()
        except Exception:
            label = ""
        if "rp1" in label:
            geordnet.insert(0, (chip, h))
        else:
            geordnet.append((chip, h))
    for chip, h in geordnet:
        if handle is None:
            try:
                lgpio.gpio_claim_input(h, args.gpio, lgpio.SET_PULL_NONE)
                ruhe = lgpio.gpio_read(h, args.gpio)
                lgpio.gpio_free(h, args.gpio)
                edge = lgpio.RISING_EDGE if ruhe == 0 else lgpio.FALLING_EDGE
                lgpio.gpio_claim_alert(h, args.gpio, edge, lgpio.SET_PULL_NONE)
                handle, gefunden = h, chip
                richtung = "steigende" if ruhe == 0 else "fallende"
                print(f"GPIO{args.gpio} auf gpiochip{chip} belegt (Ruhepegel {ruhe}, "
                      f"lausche auf {richtung} Flanken) — warte auf Pulse …")
                continue
            except Exception:
                pass
        try: lgpio.gpiochip_close(h)
        except Exception: pass
    if handle is None:
        print(f"FEHLER: GPIO{args.gpio} konnte nicht belegt werden (belegt? falscher Pin?).")
        sys.exit(2)

    ereignisse = []
    t_start = time.monotonic()

    DEBOUNCE_NS = 30_000_000   # 30 ms: mehrere Flanken eines Klick-Bursts = 1 Ereignis
    def cb(chip, gpio, level, ts_ns):
        if ereignisse and ts_ns - ereignisse[-1] < DEBOUNCE_NS:
            return
        ereignisse.append(ts_ns)
        n = len(ereignisse)
        el = time.monotonic() - t_start
        cpm = n / el * 60 if el > 0 else 0
        if n >= 2:
            dt = (ereignisse[-1] - ereignisse[-2]) / 1e9
            print(f"  PULS #{n:<4d}  Abstand {dt:7.2f} s   laufende CPM: {cpm:5.1f}")
        else:
            print(f"  PULS #{n:<4d}  (erster Puls nach {el:.1f} s)")

    cbh = lgpio.callback(handle, args.gpio, edge, cb)
    print("Test laeuft. Jeder Klick des Boards muss hier als Zeile erscheinen.")
    print("Beenden mit Strg+C — dann folgt die Auswertung.\n")

    try:
        while True:
            time.sleep(1)
            el = time.monotonic() - t_start
            if not ereignisse and el > 90:
                print("\n⚠ 90 s ohne Puls — klickt das Board? Verkabelung/Teiler/GND pruefen!")
                t_start = time.monotonic()  # Meldung nicht dauerwiederholen
    except KeyboardInterrupt:
        pass
    finally:
        try:
            cbh.cancel(); lgpio.gpiochip_close(handle)
        except Exception:
            pass

    # ---- Auswertung ----
    dauer = time.monotonic() - t_start
    n = len(ereignisse)
    print("\n" + "=" * 52)
    print(f" Auswertung: {n} Pulse in {dauer/60:.1f} min")
    if n >= 2:
        cpm = n / dauer * 60
        deltas = [(b - a) / 1e9 for a, b in zip(ereignisse, ereignisse[1:])]
        print(f" Rate:            {cpm:.1f} CPM")
        print(f" Intervalle:      min {min(deltas):.2f} s | Mittel {sum(deltas)/len(deltas):.2f} s | max {max(deltas):.2f} s")
        # Grobe Plausibilitaet: Zerfall = unregelmaessig
        if len(set(round(d, 2) for d in deltas)) < max(2, len(deltas) // 4):
            print(" ⚠ Intervalle auffaellig gleichmaessig — Stoerquelle statt Zerfall?")
        else:
            print(" ✔ Intervalle unregelmaessig — sieht nach echtem Zerfall aus.")
        if 10 <= cpm <= 60:
            print(" ✔ Rate im erwarteten Bereich fuer Hintergrundstrahlung.")
        elif cpm < 10:
            print(" ⚠ Rate niedrig — Poti/Roehre pruefen (Ziel 15-30 CPM).")
        else:
            print(" ⚠ Rate hoch — Strahlungsquelle in der Naehe oder Fehlpulse?")
    elif n == 1:
        print(" Nur 1 Puls — laenger laufen lassen.")
    else:
        print(" Keine Pulse erkannt. Checkliste:")
        print("  1. Klickt das Board hoerbar? (Wenn nein: Board/Poti-Problem)")
        print("  2. Gemeinsame Masse Pi<->Teiler<->CAJOE verbunden?")
        print("  3. GPIO17 am KNOTEN des Teilers (nicht am CAJOE-VIN direkt)?")
        print("  4. Am Knoten bei Puls ~2,5 V messbar?")
    print("=" * 52)

if __name__ == "__main__":
    main()
