#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gpio_decay_diagnose.py — Diagnose fuer den CAJOE-Zerfallszaehler.

Aendert NICHTS am System und erzeugt KEINEN Seed. Testet nacheinander alle
Kombinationen aus Pull-Widerstand (UP / NONE / DOWN) und Flanke
(FALLING / RISING / BOTH) und meldet, welche Kombination Pulse sieht.

    sudo python3 gpio_decay_diagnose.py             # 15 s pro Kombination
    sudo python3 gpio_decay_diagnose.py --sek 30    # laenger messen
    sudo python3 gpio_decay_diagnose.py --gpio 17

Bei niedriger Zaehlrate (< 20 CPM) sind 15 s knapp — dann --sek erhoehen.
"""
import argparse
import sys
import time

try:
    import lgpio
except ImportError:
    sys.exit("Modul 'lgpio' fehlt:  sudo apt install python3-lgpio")

DEBOUNCE_NS = 30_000_000   # identisch zum Hauptskript


def chips_auflisten():
    """Alle gpiochips mit Rohdaten von gpio_get_chip_info."""
    gefunden = []
    for n in range(0, 32):
        try:
            h = lgpio.gpiochip_open(n)
        except Exception:
            continue
        try:
            info = lgpio.gpio_get_chip_info(h)
        except Exception as e:
            info = f"<Fehler: {e}>"
        gefunden.append((n, h, info))
    return gefunden


def pegel_messen(h, gpio, pull, dauer=1.0):
    """Ruhepegel unter dem gegebenen Pull ermitteln (Mehrheit aus Proben)."""
    lgpio.gpio_claim_input(h, gpio, pull)
    try:
        proben = []
        t0 = time.monotonic()
        while time.monotonic() - t0 < dauer:
            proben.append(lgpio.gpio_read(h, gpio))
            time.sleep(0.002)
        hi = sum(proben)
        return hi / len(proben), len(proben)
    finally:
        lgpio.gpio_free(h, gpio)


def flanken_zaehlen(h, gpio, pull, edge, sekunden):
    """Zaehlt entprellte Flanken im Zeitfenster."""
    ts = []

    def _cb(chip, g, level, ts_ns):
        if ts and ts_ns - ts[-1] < DEBOUNCE_NS:
            return
        ts.append(ts_ns)

    cb = None
    try:
        lgpio.gpio_claim_alert(h, gpio, edge, pull)
        cb = lgpio.callback(h, gpio, edge, _cb)
        time.sleep(sekunden)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"
    finally:
        try:
            if cb is not None:
                cb.cancel()
        except Exception:
            pass
        try:
            lgpio.gpio_free(h, gpio)
        except Exception:
            pass
    return len(ts), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gpio", type=int, default=17)
    ap.add_argument("--sek", type=float, default=15.0,
                    help="Messdauer pro Kombination (Standard 15)")
    args = ap.parse_args()

    print("=" * 72)
    print(" 1) Verfuegbare gpiochips (Rohausgabe von gpio_get_chip_info)")
    print("=" * 72)
    chips = chips_auflisten()
    if not chips:
        sys.exit(" Kein gpiochip zu oeffnen — als root starten (sudo).")
    for n, h, info in chips:
        print(f"   gpiochip{n}: {info!r}")
        print(f"      Typ={type(info).__name__}", end="")
        if isinstance(info, (list, tuple)):
            print(f"  Laenge={len(info)}", end="")
            for i, feld in enumerate(info):
                print(f"  [{i}]={feld!r}", end="")
        print()
    print()
    print("   >> Erwartet vom Hauptskript: eine Liste/Tupel mit >= 4 Feldern,")
    print("      [1] = Anzahl Leitungen (54), [3] = Label mit 'rp1'.")
    print("      Weicht das ab, ist die Chip-Auswahl in find_rp1_chip die Ursache.")

    # rp1-Chip bestimmen (gleiche Logik wie im Hauptskript)
    ziel = None
    for n, h, info in chips:
        label = ""
        if isinstance(info, (list, tuple)) and len(info) >= 4:
            label = str(info[3]).lower()
        else:
            label = str(info).lower()
        if "rp1" in label:
            ziel = (n, h, label)
            break
    if ziel is None:
        print("\n   ⚠ KEIN Chip mit 'rp1' im Label gefunden — das allein erklaert")
        print("     bereits ausbleibende Ereignisse. Bitte 'gpiodetect' pruefen.")
        for n, h, info in chips:
            try:
                lgpio.gpiochip_close(h)
            except Exception:
                pass
        return
    n_ziel, h_ziel, label_ziel = ziel
    for n, h, info in chips:
        if n != n_ziel:
            try:
                lgpio.gpiochip_close(h)
            except Exception:
                pass

    print()
    print("=" * 72)
    print(f" 2) Ruhepegel auf GPIO{args.gpio} (gpiochip{n_ziel}, Label '{label_ziel}')")
    print("=" * 72)
    pulls = [("SET_PULL_UP", lgpio.SET_PULL_UP),
             ("SET_PULL_NONE", lgpio.SET_PULL_NONE),
             ("SET_PULL_DOWN", lgpio.SET_PULL_DOWN)]
    for name, p in pulls:
        try:
            anteil, n_proben = pegel_messen(h_ziel, args.gpio, p)
            deutung = ("konstant HIGH" if anteil > 0.99 else
                       "konstant LOW" if anteil < 0.01 else
                       f"WECHSELND ({anteil*100:.1f}% HIGH) — Pulse sichtbar!")
            print(f"   {name:<15} HIGH-Anteil {anteil*100:6.2f}%  ({n_proben} Proben)  -> {deutung}")
        except Exception as e:
            print(f"   {name:<15} Fehler: {e}")

    print()
    print("=" * 72)
    print(f" 3) Flankenzaehlung, je {args.sek:.0f} s pro Kombination")
    print("=" * 72)
    edges = [("FALLING", lgpio.FALLING_EDGE),
             ("RISING", lgpio.RISING_EDGE),
             ("BOTH", lgpio.BOTH_EDGES)]
    ergebnisse = []
    for pname, p in pulls:
        for ename, e in edges:
            n_ev, fehler = flanken_zaehlen(h_ziel, args.gpio, p, e, args.sek)
            if fehler:
                print(f"   {pname:<15} {ename:<8} Fehler: {fehler}")
                continue
            cpm = n_ev / args.sek * 60
            marker = "  <== Pulse" if n_ev > 0 else ""
            print(f"   {pname:<15} {ename:<8} {n_ev:4d} Ereignisse  ({cpm:6.1f} CPM){marker}")
            ergebnisse.append((n_ev, cpm, pname, ename))

    try:
        lgpio.gpiochip_close(h_ziel)
    except Exception:
        pass

    print()
    print("=" * 72)
    print(" 4) Auswertung")
    print("=" * 72)
    treffer = [r for r in ergebnisse if r[0] > 0]
    if not treffer:
        print("   Keine einzige Kombination sah Pulse.")
        print("   -> Die Ursache liegt NICHT in der Pull-/Flanken-Einstellung,")
        print("      sondern in Verkabelung, Roehrenspannung oder Board (Poti,")
        print("      5 V-Versorgung, INT-Pin, gemeinsame Masse pruefen).")
        return
    treffer.sort(reverse=True)
    n_ev, cpm, pname, ename = treffer[0]
    print(f"   Beste Kombination: {pname} + {ename}  ({cpm:.1f} CPM)")
    none_ok = any(r[2] == "SET_PULL_NONE" for r in treffer)
    up_ok = any(r[2] == "SET_PULL_UP" for r in treffer)
    print()
    if none_ok and not up_ok:
        print("   >> Erwartungsgemaess: nur BIASFREI (Pull None) kommen Pulse an.")
        print("      Der hochohmige P3-VIN-Abgriff (10k in Reihe) wird von jedem")
        print("      internen Pull abgewuergt — genau der am Geraet erarbeitete")
        print("      Befund, den auch install_seedgen.py als 'gpio=17=ip,pn'")
        print("      dauerhaft in der config.txt verankert.")
        print("      -> Hauptskript ab v1.5.1 nutzt 'none' als Standard. Nichts")
        print("         weiter zu tun.")
    elif up_ok and not none_ok:
        print("   >> Ungewoehnlich: nur MIT Pull-up kommen Pulse an — abweichende")
        print("      Platinenrevision oder geaenderte Verdrahtung.")
        print("      -> Hauptskript mit  --gpio-pull up  starten.")
    elif not treffer:
        pass
    else:
        print(f"   >> Mehrere Modi funktionieren. Empfehlung: {pname} beibehalten.")
        print("      Passend zur config.txt-Einstellung ist 'none' die erste Wahl.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAbbruch.")
