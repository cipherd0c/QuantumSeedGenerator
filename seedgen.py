#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Quantum Seed Generator Project
# Lizenz: MIT License — Volltext in der Datei LICENSE des Repositories.
# License: MIT License — full text in the LICENSE file of the repository.
"""
btc_seedgen.py  —  Hochsicherer BIP39-Seed-Generator mit Hardware-Entropie
===========================================================================
Zielplattform : Raspberry Pi 5, Raspberry Pi OS "Trixie" (64-bit)
Hardware      : 1) BCM2712 Hardware-RNG            (/dev/hwrng, einmalig)
                2) RadiationD-v1.1 (CAJOE) Geiger  (GPIO-Pulse, Zerfallstiming)
                3) MLX90640 IR-Waermebildsensor    (I2C 0x33, Sensorrauschen)
                4) Praezisionswuerfel              (manuelle Eingabe, LETZTE Quelle)

Krypto-Schema (Kurzfassung, Details siehe README-Abschnitt unten):
    H_hw   = SHA-512( DOM|"hwrng"  | rohdaten_hwrng )
    H_dec  = SHA-512( DOM|"decay"  | alle_zerfalls_timestamps_ns )
    H_cam  = SHA-512( DOM|"cam"    | alle_rohframes )
    H_os   = SHA-512( DOM|"os"     | os.urandom(64) )        # Defense-in-Depth
    POOL   = SHA-512( DOM|"pool"   | H_hw | H_dec | H_cam | H_os )
    H_dice = SHA-512( DOM|"dice"   | wuerfel_als_bytes )
    FINAL  = HMAC-SHA512( key = H_dice , msg = POOL )          # Robuster 2-Quellen-Kombinierer
    ENTROPY= FINAL[:16] (12 Woerter) bzw. FINAL[:32] (24 Woerter)
    SEED   = BIP39(ENTROPY)

Eigenschaften des Kombinierers:
  * Ist AUCH NUR EINE der beiden Seiten (Wuerfel ODER Hardware-Pool)
    unvorhersagbar, ist das Ergebnis unvorhersagbar.
  * Die Wuerfel gehen als HMAC-*Schluessel* ein => hardwareunabhaengige,
    letzte Entropiequelle, wie gefordert.

Sicherheit / Fail-Safe:
  * Jede Quelle hat Gesundheitspruefungen. Faellt eine Quelle aus oder
    liefert offensichtlich defekte Daten => sofortiger ABBRUCH mit Meldung.
  * BIP39-Wortliste wird per SHA-256 gegen den offiziellen Hash verifiziert.
  * Selbsttest gegen offizielle BIP39-Testvektoren via --selftest.

Aufruf:
  sudo python3 btc_seedgen.py                  # interaktiv, echte Hardware
  python3 btc_seedgen.py --selftest            # Krypto-Selbsttests
  python3 btc_seedgen.py --mock --yes ...      # NUR ZUM TESTEN, simulierte HW
"""

import argparse
import hashlib
import hmac
import math
import os
import shutil
import sys
import time
from dataclasses import dataclass, field

# ----------------------------------------------------------------------------
# Konstanten
# ----------------------------------------------------------------------------
VERSION            = "1.0"
LANG               = "de"   # wird beim Start gesetzt

def t(de, en):
    """Zweisprachige Programmfuehrung."""
    return en if LANG == "en" else de

DOMAIN             = b"BTC-SEEDGEN-v1"          # Domain-Separation-Tag
GPIO_GEIGER        = 17                          # BCM-Nummer (phys. Pin 11)
MLX_I2C_BUS        = 1
MLX_I2C_ADDR       = 0x33
WORDLIST_SHA256    = ("2f5eed53a4727b4bf8880d8f3f199efc"
                      "90e58503646d9ff8eff3a2ed3b24dbda")   # offizielle english.txt
DECAY_DEBOUNCE_NS  = 30_000_000   # 30 ms Totzeit: Audio-Burst = 1 Zerfall
DECAY_TIMEOUT_S    = 360      # Abbruch, wenn so lange kein Zerfall registriert wird
HWRNG_SAMPLES         = 5     # Proben a 64 B, 2 s Abstand (Warmlauf-Dekorrelation)
HWRNG_BYTES        = 64       # 512 Bit, einmalige Entnahme
CAM_ENTROPY_PER_FRAME = 64    # konservativ kreditierte Bits pro Frame
CAM_MIN_DIFF          = 0.85  # Frame nur akzeptieren, wenn >=85% Pixel anders
CAM_MIN_FRAMES        = 12    # hartes Minimum akzeptierter Frames
CAM_ACCEPT_TIMEOUT_S  = 300   # 5 min Zeit fuer den User, per Handbewegung
                              # einen akzeptablen Frame zu erzeugen
CAM_FROZEN_DIFF       = 0.05  # darunter gilt ein Frame als 'eingefroren'
CAM_FROZEN_LIMIT      = 200   # so viele eingefrorene Frames in Folge = Defekt
DECAY_BITS_PER_EVENT  = 2     # konservativ kreditierte Bits pro Zerfallsereignis
DICE_BITS_PER_ROLL    = math.log2(6)   # ~2.585 Bit pro Wurf
DICE_MIN_ROLLS        = 52    # hartes Minimum (~134 Bit); 100 empfohlen

# ----------------------------------------------------------------------------
# Konsolen-Hilfsfunktionen (ANSI)
# ----------------------------------------------------------------------------
class C:
    RESET  = "\033[0m";  BOLD = "\033[1m";  DIM = "\033[2m"
    RED    = "\033[31m"; GRN  = "\033[32m"; YEL = "\033[33m"
    CYA    = "\033[36m"; MAG  = "\033[35m"; WHT = "\033[97m"
    ORA    = "\033[38;5;208m"   # Orange (256-Farben-Modus)
    HBL    = "\033[38;5;45m"    # helles Blau (Deko/Titel)

def term_width() -> int:
    try:
        return max(60, min(100, shutil.get_terminal_size().columns))
    except Exception:
        return 78

def hr(ch="─"):
    print(C.DIM + ch * term_width() + C.RESET)

ASCII_LOGO = r"""
    ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗
   ██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║
   ██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
             ███████╗███████╗███████╗██████╗
             ██╔════╝██╔════╝██╔════╝██╔══██╗
             ███████╗█████╗  █████╗  ██║  ██║
             ╚════██║██╔══╝  ██╔══╝  ██║  ██║
             ███████║███████╗███████╗██████╔╝
             ╚══════╝╚══════╝╚══════╝╚═════╝
    ██████╗ ███████╗███╗   ██╗███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗
   ██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
   ██║  ███╗█████╗  ██╔██╗ ██║█████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝
   ██║   ██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗
   ╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
    ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
"""

ASCII_DEKO_DE = r"""      ☢ Radiozerfall ─┐  ┌─ ⌁ HWRNG   ┌─ ⌂ IR-Kamera   ┌─ ⚄ Wuerfel
                      └──┴────────────┴────────────────┘
                    ▓▒░ Quanten-Entropie → HMAC-SHA512 → BIP39 ░▒▓"""

ASCII_DEKO_EN = r"""      ☢ Radioactive decay ─┐  ┌─ ⌁ HWRNG   ┌─ ⌂ IR camera   ┌─ ⚄ Dice
                           └──┴────────────┴───────────────┘
                     ▓▒░ Quantum entropy → HMAC-SHA512 → BIP39 ░▒▓"""

def banner():
    w = term_width()
    if w >= 84:
        print(C.ORA + ASCII_LOGO + C.RESET)
        print(C.HBL + t(ASCII_DEKO_DE, ASCII_DEKO_EN) + C.RESET)
        print()
        titel = t(f"QUANTUM SEED GENERATOR v{VERSION} · Hardware-Entropie · Raspberry Pi 5", f"QUANTUM SEED GENERATOR v{VERSION} · Hardware Entropy · Raspberry Pi 5")
        print(C.HBL + C.BOLD + titel.center(84) + C.RESET)
    else:
        # Fallback fuer schmale Terminals
        line = "═" * (w - 2)
        print(C.ORA + "╔" + line + "╗" + C.RESET)
        titel = t(f"QUANTUM SEED GENERATOR v{VERSION}  ·  Hardware-Entropie  ·  BIP39", f"QUANTUM SEED GENERATOR v{VERSION}  ·  Hardware Entropy  ·  BIP39")
        print(C.ORA + "║" + C.BOLD + titel.center(w - 2)[:w-2] + C.RESET + C.ORA + "║" + C.RESET)
        print(C.ORA + "╚" + line + "╝" + C.RESET)

def status_line(idx, total, name, state, detail=""):
    sym = {"ok": C.GRN + "✔", "run": C.YEL + "▶", "wait": C.DIM + "·",
           "fail": C.RED + "✘"}[state]
    print(f" [{idx}/{total}] {sym}{C.RESET} {C.BOLD}{name:<28}{C.RESET} {detail}")

def progress(label, cur, total, extra=""):
    w = 28
    frac = 0 if total == 0 else min(1.0, cur / total)
    filled = int(frac * w)
    bar = "▓" * filled + "░" * (w - filled)
    sys.stdout.write(f"\r   {label:<12} {C.CYA}{bar}{C.RESET} "
                     f"{cur}/{total} ({frac*100:5.1f}%) {extra}   ")
    sys.stdout.flush()

_ABORT_SRC_EN = {
    "Radiozerfall (CAJOE)": "Radioactive decay (CAJOE)",
    "Radiozerfall (Initialisierungstest)": "Radioactive decay (initialization test)",
    "MLX90640 (Initialisierungstest)": "MLX90640 (initialization test)",
    "HWRNG (Initialisierungstest)": "HWRNG (initialization test)",
    "Wuerfel": "Dice",
    "BIP39-Wortliste": "BIP39 wordlist",
    "Funk-Deaktivierung": "Radio disable",
    "Swap-Pruefung": "Swap check",
    "Konfiguration": "Configuration",
    "Entropie-Bilanz": "Entropy balance",
}
_ABORT_TXT_EN = [  # laengere Fragmente zuerst!
    ("Keine verifizierbare english.txt gefunden. Bitte die offizielle BIP39-Wortliste als 'english.txt' neben das Skript legen (SHA-256 wird automatisch geprueft).",
     "No verifiable english.txt found. Please place the official BIP39 wordlist as 'english.txt' next to the script (SHA-256 is checked automatically)."),
    ("stimmt NICHT mit der offiziellen Liste ueberein — Datei manipuliert oder beschaedigt!",
     "does NOT match the official list — file manipulated or corrupted!"),
    ("Mindestens zwei von 10 Proben identisch — RNG liefert keine frischen Daten.",
     "at least two of 10 samples identical — RNG not delivering fresh data."),
    ("Pulsintervalle nahezu konstant — Signal sieht nicht nach Zerfall aus (Stoerquelle/Oszillator am Pin?).",
     "pulse intervals nearly constant — signal does not look like decay (interference/oscillator on the pin?)."),
    ("Zeitstempel nicht streng aufsteigend — Messung unplausibel.",
     "timestamps not strictly increasing — measurement implausible."),
    ("Identische Frames erkannt — kein Sensorrauschen vorhanden.",
     "identical frames detected — no sensor noise present."),
    ("Identische Frames erkannt — kein lebendiges Sensorrauschen.",
     "identical frames detected — no live sensor noise."),
    ("Alle Wuerfe identisch — das ist keine Zufallsquelle.",
     "all rolls identical — that is not a randomness source."),
    ("Automatikmodus (--yes) bricht ohne bestaetigte Netztrennung ab.",
     "automatic mode aborts without confirmed radio disable."),
    ("Vom Benutzer abgebrochen — bitte Funk manuell trennen und neu starten.",
     "aborted by user — please disable radios manually and restart."),
    ("Automatikmodus bricht mit aktivem Swap ab.",
     "automatic mode aborts with active swap."),
    ("sudo swapoff -a ausfuehren und neu starten.", "run sudo swapoff -a and restart."),
    ("Keine Leserechte auf /dev/hwrng — Skript mit sudo starten.",
     "no read permission on /dev/hwrng — start the script with sudo."),
    ("existiert nicht (Kernel/Treiber pruefen).", "does not exist (check kernel/driver)."),
    ("Verkabelung/Board/Roehrenspannung pruefen.", "check wiring/board/tube voltage."),
    ("konnte auf keinem gpiochip belegt werden", "could not be claimed on any gpiochip"),
    ("(gpiodetect ausfuehren: Chip mit Label 'pinctrl-rp1' fehlt?).",
     "(run gpiodetect: chip labeled 'pinctrl-rp1' missing?)."),
    ("Timeout beim Warten auf neues Frame", "timeout waiting for a new frame"),
    ("Sensor antwortet nicht (Adresse 0x33?).", "sensor not responding (address 0x33?)."),
    ("Frame mit nahezu konstantem Inhalt", "frame with nearly constant content"),
    ("Minuten ohne akzeptablen Frame", "minutes without an acceptable frame"),
    ("eingefrorene Frames in Folge", "frozen frames in a row"),
    ("Kamera frei? Hand bewegt?", "camera unobstructed? hand moving?"),
    ("Vom Benutzer abgebrochen (Strg+C).", "aborted by user (Ctrl+C)."),
    ("Vom Benutzer abgebrochen.", "aborted by user."),
    ("Zu wenige Ereignisse erfasst.", "too few events captured."),
    ("Intervall-Mittelwert <= 0 — Messung defekt.", "interval mean <= 0 — measurement broken."),
    ("Python-Modul 'lgpio' fehlt:", "Python module 'lgpio' missing:"),
    ("Python-Modul 'smbus2' fehlt:", "Python module 'smbus2' missing:"),
    ("(I2C in raspi-config aktivieren).", "(enable I2C in raspi-config)."),
    ("unterschreitet das Minimum von", "is below the minimum of"),
    ("Verdaechtige Ausgabe: nur", "suspicious output: only"),
    ("verschiedene Bytewerte.", "distinct byte values."),
    ("Monobit-Test fehlgeschlagen", "monobit test failed"),
    ("Unvollstaendige Probe gelesen.", "incomplete sample read."),
    ("konnte nicht belegt werden.", "could not be claimed."),
    ("ohne Zerfallsereignis", "without a decay event"),
    ("Stoerquelle statt Zerfall?", "interference instead of decay?"),
    ("Eine Augenzahl macht", "one face accounts for"),
    ("% aller Wuerfe aus", "% of all rolls"),
    ("Wuerfel/Eingabe pruefen.", "check die/input."),
    ("Eingabe abgebrochen.", "input aborted."),
    ("erwartet 2048 Woerter, gefunden", "expected 2048 words, found"),
    ("Kreditierte Gesamtentropie (", "credited total entropy ("),
    ("Bit) unter dem Sicherheitsminimum von", "bits) below the safety minimum of"),
    ("Bit — Parameter erhoehen.", "bits — increase parameters."),
    ("Wuerfelwuerfen.", "dice rolls."),
    ("Ereignissen (", "events ("),
    ("nicht verfuegbar:", "not available:"),
    ("I2C-Fehler:", "I2C error:"),
    ("Lesefehler:", "read error:"),
    ("Bytes gelesen.", "bytes read."),
    ("Einsen).", "ones)."),
    ("SHA-256 von", "SHA-256 of"),
    (" Bit = ", " bits = "),
    (" Bit).", " bits)."),
    ("Nur ", "Only "),
    (" von ", " of "),
]

def fail_abort(source, reason):
    if LANG == "en":
        source = _ABORT_SRC_EN.get(source, source)
        for de, en in _ABORT_TXT_EN:
            reason = reason.replace(de, en)
    print("\n")
    hr("━")
    print(C.RED + C.BOLD + t(f" ✘ ABBRUCH — Entropiequelle ausgefallen: {source}", f" ✘ ABORTED — entropy source failed: {source}") + C.RESET)
    print(C.RED + t(f"   Grund: {reason}", f"   Reason: {reason}") + C.RESET)
    print(C.RED + t("   Es wurde KEIN Seed erzeugt. Bitte Hardware pruefen und neu starten.", "   NO seed was generated. Please check hardware and restart.") + C.RESET)
    hr("━")
    sys.exit(2)

# ----------------------------------------------------------------------------
# Domain-separiertes Hashing
# ----------------------------------------------------------------------------
def dsha512(tag: str, data: bytes) -> bytes:
    h = hashlib.sha512()
    h.update(DOMAIN + b"|" + tag.encode() + b"|")
    h.update(len(data).to_bytes(8, "big"))
    h.update(data)
    return h.digest()

# ----------------------------------------------------------------------------
# Entropiequellen
# ----------------------------------------------------------------------------
@dataclass
class SourceResult:
    name: str
    digest: bytes
    raw_len: int
    credited_bits: float
    info: str = ""

# ---------- 1) BCM2712 Hardware-RNG -----------------------------------------
def _thermal_burst(seed_bytes: bytes, dauer_s: float = 2.0):
    """Heizt die CPU fuer die Pausendauer mit SHA-512-Schleifen auf: die
    naechste HWRNG-Probe entsteht unter veraenderten physikalischen
    Bedingungen (Die-Temperatur, Versorgungslast) — Dekorrelations-
    Verstaerkung, KEINE Entropiequelle. Als ehrliches Beiprodukt werden
    Iterationszahl und exakte Dauer geerntet (Scheduler-/Cache-Jitter),
    die unkreditiert in die Rohdaten einfliessen."""
    h = seed_bytes or b"\x00" * 64
    n = 0
    t0 = time.monotonic_ns()
    ziel = t0 + int(dauer_s * 1e9)
    while True:
        for _ in range(256):
            h = hashlib.sha512(h).digest()
        n += 256
        if time.monotonic_ns() >= ziel:
            break
    return n, time.monotonic_ns() - t0


def collect_hwrng(mock: bool, transparent: bool = False) -> SourceResult:
    """Liest HWRNG_SAMPLES Proben a 64 B mit 2 s Abstand: zeitliche
    Dekorrelation (Kaltstart-/Warmlauf-Schutz) + Kreuzvergleich der Proben.
    Kreditiert werden unveraendert konservative 256 Bit."""
    proben = []
    jitter = b""
    iter_liste = []
    for i in range(HWRNG_SAMPLES):
        if mock:
            raw = os.urandom(HWRNG_BYTES)
        else:
            path = "/dev/hwrng"
            if not os.path.exists(path):
                fail_abort("BCM2712 HWRNG", f"{path} existiert nicht (Kernel/Treiber pruefen).")
            try:
                with open(path, "rb") as f:
                    raw = f.read(HWRNG_BYTES)
            except PermissionError:
                fail_abort("BCM2712 HWRNG", "Keine Leserechte auf /dev/hwrng — Skript mit sudo starten.")
            except OSError as e:
                fail_abort("BCM2712 HWRNG", f"Lesefehler: {e}")
        if len(raw) != HWRNG_BYTES:
            fail_abort("BCM2712 HWRNG", f"Nur {len(raw)} von {HWRNG_BYTES} Bytes gelesen.")
        # Pruefungen PRO Probe: Diversitaet + Monobit (Audit H5: erkennt
        # Defekte, keine Manipulation — dagegen steht der HMAC-Kombinierer).
        uniq = len(set(raw))
        ones = sum(bin(b).count("1") for b in raw)
        total_bits = HWRNG_BYTES * 8
        if uniq < 32:
            fail_abort("BCM2712 HWRNG", f"Verdaechtige Ausgabe: nur {uniq} verschiedene Bytewerte.")
        if not (0.30 * total_bits < ones < 0.70 * total_bits):
            fail_abort("BCM2712 HWRNG", f"Monobit-Test fehlgeschlagen ({ones}/{total_bits} Einsen).")
        proben.append(raw)
        progress(t("HWRNG", "HWRNG"), i + 1, HWRNG_SAMPLES,
                 t(f"Probe {i+1}/{HWRNG_SAMPLES}", f"sample {i+1}/{HWRNG_SAMPLES}"))
        if not mock and i < HWRNG_SAMPLES - 1:
            progress(t("HWRNG", "HWRNG"), i + 1, HWRNG_SAMPLES,
                     t("thermische Anregung …", "thermal excitation …"))
            n_it, dt_ns = _thermal_burst(raw)
            jitter += n_it.to_bytes(8, "big") + dt_ns.to_bytes(8, "big")
            iter_liste.append(n_it)
    print()
    # Kreuzvergleich: alle Proben muessen paarweise verschieden sein
    if len(set(proben)) != HWRNG_SAMPLES:
        fail_abort("BCM2712 HWRNG",
                   t("Mindestens zwei der 5 Proben identisch — RNG liefert keine "
                     "frischen Daten.",
                     "at least two of the 5 samples identical — RNG not delivering "
                     "fresh data."))
    raw = b"".join(proben) + jitter   # Jitter-Beiprodukt: unkreditiert, schadet nie
    res = SourceResult("BCM2712 HWRNG", dsha512("hwrng", raw), len(raw),
                       credited_bits=256,   # konservativ, unabhaengig von der Probenzahl
                       info=t(f"{len(raw)} B: {HWRNG_SAMPLES} Proben + therm. Jitter, Monobit ok",
                              f"{len(raw)} B: {HWRNG_SAMPLES} samples + thermal jitter, monobit ok"))
    if transparent:
        print(C.DIM + t(f"   Rohdaten ({HWRNG_SAMPLES} x 512 Bit, je erste 16 B):",
                        f"   Raw data ({HWRNG_SAMPLES} x 512 bits, first 16 B each):") + C.RESET)
        for i, p in enumerate(proben, 1):
            print(f"     Probe {i}: {p[:16].hex()}…")
        if iter_liste:
            print(C.DIM + t(f"   Thermische Anregung — SHA-512-Iterationen je Pause: {iter_liste}",
                            f"   Thermal excitation — SHA-512 iterations per pause: {iter_liste}") + C.RESET)
        print(f"   H_hw = {res.digest.hex()}")
    return res

# ---------- 2) Radioaktiver Zerfall (CAJOE / GPIO) ---------------------------
def find_rp1_chip(lgpio, gpio_nr):
    """Findet den 40-Pin-Header des Pi 5 (RP1, 54 Leitungen) dynamisch.
    Die Chipnummer variiert je nach Kernel (0, 4, 15, ...)."""
    kandidaten = []
    for n in range(0, 32):
        try:
            h = lgpio.gpiochip_open(n)
        except Exception:
            continue
        label = ""
        try:
            info = lgpio.gpio_get_chip_info(h)
            label = str(info).lower()
        except Exception:
            pass
        if "rp1" in label or "54" in label.replace(",", " ").split():
            kandidaten.insert(0, (n, h))      # rp1 bevorzugt an den Anfang
        else:
            kandidaten.append((n, h))
    handle = None
    edge_used = None
    for n, h in kandidaten:
        if handle is None:
            try:
                # Ruhepegel messen -> Flankenrichtung automatisch bestimmen
                lgpio.gpio_claim_input(h, gpio_nr, lgpio.SET_PULL_NONE)
                ruhe = lgpio.gpio_read(h, gpio_nr)
                lgpio.gpio_free(h, gpio_nr)
                edge = lgpio.RISING_EDGE if ruhe == 0 else lgpio.FALLING_EDGE
                lgpio.gpio_claim_alert(h, gpio_nr, edge, lgpio.SET_PULL_NONE)
                handle, edge_used = h, edge
                continue
            except Exception:
                pass
        try: lgpio.gpiochip_close(h)
        except Exception: pass
    return (handle, edge_used) if handle is not None else (None, None)


def _decay_stats_check(timestamps, mock: bool):
    """Audit M4: erkennt jitternde Periodik (Netzbrummen, Funktionsgenerator).
    Echter Zerfall ist ein Poisson-Prozess -> Intervalle exponentialverteilt:
    Variationskoeffizient ~1, Chi-Quadrat gegen Exponentialverteilung klein."""
    deltas = [(b - a) / 1e9 for a, b in zip(timestamps, timestamps[1:])]
    n = len(deltas)
    if n < 32:
        return  # zu wenig Daten fuer Statistik (Healthcheck prueft nur grob)
    m = sum(deltas) / n
    if m <= 0:
        fail_abort("Radiozerfall (CAJOE)", "Intervall-Mittelwert <= 0 — Messung defekt.")
    # CPM-Plausibilitaetsfenster (nur echte Hardware; Mock ist zeitgerafft)
    if not mock:
        cpm = 60.0 / m
        if not (1.0 <= cpm <= 3000.0):
            fail_abort("Radiozerfall (CAJOE)",
                       t(f"Zaehlrate {cpm:.0f} CPM ausserhalb des Plausibilitaetsfensters "
                         "1-3000 — Stoerquelle statt Roehre? (Audit M4)",
                         f"count rate {cpm:.0f} CPM outside plausibility window "
                         "1-3000 — interference instead of tube? (audit M4)"))
    # Variationskoeffizient: Exponentialverteilung hat CV=1; Periodik mit
    # Jitter hat CV << 1 (paarweise verschiedene Werte reichen dann nicht mehr)
    var = sum((d - m) ** 2 for d in deltas) / n
    cv = (var ** 0.5) / m
    if cv < 0.25:
        fail_abort("Radiozerfall (CAJOE)",
                   t(f"Intervalle zu regelmaessig (CV={cv:.2f}, erwartet ~1.0) — "
                     "periodisches Stoersignal statt Zerfall? (Audit M4)",
                     f"intervals too regular (CV={cv:.2f}, expected ~1.0) — "
                     "periodic interference instead of decay? (audit M4)"))
    # Chi-Quadrat gegen Exponentialverteilung mit geschaetztem Mittelwert
    k = 8
    grenzen = [-m * math.log(1.0 - i / k) for i in range(1, k)]
    beob = [0] * k
    for d in deltas:
        b_idx = 0
        while b_idx < k - 1 and d > grenzen[b_idx]:
            b_idx += 1
        beob[b_idx] += 1
    erw = n / k
    chi2 = sum((o - erw) ** 2 / erw for o in beob)
    # df = k-2 = 6, alpha ~ 0.0005 -> kritisch ~24  (bewusst streng gegen
    # Fehlalarme, ein 40-min-Lauf soll nicht grundlos sterben)
    if chi2 > 24.0:
        fail_abort("Radiozerfall (CAJOE)",
                   t(f"Chi-Quadrat={chi2:.1f} (>24): Intervalle folgen keiner "
                     "Exponentialverteilung — keine Zerfallsstatistik. (Audit M4)",
                     f"chi-square={chi2:.1f} (>24): intervals do not follow an "
                     "exponential distribution — not decay statistics. (audit M4)"))


def collect_decay(n_events: int, mock: bool, transparent: bool = False) -> SourceResult:
    timestamps = []
    t_start = time.monotonic()

    if mock:
        # Simulierter Poisson-Prozess ~30 CPM (NUR ZUM TESTEN)
        import random
        ts_val = time.monotonic_ns()
        for i in range(n_events):
            ts_val += int(random.expovariate(0.5) * 1e6)  # gerafft fuer Testlauf
            timestamps.append(ts_val)
            if transparent:
                d = (ts_val - timestamps[-2]) / 1e9 if i else 0.0
                print(t(f"   Ereignis {i+1:4d}", f"   Event {i+1:4d}") + f"/{n_events}: t = {ts_val} ns   Δ = {d:8.3f} s [MOCK]")
            elif i % max(1, n_events // 50) == 0 or i == n_events - 1:
                cpm = (i + 1) / max(1e-9, (time.monotonic() - t_start)) * 60
                progress(t("Zerfall", "Decay"), i + 1, n_events, f"CPM≈{cpm:7.1f} [MOCK]")
            time.sleep(0.002)
    else:
        try:
            import lgpio
        except ImportError:
            fail_abort("Radiozerfall (CAJOE)",
                       "Python-Modul 'lgpio' fehlt: sudo apt install python3-lgpio")
        handle, edge = find_rp1_chip(lgpio, GPIO_GEIGER)
        if handle is None:
            fail_abort("Radiozerfall (CAJOE)",
                       f"GPIO{GPIO_GEIGER} konnte auf keinem gpiochip belegt werden "
                       "(gpiodetect ausfuehren: Chip mit Label 'pinctrl-rp1' fehlt?).")

        last_event = time.monotonic()
        def _cb(chip, gpio, level, ts_ns):
            nonlocal last_event
            if timestamps and ts_ns - timestamps[-1] < DECAY_DEBOUNCE_NS:
                return                       # Flanke gehoert zum selben Klick-Burst
            timestamps.append(ts_ns)
            last_event = time.monotonic()

        cb = lgpio.callback(handle, GPIO_GEIGER, edge, _cb)
        try:
            shown = -1
            shown_evt = 0
            while len(timestamps) < n_events:
                time.sleep(0.2)
                n = len(timestamps)
                if n != shown:
                    el = time.monotonic() - t_start
                    cpm = n / max(1e-9, el) * 60
                    eta = (n_events - n) / max(1e-9, cpm) * 60
                    if transparent:
                        while shown_evt < n:
                            ts = timestamps[shown_evt]
                            d = (ts - timestamps[shown_evt-1]) / 1e9 if shown_evt else 0.0
                            print(t(f"   Ereignis {shown_evt+1:4d}", f"   Event {shown_evt+1:4d}") + f"/{n_events}: t = {ts} ns   "
                                  f"Δ = {d:8.3f} s   (CPM={cpm:5.1f}, ETA {eta/60:5.1f} min)")
                            shown_evt += 1
                    else:
                        progress(t("Zerfall", "Decay"), n, n_events,
                                 f"CPM={cpm:5.1f}  ETA {eta/60:5.1f} min")
                    shown = n
                if time.monotonic() - last_event > DECAY_TIMEOUT_S:
                    fail_abort("Radiozerfall (CAJOE)",
                               f"{DECAY_TIMEOUT_S}s ohne Zerfallsereignis — "
                               "Verkabelung/Board/Roehrenspannung pruefen.")
        except KeyboardInterrupt:
            fail_abort("Radiozerfall (CAJOE)", "Vom Benutzer abgebrochen (Strg+C).")
        finally:
            try:
                cb.cancel(); lgpio.gpiochip_close(handle)
            except Exception:
                pass

    print()
    if len(timestamps) < n_events:
        fail_abort("Radiozerfall (CAJOE)", "Zu wenige Ereignisse erfasst.")
    # Gesundheitspruefung: Intervalle muessen variieren (kein festgeklemmter Pin)
    deltas = [b - a for a, b in zip(timestamps, timestamps[1:])]
    if len(set(deltas)) < max(4, len(deltas) // 10):
        fail_abort("Radiozerfall (CAJOE)",
                   "Pulsintervalle nahezu konstant — Signal sieht nicht nach Zerfall aus "
                   "(Stoerquelle/Oszillator am Pin?).")
    _decay_stats_check(timestamps, mock)
    raw = b"".join(t.to_bytes(8, "big", signed=False) for t in timestamps)
    dur = time.monotonic() - t_start
    res = SourceResult(t("Radiozerfall (CAJOE)", "Radioactive decay (CAJOE)"), dsha512("decay", raw), len(raw),
                       credited_bits=n_events * DECAY_BITS_PER_EVENT,
                       info=t(f"{n_events} Ereignisse in {dur/60:.1f} min", f"{n_events} events in {dur/60:.1f} min"))
    if transparent:
        print(f"   H_dec = {res.digest.hex()}")
    return res

# ---------- 3) MLX90640 IR-Kamera (I2C, Roh-Frames) --------------------------
def _mlx_read_words(bus, reg: int, n_words: int) -> bytes:
    """16-Bit-Registeradresse schreiben, dann n_words*2 Bytes lesen."""
    from smbus2 import i2c_msg
    out = bytearray()
    CHUNK = 24  # Worte pro Transaktion (konservativ)
    off = 0
    while off < n_words:
        n = min(CHUNK, n_words - off)
        w = i2c_msg.write(MLX_I2C_ADDR, [(reg + off) >> 8, (reg + off) & 0xFF])
        r = i2c_msg.read(MLX_I2C_ADDR, n * 2)
        bus.i2c_rdwr(w, r)
        out += bytes(r)
        off += n
    return bytes(out)

def _hand_hinweis():
    print(C.YEL + C.BOLD + t("   >>> Bitte die Hand in ca. 60 cm Abstand ZUFAELLIG vor der Kamera bewegen! <<<", "   >>> Please move your hand RANDOMLY about 60 cm in front of the camera! <<<") + C.RESET)

def frame_diff_ratio(a: bytes, b: bytes) -> float:
    """Anteil der 768 Bildpixel (16-Bit-Worte), die sich unterscheiden."""
    n = min(768, min(len(a), len(b)) // 2)
    diff = sum(1 for i in range(n) if a[2*i:2*i+2] != b[2*i:2*i+2])
    return diff / max(1, n)

def collect_camera(n_frames: int, mock: bool, transparent: bool = False) -> SourceResult:
    frames = []
    rejected = 0
    _hand_hinweis()
    print(C.DIM + t(f"   (Frames werden nur akzeptiert, wenn sich >= {CAM_MIN_DIFF*100:.0f}% der Pixel zum letzten AKZEPTIERTEN Frame unterscheiden)", f"   (Frames are only accepted if >= {CAM_MIN_DIFF*100:.0f}% of pixels differ from the last ACCEPTED frame)") + C.RESET)
    if mock:
        for i in range(n_frames):
            f = os.urandom(832 * 2)
            d = frame_diff_ratio(f, frames[-1]) if frames else 1.0
            frames.append(f)
            if transparent:
                h = hashlib.sha256(f).hexdigest()
                print(C.GRN + t("   ✔ AKZEPTIERT", "   ✔ ACCEPTED") + C.RESET +
                      f" Frame {i+1:3d}/{n_frames}: SHA256 {h[:16]}…  Diff {d*100:5.1f}%  " +
                      t("Rohworte", "raw words") + f" {f[:6].hex()} [MOCK]")
            else:
                progress(t("IR-Kamera", "IR camera"), i + 1, n_frames, "[MOCK]")
            if (i + 1) % 5 == 0 and i + 1 < n_frames:
                if not transparent:
                    print()
                _hand_hinweis()
            time.sleep(0.01)
    else:
        try:
            from smbus2 import SMBus
        except ImportError:
            fail_abort("MLX90640", "Python-Modul 'smbus2' fehlt: "
                       "sudo apt install python3-smbus2  (oder pip install smbus2)")
        try:
            bus = SMBus(MLX_I2C_BUS)
        except OSError as e:
            fail_abort("MLX90640", f"I2C-Bus {MLX_I2C_BUS} nicht verfuegbar: {e} "
                       "(I2C in raspi-config aktivieren).")
        try:
            consec_reject = 0
            frozen_count = 0
            last_accept = time.monotonic()
            while len(frames) < n_frames:
                # Auf neues Frame warten (Statusregister 0x8000, Bit 3)
                t0 = time.monotonic()
                while True:
                    st = _mlx_read_words(bus, 0x8000, 1)
                    if st[1] & 0x08:
                        break
                    if time.monotonic() - t0 > 5:
                        fail_abort("MLX90640", "Timeout beim Warten auf neues Frame — "
                                   "Sensor antwortet nicht (Adresse 0x33?).")
                    time.sleep(0.02)
                frame = _mlx_read_words(bus, 0x0400, 832)   # kompletter RAM-Block
                # Statusbit "new data" loeschen
                from smbus2 import i2c_msg
                wmsg = i2c_msg.write(MLX_I2C_ADDR, [0x80, 0x00, 0x00, 0x30])
                bus.i2c_rdwr(wmsg)
                # CAM_MIN_DIFF-Filter (aktuell 85%): nur deutlich veraenderte Frames akzeptieren
                d = frame_diff_ratio(frame, frames[-1]) if frames else 1.0
                if frames and d < CAM_MIN_DIFF:
                    rejected += 1
                    consec_reject += 1
                    # Healthcheck: wirklich EINGEFRORENES Bild (Sensordefekt) ...
                    if d < CAM_FROZEN_DIFF:
                        frozen_count += 1
                        if frozen_count >= CAM_FROZEN_LIMIT:
                            fail_abort("MLX90640",
                                       f"{CAM_FROZEN_LIMIT} eingefrorene Frames in Folge "
                                       f"(Diff < {CAM_FROZEN_DIFF*100:.0f}%) — Sensor defekt?")
                    else:
                        frozen_count = 0
                    # ... aber dem Menschen 5 Minuten Zeit fuer die Handbewegung geben
                    warte = time.monotonic() - last_accept
                    if warte > CAM_ACCEPT_TIMEOUT_S:
                        fail_abort("MLX90640",
                                   f"{CAM_ACCEPT_TIMEOUT_S/60:.0f} Minuten ohne akzeptablen Frame "
                                   f"(>= {CAM_MIN_DIFF*100:.0f}% Diff) — Kamera frei? Hand bewegt?")
                    if transparent:
                        print(C.RED + t(f"   ✘ VERWORFEN (nicht verwendet): Diff nur {d*100:5.1f}% < {CAM_MIN_DIFF*100:.0f}%", f"   ✘ REJECTED (not used): diff only {d*100:5.1f}% < {CAM_MIN_DIFF*100:.0f}%") + C.RESET + C.DIM + t(f"   [noch {max(0, CAM_ACCEPT_TIMEOUT_S-warte):3.0f} s Zeit]", f"   [{max(0, CAM_ACCEPT_TIMEOUT_S-warte):3.0f} s left]") + C.RESET)
                    if consec_reject % 3 == 0:
                        if not transparent:
                            print()
                        _hand_hinweis()
                    continue
                consec_reject = 0
                frozen_count = 0
                last_accept = time.monotonic()
                frames.append(frame)
                if transparent:
                    h = hashlib.sha256(frame).hexdigest()
                    print(C.GRN + t("   ✔ AKZEPTIERT", "   ✔ ACCEPTED") + C.RESET +
                          f" Frame {len(frames):3d}/{n_frames}: SHA256 {h[:16]}…  "
                          f"Diff {d*100:5.1f}%  " + t("Rohworte", "raw words") + f" {frame[:6].hex()}")
                else:
                    progress(t("IR-Kamera", "IR camera"), len(frames), n_frames,
                             f"Diff {d*100:4.0f}%  verworfen: {rejected}")
                if len(frames) % 5 == 0 and len(frames) < n_frames:
                    if not transparent:
                        print()
                    _hand_hinweis()
        except OSError as e:
            fail_abort("MLX90640", f"I2C-Fehler: {e}")
        finally:
            try: bus.close()
            except Exception: pass
    print()
    # Gesundheitspruefung: Frames duerfen weder leer/konstant noch identisch sein
    if any(len(set(f)) < 8 for f in frames):
        fail_abort("MLX90640", "Frame mit nahezu konstantem Inhalt — Sensor defekt?")
    if n_frames >= 2 and len({hashlib.sha256(f).digest() for f in frames}) < n_frames:
        fail_abort("MLX90640", "Identische Frames erkannt — kein Sensorrauschen vorhanden.")
    raw = b"".join(frames)
    res = SourceResult(t("MLX90640 IR-Kamera", "MLX90640 IR camera"), dsha512("cam", raw), len(raw),
                       credited_bits=n_frames * CAM_ENTROPY_PER_FRAME,
                       info=t(f"{n_frames} Frames akzeptiert, {rejected} verworfen ({len(raw)} B)", f"{n_frames} frames accepted, {rejected} rejected ({len(raw)} B)"))
    if transparent:
        print(f"   H_cam = {res.digest.hex()}")
    return res

# ---------- 4) Wuerfel (manuell, LETZTE Quelle) ------------------------------
def dice_to_bytes(rolls) -> bytes:
    val = 0
    for r in rolls:
        val = val * 6 + (r - 1)
    n = max(1, (val.bit_length() + 7) // 8)
    return len(rolls).to_bytes(4, "big") + val.to_bytes(n, "big")

def collect_dice(n_rolls: int, target_bits: int, mock: bool, transparent: bool = False) -> SourceResult:
    rolls = []
    if mock:
        import random
        rolls = [random.randint(1, 6) for _ in range(n_rolls)]
        print(t(f"   Wuerfel: {n_rolls} simulierte Wuerfe [MOCK]", f"   Dice: {n_rolls} simulated rolls [MOCK]"))
    else:
        print(C.BOLD + t(f"\n   Bitte {n_rolls} Wuerfelwuerfe eingeben (Ziffern 1-6).", f"\n   Please enter {n_rolls} dice rolls (digits 1-6).") + C.RESET)
        print(C.DIM + t("   Eingabe einzeln oder als Block (z.B. 415263...). 'u' = letzten Wurf loeschen.", "   Enter singly or as a block (e.g. 415263...). 'u' = delete last roll.") + C.RESET)
        while len(rolls) < n_rolls:
            progress(t("Wuerfel", "Dice"), len(rolls), n_rolls)
            try:
                s = input("\n   > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                fail_abort("Wuerfel", "Eingabe abgebrochen.")
            if s == "u":
                if rolls: rolls.pop()
                continue
            for ch in s:
                if ch in "123456":
                    if len(rolls) < n_rolls:
                        rolls.append(int(ch))
                elif ch in " ,;":
                    continue
                else:
                    print(C.YEL + f"   Ignoriere ungueltiges Zeichen: '{ch}'" + C.RESET)
        progress(t("Wuerfel", "Dice"), len(rolls), n_rolls); print()
    # Gesundheitspruefung
    counts = {v: rolls.count(v) for v in range(1, 7)}
    if len(set(rolls)) == 1:
        fail_abort("Wuerfel", "Alle Wuerfe identisch — das ist keine Zufallsquelle.")
    worst = max(counts.values()) / len(rolls)
    if n_rolls >= 60 and worst > 0.40:
        fail_abort("Wuerfel", f"Eine Augenzahl macht {worst*100:.0f}% aller Wuerfe aus — "
                   "Wuerfel/Eingabe pruefen.")
    # Audit N4: Mindest-Diversitaet auch bei kleinen Stichproben
    if len(set(rolls)) < 4:
        fail_abort("Wuerfel",
                   t(f"Nur {len(set(rolls))} verschiedene Augenzahlen in {n_rolls} "
                     "Wuerfen — unplausibel fuer einen fairen Wuerfel (Audit N4).",
                     f"only {len(set(rolls))} distinct faces in {n_rolls} rolls — "
                     "implausible for a fair die (audit N4)."))
    bits = n_rolls * DICE_BITS_PER_ROLL
    if bits < target_bits:
        print(C.YEL + t(f"   ⚠ Hinweis: Wuerfel liefern nur ~{bits:.0f} Bit (< {target_bits} Bit Ziel). Fuer volle Hardware-Unabhaengigkeit mind. {math.ceil(target_bits / DICE_BITS_PER_ROLL)} Wuerfe verwenden.", f"   ⚠ Note: dice provide only ~{bits:.0f} bits (< {target_bits} bits target). For full hardware independence use at least {math.ceil(target_bits / DICE_BITS_PER_ROLL)} rolls.") + C.RESET)
    raw = dice_to_bytes(rolls)
    res = SourceResult(t("Wuerfel (manuell)", "Dice (manual)"), dsha512("dice", raw), len(raw),
                       credited_bits=bits,
                       info=t(f"{n_rolls} Wuerfe, Verteilung {counts}", f"{n_rolls} rolls, distribution {counts}"))
    if transparent:
        print(t(f"   Wuerfelfolge : {''.join(str(r) for r in rolls)}", f"   Dice sequence: {''.join(str(r) for r in rolls)}"))
        print(t(f"   Kodiert (hex): {raw.hex()}", f"   Encoded (hex): {raw.hex()}"))
        print(f"   H_dice = {res.digest.hex()}")
    return res

# ----------------------------------------------------------------------------
# Kombinierer + BIP39
# ----------------------------------------------------------------------------
def combine(hw: SourceResult, dec, cam,
            dice: SourceResult, n_bytes: int, transparent: bool = False,
            light: bool = False) -> bytes:
    h_os = dsha512("os", os.urandom(64))                    # Defense-in-Depth
    mode_tag = b"light" if light else b"full"               # Domain-Separation der Modi
    parts = hw.digest + (dec.digest if dec else b"") + (cam.digest if cam else b"") + h_os
    pool = dsha512("pool", mode_tag + parts)
    final = hmac.new(dice.digest, pool, hashlib.sha512).digest()
    if transparent:
        print(C.DIM + t("   — Transparenz: alle Zwischenwerte des Kombinierers —", "   — Transparency: all intermediate values of the combiner —") + C.RESET)
        print(C.DIM + t(f"   Modus-Tag im Pool: {mode_tag.decode()}", f"   mode tag in pool: {mode_tag.decode()}") + C.RESET)
        print(f"   H_hw   = {hw.digest.hex()}")
        if dec: print(f"   H_dec  = {dec.digest.hex()}")
        if cam: print(f"   H_cam  = {cam.digest.hex()}")
        print(f"   H_os   = {h_os.hex()}")
        print(f"   POOL   = {pool.hex()}")
        print(f"   H_dice = {dice.digest.hex()}" + t("  (HMAC-Schluessel)", "  (HMAC key)"))
        print(f"   FINAL  = HMAC-SHA512(H_dice, POOL) = {final.hex()}")
        print(f"   ENTROPY= FINAL[:{n_bytes}] = {final[:n_bytes].hex()}")
    return final[:n_bytes]

def bip39_indices(entropy: bytes):
    ent_bits = len(entropy) * 8
    cs_bits  = ent_bits // 32
    cs = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    num = (int.from_bytes(entropy, "big") << cs_bits) | cs
    total = ent_bits + cs_bits
    return [(num >> (total - 11 * (i + 1))) & 0x7FF for i in range(total // 11)]

def load_wordlist():
    """Sucht english.txt neben dem Skript oder im 'mnemonic'-Paket; verifiziert Hash."""
    candidates = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "english.txt")]
    try:
        import mnemonic as _m
        candidates.append(os.path.join(os.path.dirname(_m.__file__),
                                       "wordlist", "english.txt"))
    except ImportError:
        pass
    for p in candidates:
        if os.path.exists(p):
            data = open(p, "rb").read()
            if hashlib.sha256(data).hexdigest() != WORDLIST_SHA256:
                fail_abort("BIP39-Wortliste",
                           f"SHA-256 von {p} stimmt NICHT mit der offiziellen Liste "
                           "ueberein — Datei manipuliert oder beschaedigt!")
            words = data.decode("utf-8").split()
            if len(words) != 2048:
                fail_abort("BIP39-Wortliste", f"{p}: erwartet 2048 Woerter, gefunden {len(words)}.")
            return words, p
    return None, None

# ----------------------------------------------------------------------------
# Selbsttest (BIP39-Vektoren + Kombinierer)
# ----------------------------------------------------------------------------
def _st(cond, name):
    """Expliziter Selbsttest-Check — wird im Gegensatz zu assert NICHT
    durch python3 -O entfernt (Audit M1)."""
    if not cond:
        fail_abort("Selbsttest / self-test", name)

def selftest():
    if not __debug__:
        print(C.RED + C.BOLD + t(
            " ✘ Start mit python3 -O erkannt — Selbsttests wuerden unvollstaendig laufen. Bitte OHNE -O starten.",
            " ✘ python3 -O detected — self-tests would run incompletely. Please start WITHOUT -O.") + C.RESET)
        sys.exit(2)
    print(t("Selbsttest laeuft …", "Self-test running …"))
    # 1) Offizieller BIP39-Vektor: 16x 0x00 -> Indizes [0]*11 + [3]
    #    ("abandon"x11 + "about", da 'about' Index 3 der Wortliste ist)
    idx = bip39_indices(b"\x00" * 16)
    _st(idx == [0] * 11 + [3], f"Vektor 0x00: {idx}")
    # 2) Vektor 16x 0xFF: erste 11 Indizes = 2047, letzter = (0x7F<<4)|cs
    idx = bip39_indices(b"\xff" * 16)
    cs = hashlib.sha256(b"\xff" * 16).digest()[0] >> 4
    _st(idx[:11] == [2047] * 11 and idx[11] == (0x7F << 4) | cs, "Vektor 0xFF")
    # 3) Laengen: 128 Bit -> 12 Indizes, 256 Bit -> 24 Indizes
    _st(len(bip39_indices(os.urandom(16))) == 12, "Laenge 128 Bit")
    _st(len(bip39_indices(os.urandom(32))) == 24, "Laenge 256 Bit")
    # 4) Checksummen-Roundtrip fuer 256 Bit
    e = os.urandom(32)
    idx = bip39_indices(e)
    num = 0
    for i in idx: num = (num << 11) | i
    ent = (num >> 8).to_bytes(32, "big")
    cs  = num & 0xFF
    _st(ent == e and cs == hashlib.sha256(e).digest()[0], "Roundtrip 256")
    # 5) Kombinierer: deterministisch & sensitiv auf jede Quelle
    def sr(tag, data): return SourceResult(tag, dsha512(tag, data), len(data), 0)
    a = combine(sr("hwrng", b"A"), sr("decay", b"B"), sr("cam", b"C"), sr("dice", b"D"), 32)
    # (combine mischt os.urandom -> zwei Aufrufe muessen sich unterscheiden)
    b = combine(sr("hwrng", b"A"), sr("decay", b"B"), sr("cam", b"C"), sr("dice", b"D"), 32)
    _st(a != b and len(a) == 32, "Kombinierer nicht frisch/32B")
    # 6) HMAC-Kombinierer-Kern deterministisch pruefen (ohne urandom-Anteil)
    pool = dsha512("pool", b"x")
    k1 = hmac.new(dsha512("dice", b"D1"), pool, hashlib.sha512).digest()
    k2 = hmac.new(dsha512("dice", b"D2"), pool, hashlib.sha512).digest()
    _st(k1 != k2, "HMAC-Key-Sensitivitaet")
    # 7) Wuerfel-Kodierung
    _st(dice_to_bytes([1, 1, 1]) == (3).to_bytes(4, "big") + b"\x00", "Wuerfelkodierung 111")
    _st(dice_to_bytes([6]) == (1).to_bytes(4, "big") + b"\x05", "Wuerfelkodierung 6")
    # 8) Wortliste (falls vorhanden) verifizieren
    words, path = load_wordlist()
    if words:
        _st(words[0] == "abandon" and words[3] == "about" and words[2047] == "zoo", "Wortliste Stichprobe")
        print(t(f"  Wortliste verifiziert: {path}", f"  Wordlist verified: {path}"))
    else:
        print(t("  Hinweis: keine english.txt gefunden — Wortlistentest uebersprungen.", "  Note: no english.txt found — wordlist test skipped."))
    print(C.GRN + t("  ✔ Alle Selbsttests bestanden.", "  ✔ All self-tests passed.") + C.RESET)



# ----------------------------------------------------------------------------
# Sicherheitsbelehrung beim Start (Bestaetigung erforderlich)
# ----------------------------------------------------------------------------
def security_briefing(args):
    """Offline-Grundregeln in einer roten Box. Ohne ausdrueckliche
    Bestaetigung endet das Programm. Im --yes-/Mock-Modus wird die Box
    angezeigt, aber nicht abgefragt (keine Interaktion moeglich)."""
    B = 78  # Innenbreite der Box
    def zeile(txt="", fett=False):
        stil = C.RED + (C.BOLD if fett else "")
        print(stil + "║ " + txt.ljust(B - 2) + C.RESET + C.RED + " ║" + C.RESET)
    print(C.RED + "╔" + "═" * B + "╗" + C.RESET)
    zeile(t("⚠  SICHERHEITSREGELN — BITTE LESEN:",
            "⚠  SECURITY RULES — PLEASE READ:"), fett=True)
    zeile()
    zeile(t("1. Dieser Generator darf NUR OHNE Internetverbindung betrieben werden.",
            "1. This generator must ONLY be operated WITHOUT an internet connection."))
    zeile(t("2. Der Raspberry Pi muss auch NACH der Seed-Erzeugung dauerhaft offline",
            "2. The Raspberry Pi must remain permanently offline even AFTER seed"))
    zeile(t("   bleiben. Falls Sie den Raspberry Pi spaeter fuer andere Zwecke",
            "   generation. If you want to use the Raspberry Pi for other purposes"))
    zeile(t("   verwenden moechten, bauen Sie eine frische SD-Karte ein (neue",
            "   later, insert a fresh SD card (new installation) or erase this"))
    zeile(t("   Installation) oder loeschen Sie diese Installation von der SD-Karte.",
            "   installation from the SD card."))
    zeile(t("3. Der angeschlossene Monitor/TV darf KEINE Smart-Funktionen und KEINEN",
            "3. The connected monitor/TV must have NO smart features and NO internet"))
    zeile(t("   Internetanschluss besitzen (Smart-TVs koennen Bildinhalte erfassen",
            "   connection (smart TVs can capture and transmit screen contents)."))
    zeile(t("   und uebertragen).", ""))
    zeile(t("4. Waehrend der Ausfuehrung duerfen sich KEINE Mobiltelefone oder",
            "4. During execution NO mobile phones or camera devices of any kind"))
    zeile(t("   Kamerageraete jeglicher Art im Raum befinden.",
            "   may be present in the room."))
    zeile(t("5. Ausser dir selbst darf sich KEINE weitere Person im Raum aufhalten.",
            "5. NO other person besides yourself may be present in the room."))
    zeile()
    zeile(t("Beim Fortfahren werden WLAN + Bluetooth AUTOMATISCH deaktiviert:",
            "When you continue, WLAN + Bluetooth will be disabled AUTOMATICALLY:"), fett=True)
    zeile(t("sofort (rfkill) UND dauerhaft auf Firmware-Ebene (config.txt) —",
            "immediately (rfkill) AND permanently at firmware level (config.txt) —"), fett=True)
    zeile(t("die Funkchips werden ab dem naechsten Boot nicht mehr initialisiert.",
            "the radio chips will no longer be initialized from the next boot on."), fett=True)
    print(C.RED + "╚" + "═" * B + "╝" + C.RESET)
    if args.yes or args.mock:
        print(C.YEL + t("   (--yes/Mock: Bestaetigung uebersprungen — Regeln gelten trotzdem!)",
                        "   (--yes/mock: confirmation skipped — the rules still apply!)") + C.RESET)
        return
    try:
        antwort = input(C.ORA + t(
            "   Hast du die Sicherheitsregeln verstanden und akzeptierst du diese? [ja/nein]: ",
            "   Have you understood the security rules and do you accept them? [yes/no]: ")
            + C.RESET + C.GRN).strip().lower()
        sys.stdout.write(C.RESET); sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        sys.stdout.write(C.RESET)
        antwort = ""
    if antwort not in ("ja", "yes", "y"):
        print(C.RED + C.BOLD + t(
            " ✘ Ohne Bestaetigung der Sicherheitsregeln wird kein Seed erzeugt. Programmende.",
            " ✘ Without confirming the security rules no seed will be generated. Exiting.") + C.RESET)
        sys.exit(2)
    print(C.GRN + t(" ✔ Sicherheitsregeln bestaetigt.", " ✔ Security rules confirmed.") + C.RESET)


# ----------------------------------------------------------------------------
# SSH-/Session-Recording-Erkennung (Audit M3/N2)
# ----------------------------------------------------------------------------
def check_remote_session(args):
    """Ueber SSH verlaesst der Seed den Air-Gap und landet im Scrollback des
    entfernten Clients; tmux/screen koennen Sitzungen mitschneiden."""
    if args.mock:
        return
    ssh = os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY")
    if ssh:
        print(C.RED + C.BOLD + t(
            " ⚠ SSH-SITZUNG ERKANNT — der Seed wuerde ueber das Netzwerk zum "
            "Client uebertragen\n   und dort im Terminal-Scrollback/Log landen!",
            " ⚠ SSH SESSION DETECTED — the seed would travel over the network "
            "to the client\n   and persist in its terminal scrollback/log!") + C.RESET)
        if args.yes:
            fail_abort("SSH-Erkennung / SSH detection",
                       t("Automatikmodus bricht in SSH-Sitzungen ab (Audit M3).",
                         "automatic mode aborts in SSH sessions (audit M3)."))
        antwort = input(t("   Trotzdem fortfahren? Nur 'ja' setzt fort: ",
                          "   Continue anyway? Only 'yes' continues: ")).strip().lower()
        if antwort not in ("ja", "yes", "y"):
            fail_abort("SSH-Erkennung / SSH detection",
                       t("Vom Benutzer abgebrochen — bitte lokal an Tastatur/Monitor arbeiten.",
                         "aborted by user — please work locally on keyboard/monitor."))
    if os.environ.get("TMUX") or os.environ.get("STY"):
        print(C.YEL + t(
            " ⚠ tmux/screen erkannt: Scrollback-Loeschung erreicht deren Puffer/Logs "
            "nicht zuverlaessig (Audit N2).",
            " ⚠ tmux/screen detected: scrollback erase does not reliably reach "
            "their buffers/logs (audit N2).") + C.RESET)


# ----------------------------------------------------------------------------
# Root-Pruefung: Hardware-Zugriff erfordert sudo
# ----------------------------------------------------------------------------
def require_root(args):
    """/dev/hwrng, rfkill, swapoff und History-Bereinigung brauchen Root.
    Klare Anleitung statt spaeterem 'Permission denied' mitten im Lauf."""
    if args.mock:
        return
    if os.geteuid() != 0:
        print(C.RED + C.BOLD + t(
            " ✘ Dieses Skript benoetigt Hardware-Zugriff auf Systemebene "
            "(/dev/hwrng, rfkill, swapoff)",
            " ✘ This script needs hardware-level system access "
            "(/dev/hwrng, rfkill, swapoff)") + C.RESET)
        print(C.RED + t("   und muss deshalb mit sudo gestartet werden:",
                        "   and therefore must be started with sudo:") + C.RESET)
        skript = os.path.basename(sys.argv[0])
        print(C.BOLD + f"\n       sudo python3 {skript}\n" + C.RESET)
        sys.exit(2)

# ----------------------------------------------------------------------------
# WLAN-Deaktivierung beim Start (Ethernet bleibt unberuehrt)
# ----------------------------------------------------------------------------
def disable_wifi(args):
    """Blockiert WLAN UND Bluetooth via rfkill (dauerhaft, uebersteht Reboots,
    da systemd-rfkill den Zustand speichert). Ethernet ist nicht betroffen.
    Mit --keep-wifi ueberspringbar."""
    if getattr(args, "keep_wifi", False):
        print(C.YEL + t(" ⚠ Funkmodule (WLAN+Bluetooth) bleiben auf Wunsch AKTIV (--keep-wifi) — fuer echte Seeds nicht empfohlen!", " ⚠ Radios (WLAN+Bluetooth) stay ACTIVE on request (--keep-wifi) — not recommended for real seeds!") + C.RESET)
        return
    import subprocess
    methode = None
    try:
        subprocess.run(["rfkill", "block", "wlan"], check=True,
                       capture_output=True, timeout=10)
        subprocess.run(["rfkill", "block", "bluetooth"], check=True,
                       capture_output=True, timeout=10)
        methode = "rfkill"
    except Exception:
        try:
            subprocess.run(["nmcli", "radio", "all", "off"], check=True,
                           capture_output=True, timeout=10)
            methode = "nmcli"
        except Exception:
            methode = None
    if methode:
        # Beide Funktypen verifizieren, soweit moeglich
        geprueft = []
        for typ in ("wlan", "bluetooth"):
            try:
                out = subprocess.run(["rfkill", "list", typ], capture_output=True,
                                     text=True, timeout=10).stdout
                if "Soft blocked: yes" in out:
                    geprueft.append(typ)
            except Exception:
                pass
        status = t(f" (verifiziert: {', '.join(geprueft)})", f" (verified: {', '.join(geprueft)})") if geprueft else ""
        print(C.GRN + t(f" ✔ WLAN + Bluetooth deaktiviert via {methode}{status}. Ethernet bleibt unberuehrt.", f" ✔ WLAN + Bluetooth disabled via {methode}{status}. Ethernet is unaffected.") + C.RESET)
    else:
        if args.mock:
            print(C.YEL + " ⚠ Funk-Deaktivierung nicht moeglich (rfkill/nmcli fehlen) "
                  "— im MOCK-Modus toleriert." + C.RESET)
            return
        print(C.RED + C.BOLD + " ⚠ Funkmodule konnten NICHT deaktiviert werden "
              "(rfkill/nmcli fehlgeschlagen — sudo? rfkill installiert?)." + C.RESET)
        if args.yes:
            fail_abort("Funk-Deaktivierung", "Automatikmodus (--yes) bricht ohne "
                       "bestaetigte Netztrennung ab.")
        antwort = input(t("   Trotzdem fortfahren? Nur 'ja' setzt fort: ", "   Continue anyway? Only 'yes' continues: ")).strip().lower()
        if antwort not in ("ja", "yes", "y"):
            fail_abort("Funk-Deaktivierung", "Vom Benutzer abgebrochen — bitte Funk "
                       "manuell trennen und neu starten.")


# ----------------------------------------------------------------------------
# Erfolgs-Sound im Atari-Stil (Rechteckwelle ueber HDMI, komplett im RAM)
# ----------------------------------------------------------------------------
def play_success_jingle():
    """Aufsteigendes Rechteck-Arpeggio wie in fruehen Videospielen.
    Best-effort: jede Fehlbedingung (kein aplay, kein Audio) wird still
    ignoriert — der Sound darf den Lauf niemals beeinflussen. Es wird
    keine Datei geschrieben (WAV entsteht im Speicher, aplay liest stdin)."""
    try:
        import io as _io
        import shutil as _shutil
        import struct
        import subprocess
        import wave
        if not _shutil.which("aplay"):
            return
        rate = 22050
        # Der urspruengliche Power-Up-Jingle (C5 E5 G5 C6), auf ~3x Laenge
        # gestreckt: gemaechlichere Achtel + lang gehaltener Schlusston.
        noten = [(523.25, 0.18), (659.25, 0.18), (783.99, 0.18), (1046.50, 1.05)]
        frames = bytearray()
        for freq, dauer in noten:
            n = int(rate * dauer)
            periode = rate / freq
            for i in range(n):
                # Rechteckwelle (50% Duty) + Abkling-Huellkurve wie im Original
                pegel = 0.28 * (1.0 - i / n * 0.35)
                wert = pegel if (i % periode) < (periode / 2) else -pegel
                frames += struct.pack("<h", int(wert * 32767))
            frames += b"\x00\x00" * int(rate * 0.015)   # Staccato-Luecke
        buf = _io.BytesIO()
        with wave.open(buf, "wb") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
            w.writeframes(bytes(frames))
        subprocess.run(["aplay", "-q", "-"], input=buf.getvalue(),
                       capture_output=True, timeout=5)
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Dauerhafte Funk-Abschaltung auf Firmware-Ebene (Device-Tree-Overlays)
# ----------------------------------------------------------------------------
def enforce_permanent_radio_off(args):
    """ERZWUNGEN (per Sicherheitsregeln bestaetigt): WLAN+Bluetooth werden
    per dtoverlay in config.txt auf Firmware-Ebene dauerhaft deaktiviert —
    die Chips werden ab dem naechsten Boot nicht mehr initialisiert."""
    if args.mock:
        return
    pfad = None
    for p in ("/boot/firmware/config.txt", "/boot/config.txt"):
        if os.path.exists(p):
            pfad = p
            break
    if pfad is None:
        print(C.YEL + t("   ⚠ config.txt nicht gefunden — Firmware-Abschaltung manuell "
                        "eintragen: dtoverlay=disable-wifi / disable-bt",
                        "   ⚠ config.txt not found — add firmware disable manually: "
                        "dtoverlay=disable-wifi / disable-bt") + C.RESET)
        return
    try:
        inhalt = open(pfad).read()
    except Exception as e:
        print(C.YEL + t(f"   ⚠ config.txt nicht lesbar ({e}).",
                        f"   ⚠ cannot read config.txt ({e}).") + C.RESET)
        return
    hat_wifi = "dtoverlay=disable-wifi" in inhalt
    hat_bt = "dtoverlay=disable-bt" in inhalt
    if hat_wifi and hat_bt:
        print(C.GRN + t(" ✔ Funkchips sind bereits auf Firmware-Ebene deaktiviert.",
                        " ✔ Radio chips are already disabled at firmware level.") + C.RESET)
        return
    try:
        zusatz = "\n# QUANTUM SEED GENERATOR: Funk dauerhaft deaktiviert\n"
        if not hat_wifi:
            zusatz += "dtoverlay=disable-wifi\n"
        if not hat_bt:
            zusatz += "dtoverlay=disable-bt\n"
        with open(pfad, "a") as f:
            f.write(zusatz)
        print(C.GRN + t(f" ✔ WLAN+Bluetooth dauerhaft deaktiviert ({pfad}) — wirksam ab "
                        "dem naechsten Boot.",
                        f" ✔ WLAN+Bluetooth permanently disabled ({pfad}) — effective "
                        "from the next boot.") + C.RESET)
    except Exception as e:
        print(C.YEL + t(f"   ⚠ Firmware-Eintrag fehlgeschlagen ({e}) — rfkill-Block "
                        "bleibt aktiv.",
                        f"   ⚠ firmware entry failed ({e}) — rfkill block remains "
                        "active.") + C.RESET)


# ----------------------------------------------------------------------------
# Pflichtpruefung: Ethernet-Kabel muss entfernt werden
# ----------------------------------------------------------------------------
def _eth_verbunden():
    """Liste der Kabel-Interfaces mit aktivem Link (Kabel steckt)."""
    aktiv = []
    try:
        for n in os.listdir("/sys/class/net"):
            if n == "lo" or n.startswith(("wlan", "wl", "blu")):
                continue
            try:
                if open(f"/sys/class/net/{n}/carrier").read().strip() == "1":
                    aktiv.append(n)
            except OSError:
                pass          # Interface down -> kein aktiver Link
    except Exception:
        pass
    return aktiv

def require_ethernet_unplugged(args):
    """Erzwingt das physische Ziehen des Ethernet-Kabels: Solange ein
    Link erkannt wird, kommt das Programm nicht weiter. Nach der
    Ja-Bestaetigung wird der Zustand technisch nachgeprueft."""
    if args.mock:
        return
    if not _eth_verbunden():
        print(C.GRN + t(" ✔ Kein aktives Ethernet-Kabel erkannt.",
                        " ✔ No active Ethernet cable detected.") + C.RESET)
        return
    if args.yes:
        fail_abort("Ethernet-Pruefung / Ethernet check",
                   t("Ethernet-Kabel steckt — Automatikmodus bricht ab. Kabel "
                     "entfernen und neu starten.",
                     "Ethernet cable connected — automatic mode aborts. Remove "
                     "the cable and restart."))
    while True:
        aktiv = _eth_verbunden()
        if not aktiv:
            print(C.GRN + t(" ✔ Verifiziert: Ethernet getrennt — keine Internet-"
                            "verbindung ueber Kabel mehr moeglich.",
                            " ✔ Verified: Ethernet disconnected — no internet "
                            "connection via cable possible anymore.") + C.RESET)
            return
        print(C.RED + C.BOLD + t(
            f" ⚠ ETHERNET-KABEL ERKANNT ({', '.join(aktiv)}) — bitte das Kabel "
            "JETZT physisch entfernen!",
            f" ⚠ ETHERNET CABLE DETECTED ({', '.join(aktiv)}) — please remove "
            "the cable physically NOW!") + C.RESET)
        try:
            antwort = input(C.ORA + t(
                "   Wurde das Ethernet-Kabel entfernt? [ja/nein]: ",
                "   Has the Ethernet cable been removed? [yes/no]: ")
                + C.RESET + C.GRN).strip().lower()
            sys.stdout.write(C.RESET); sys.stdout.flush()
        except (EOFError, KeyboardInterrupt):
            sys.stdout.write(C.RESET)
            fail_abort("Ethernet-Pruefung / Ethernet check",
                       t("Vom Benutzer abgebrochen.", "aborted by user."))
        if antwort not in ("ja", "yes", "y"):
            continue
        time.sleep(1.0)       # Link-Status nach dem Ziehen kurz setzen lassen
        if _eth_verbunden():
            print(C.RED + t("   ✘ Nachpruefung: Es wird WEITERHIN ein aktiver "
                            "Ethernet-Link erkannt!",
                            "   ✘ Re-check: an active Ethernet link is STILL "
                            "detected!") + C.RESET)


# ----------------------------------------------------------------------------
# Optionale Ethernet-Abschaltung (sofort und/oder dauerhaft)
# ----------------------------------------------------------------------------
ETH_UNIT_PATH = "/etc/systemd/system/seedgen-ethernet-off.service"

# Spendenadresse des Projekts (leer lassen = Hinweis wird nie angezeigt).
# WICHTIG: Adresse zusaetzlich im README/in der Doku veroeffentlichen, damit
# Nutzer sie gegen die hier angezeigte querpruefen koennen (Adresstausch-Schutz).
DONATION_BTC = ""

def offer_ethernet_off(args):
    """Zwei getrennte, optionale Fragen: 1) Ethernet JETZT deaktivieren
    (ip link down, gilt bis zum Reboot). 2) DAUERHAFT deaktivieren (systemd-
    Dienst legt die Schnittstellen bei jedem Boot still)."""
    if args.yes or args.mock:
        return
    try:
        ifaces = [n for n in os.listdir("/sys/class/net")
                  if n != "lo" and not n.startswith(("wlan", "wl", "blu"))]
    except Exception:
        return
    if not ifaces:
        return
    import subprocess
    liste = ", ".join(ifaces)
    print(C.DIM + t(f"   Optional: Kabelnetzwerk ({liste}) laesst sich hier ebenfalls abschalten.",
                    f"   Optional: wired network ({liste}) can also be disabled here.") + C.RESET)
    # ---- Frage 1: sofort ----
    try:
        a1 = input(C.ORA + t("   Ethernet JETZT deaktivieren (gilt bis zum Reboot)? [ja/nein]: ",
                             "   Disable Ethernet NOW (until next reboot)? [yes/no]: ")
                   + C.RESET + C.GRN).strip().lower()
        sys.stdout.write(C.RESET); sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        sys.stdout.write(C.RESET); a1 = ""
    if a1 in ("ja", "yes", "y"):
        ok_ifs = []
        for i in ifaces:
            try:
                subprocess.run(["ip", "link", "set", i, "down"], check=True,
                               capture_output=True, timeout=10)
                ok_ifs.append(i)
            except Exception:
                pass
        if ok_ifs:
            print(C.GRN + t(f" ✔ Ethernet deaktiviert: {', '.join(ok_ifs)} (bis zum Reboot).",
                            f" ✔ Ethernet disabled: {', '.join(ok_ifs)} (until reboot).") + C.RESET)
        else:
            print(C.YEL + t("   ⚠ Ethernet-Deaktivierung fehlgeschlagen.",
                            "   ⚠ Ethernet disable failed.") + C.RESET)
    # ---- Frage 2: dauerhaft ----
    try:
        a2 = input(C.ORA + t("   Ethernet DAUERHAFT deaktivieren (bei jedem Boot)? [ja/nein]: ",
                             "   Disable Ethernet PERMANENTLY (at every boot)? [yes/no]: ")
                   + C.RESET + C.GRN).strip().lower()
        sys.stdout.write(C.RESET); sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        sys.stdout.write(C.RESET); a2 = ""
    if a2 not in ("ja", "yes", "y"):
        return
    try:
        befehle = " ; ".join(f"/usr/sbin/ip link set {i} down" for i in ifaces)
        unit = ("[Unit]\n"
                "Description=QUANTUM SEED GENERATOR: Ethernet dauerhaft deaktiviert\n"
                "After=network-pre.target\n\n"
                "[Service]\nType=oneshot\n"
                f"ExecStart=/bin/sh -c '{befehle}'\n\n"
                "[Install]\nWantedBy=multi-user.target\n")
        with open(ETH_UNIT_PATH, "w") as f:
            f.write(unit)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=15)
        subprocess.run(["systemctl", "enable", os.path.basename(ETH_UNIT_PATH)],
                       check=True, capture_output=True, timeout=15)
        print(C.GRN + t(f" ✔ Dauerhaft eingerichtet ({ETH_UNIT_PATH}) — Ethernet wird ab "
                        "jetzt bei jedem Boot stillgelegt.",
                        f" ✔ Permanently installed ({ETH_UNIT_PATH}) — Ethernet will be "
                        "taken down at every boot.") + C.RESET)
    except Exception as e:
        print(C.YEL + t(f"   ⚠ Dauerhafte Einrichtung fehlgeschlagen ({e}).",
                        f"   ⚠ Permanent setup failed ({e}).") + C.RESET)


# ----------------------------------------------------------------------------
# Finale Offline-Pruefung unmittelbar VOR der Seed-Anzeige
# ----------------------------------------------------------------------------
def _rfkill_blockiert(typ):
    """True = alle Geraete dieses Typs geblockt ODER keine vorhanden
    (Firmware-deaktiviert). False = mindestens ein Geraet aktiv.
    None = rfkill nicht verfuegbar."""
    import re as _re
    import subprocess
    try:
        out = subprocess.run(["rfkill", "list", typ], capture_output=True,
                             text=True, timeout=10).stdout
    except Exception:
        return None
    if not out.strip():
        return True
    for block in _re.split(r"\n(?=\d+:)", out):
        if ("Soft blocked: no" in block) and ("Hard blocked: no" in block):
            return False
    return True

def final_offline_check(args):
    """Letzte Verteidigungslinie: unmittelbar bevor der Seed sichtbar wird,
    werden WLAN, Bluetooth und Ethernet erneut geprueft. Wurde einer der
    Kanaele zwischenzeitlich reaktiviert (Manipulation), wird SOFORT
    beendet — der Seed erscheint nie auf dem Bildschirm."""
    if args.mock:
        return
    probleme = []
    # WLAN
    rf = _rfkill_blockiert("wlan")
    if rf is False:
        probleme.append("WLAN")
    elif rf is None:
        try:
            for n in os.listdir("/sys/class/net"):
                if n.startswith(("wlan", "wl")):
                    if open(f"/sys/class/net/{n}/operstate").read().strip() == "up":
                        probleme.append("WLAN")
                        break
        except Exception:
            probleme.append(t("WLAN (nicht pruefbar)", "WLAN (unverifiable)"))
    # Bluetooth
    rf = _rfkill_blockiert("bluetooth")
    if rf is False:
        probleme.append("Bluetooth")
    elif rf is None:
        try:
            if os.path.isdir("/sys/class/bluetooth") and os.listdir("/sys/class/bluetooth"):
                probleme.append(t("Bluetooth (nicht pruefbar)", "Bluetooth (unverifiable)"))
        except Exception:
            pass
    # Ethernet (Kabel gezogen ODER Interface deaktiviert)
    if _eth_verbunden():
        probleme.append("Ethernet")
    if not probleme:
        print(C.GRN + t(" ✔ Finale Offline-Pruefung bestanden: WLAN aus ✔  "
                        "Bluetooth aus ✔  Ethernet getrennt ✔",
                        " ✔ Final offline check passed: WLAN off ✔  "
                        "Bluetooth off ✔  Ethernet disconnected ✔") + C.RESET)
        return
    hr("━")
    print(C.RED + C.BOLD + t(
        " ✘ SICHERHEITSABBRUCH — MANIPULATION AN DER INTERNETVERBINDUNG FESTGESTELLT!",
        " ✘ SECURITY ABORT — TAMPERING WITH THE INTERNET CONNECTION DETECTED!") + C.RESET)
    print(C.RED + t(
        f"   Folgende Kanaele wurden zwischenzeitlich (re-)aktiviert: {', '.join(probleme)}",
        f"   The following channels were (re-)activated in the meantime: {', '.join(probleme)}")
        + C.RESET)
    print(C.RED + t(
        "   Der Seed wird NICHT angezeigt. Geraet pruefen, Ursache klaeren und das",
        "   The seed will NOT be displayed. Inspect the device, determine the cause") + C.RESET)
    print(C.RED + t(
        "   Programm neu starten fuer neue Seederzeugung.",
        "   and restart the program for new seed generation.") + C.RESET)
    hr("━")
    sys.exit(3)


# ----------------------------------------------------------------------------
# Keine Spuren auf dem Datentraeger: Swap-Pruefung + Aufraeumen am Ende
# ----------------------------------------------------------------------------
def check_swap(args):
    """Aktiver Swap koennte Entropie/Seed aus dem RAM auf die SD-Karte
    auslagern. Wird hier deaktiviert (Skript laeuft als root)."""
    def swap_aktiv():
        try:
            return len(open("/proc/swaps").read().strip().splitlines()) > 1
        except Exception:
            return False
    if not swap_aktiv():
        print(C.GRN + t(" ✔ Kein aktiver Swap — RAM-Daten koennen nicht auf die SD-Karte auslaufen.", " ✔ No active swap — RAM data cannot leak onto the SD card.") + C.RESET)
        return
    import subprocess
    try:
        subprocess.run(["swapoff", "-a"], check=True, capture_output=True, timeout=30)
    except Exception:
        pass
    if not swap_aktiv():
        print(C.GRN + " \u2714 Swap war aktiv und wurde deaktiviert (swapoff -a)." + C.RESET)
        return
    if args.mock:
        print(C.YEL + " \u26a0 Swap aktiv, Deaktivierung fehlgeschlagen \u2014 im MOCK-Modus "
              "toleriert." + C.RESET)
        return
    print(C.RED + C.BOLD + " \u26a0 Swap ist AKTIV und konnte nicht deaktiviert werden \u2014 "
          "Seed-Daten koennten auf die SD-Karte gelangen!" + C.RESET)
    if args.yes:
        fail_abort("Swap-Pruefung", "Automatikmodus bricht mit aktivem Swap ab.")
    antwort = input("   Trotzdem fortfahren? Nur 'ja' setzt fort: ").strip().lower()
    if antwort not in ("ja", "yes", "y"):
        fail_abort("Swap-Pruefung", "Vom Benutzer abgebrochen \u2014 "
                   "sudo swapoff -a ausfuehren und neu starten.")

def verify_seed_transcription(idx, words_list, args):
    """Audit H6: Nutzer kann die notierte Phrase erneut eingeben; Abgleich
    gegen die erzeugten Woerter deckt Abschreibfehler auf. Optional."""
    if args.yes or args.mock or not words_list or not sys.stdin.isatty():
        return
    print(C.RED + C.BOLD + t(
        "   ✋ WICHTIG — SO VERIFIZIERST DU RICHTIG:",
        "   ✋ IMPORTANT — HOW TO VERIFY CORRECTLY:") + C.RESET)
    print(C.RED + t(
        "   1. Schreibe JETZT alle Woerter von Hand auf Papier — UNBEDINGT MIT den",
        "   1. NOW write all words on paper by hand — you MUST include the") + C.RESET)
    print(C.RED + t(
        "      Nummern davor (1., 2., 3., …)! Die Nummern dokumentieren die",
        "      numbers in front of them (1., 2., 3., …)! The numbers document the") + C.RESET)
    print(C.RED + C.BOLD + t(
        "      REIHENFOLGE — mit falscher Reihenfolge ist der Seed wertlos und die",
        "      ORDER — with a wrong order the seed is worthless and the wallet") + C.RESET)
    print(C.RED + C.BOLD + t(
        "      Wallet unwiederbringlich verloren!",
        "      irrecoverably lost!") + C.RESET)
    print(C.RED + t(
        "   2. Lies die Woerter bei der Kontrolle NUR vom PAPIER ab — NICHT vom Bildschirm!",
        "   2. For the check, read the words ONLY from your PAPER — NOT from the screen!") + C.RESET)
    print(C.RED + t(
        "      Nur wenn du vom Papier abliest, wird deine Abschrift wirklich auf Fehler",
        "      Only by reading from the paper is your transcription actually checked") + C.RESET)
    print(C.RED + t(
        "      geprueft — sonst validierst du den Bildschirm statt deiner Aufzeichnung.",
        "      for errors — otherwise you validate the screen instead of your record.") + C.RESET)
    try:
        antwort = input(C.ORA + t("   Woerter VOM PAPIER ablesen und zur Kontrolle eingeben? [ja/nein]: ",
                                  "   Read the words FROM YOUR PAPER and enter them for verification? [yes/no]: ")
                        + C.RESET + C.GRN).strip().lower()
        sys.stdout.write(C.RESET); sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        sys.stdout.write(C.RESET)
        return
    if antwort not in ("ja", "yes", "y"):
        return
    print(C.DIM + t("   Alle Woerter VOM PAPIER in einer Zeile (Leerzeichen und/oder Kommas als Trenner):",
                    "   All words FROM YOUR PAPER on one line (spaces and/or commas as separators):") + C.RESET)
    try:
        roh = input(C.ORA + "   > " + C.RESET + C.GRN).strip().lower()
        sys.stdout.write(C.RESET); sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        sys.stdout.write(C.RESET)
        return
    # Tolerantes Parsen: Kommas/Semikolons wie Leerzeichen behandeln,
    # Nummerierungen wie "1." oder "(1)" ignorieren
    import re as _re
    eingabe = [w for w in _re.split(r"[\s,;]+", roh)
               if w and not _re.fullmatch(r"\(?\d+[.)]?", w)]
    soll = [words_list[i] for i in idx]
    if eingabe == soll:
        print(C.GRN + t("   ✔ Verifikation erfolgreich — Abschrift stimmt exakt ueberein.",
                        "   ✔ Verification successful — transcription matches exactly.") + C.RESET)
        return
    fehler = []
    for pos in range(max(len(soll), len(eingabe))):
        a = soll[pos] if pos < len(soll) else "(fehlt/missing)"
        b = eingabe[pos] if pos < len(eingabe) else "(fehlt/missing)"
        if a != b:
            fehler.append(pos + 1)
    if len(eingabe) != len(soll):
        print(C.YEL + t(f"   Hinweis: {len(eingabe)} Woerter gelesen, {len(soll)} erwartet.",
                        f"   Note: read {len(eingabe)} words, expected {len(soll)}.") + C.RESET)
    erste = fehler[0]
    gelesen = eingabe[erste-1] if erste-1 < len(eingabe) else t("(fehlt)", "(missing)")
    print(C.RED + C.BOLD + t(f"   ✘ ABWEICHUNG an Position(en): {fehler} — Abschrift "
                             "korrigieren und erneut pruefen!",
                             f"   ✘ MISMATCH at position(s): {fehler} — correct the "
                             "transcription and verify again!") + C.RESET)
    print(C.DIM + t(f"   (An Position {erste} wurde gelesen: '{gelesen}')",
                    f"   (At position {erste} the input read: '{gelesen}')") + C.RESET)
    verify_seed_transcription(idx, words_list, args)


def _wipe_screen():
    """Bildschirm + Scrollback wirklich loeschen — in der EINZIG sicheren
    Reihenfolge: Home, dann 2J (manche Terminals schieben den Inhalt dabei
    in den Verlauf), dann ERST 3J (purgt den Verlauf inkl. des gerade
    Verschobenen). Danach 'clear' als terminfo-Fallback und die Sequenz
    erneut — Guertel und Hosentraeger."""
    seq = "\033[H\033[2J\033[3J"
    sys.stdout.write(seq)
    sys.stdout.flush()
    try:
        os.system("clear 2>/dev/null")
    except Exception:
        pass
    sys.stdout.write(seq)
    sys.stdout.flush()

def show_donation():
    """Optionaler Spendenhinweis — erscheint erst NACH der Bildschirmloeschung,
    wenn kein Seed mehr sichtbar ist. QR via qrencode (falls installiert),
    sonst nur die Adresse als Text. Best-effort, niemals stoerend."""
    if not DONATION_BTC:
        return
    import shutil as _sh
    import subprocess as _sp
    print()
    print(C.DIM + t(" Dieses Projekt ist frei und offen. Wenn es dir geholfen hat,",
                    " This project is free and open. If it helped you,") + C.RESET)
    print(C.DIM + t(" freut sich die Entwicklung ueber eine BTC-Spende:",
                    " the development appreciates a BTC donation:") + C.RESET)
    print(C.ORA + f"   {DONATION_BTC}" + C.RESET)
    if _sh.which("qrencode"):
        try:
            r = _sp.run(["qrencode", "-t", "ANSIUTF8", f"bitcoin:{DONATION_BTC}"],
                        capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout:
                print(r.stdout)
        except Exception:
            pass
    print(C.DIM + t(" (Erst scannen, wenn der Seed sicher verstaut ist und wieder",
                    " (Only scan once the seed is safely stored and phones are") + C.RESET)
    print(C.DIM + t("  Handys im Raum erlaubt sind. Adresse gegen die im README",
                    "  allowed in the room again. Cross-check the address against") + C.RESET)
    print(C.DIM + t("  veroeffentlichte querpruefen!)",
                    "  the one published in the README!)") + C.RESET)


def secure_cleanup(args):
    """Nach der Seed-Anzeige: Bildschirm inkl. Scrollback loeschen und auf
    Wunsch die Bash-History-Dateien leeren. Das Skript selbst schreibt zu
    keinem Zeitpunkt Entropie- oder Seed-Daten auf einen Datentraeger."""
    hr()
    print(C.BOLD + t(" Aufraeumen (keine Spuren)", " Cleanup (no traces)") + C.RESET)
    print(C.DIM + t("   Hinweis: Alle Entropie- und Seed-Daten wurden ausschliesslich im RAM verarbeitet;", "   Note: all entropy and seed data was processed exclusively in RAM;") + C.RESET)
    print(C.DIM + t("   dieses Skript hat keine Datei geschrieben.", "   this script has not written any file.") + C.RESET)
    if args.yes:
        if sys.stdin.isatty():
            # Audit M2: Mensch am Terminal -> gleicher Loesch-Dialog wie interaktiv
            try:
                input(C.BOLD + t("   [--yes] Seed notiert? [Enter] loescht Bildschirm + Scrollback … ",
                                 "   [--yes] Seed written down? [Enter] erases screen + scrollback … ") + C.RESET)
            except (EOFError, KeyboardInterrupt):
                pass
            _wipe_screen()
            print(C.GRN + t(" ✔ Bildschirmanzeige und Scrollback geloescht.",
                            " ✔ Screen display and scrollback erased.") + C.RESET)
        else:
            print(C.YEL + t("   (--yes ohne TTY: Bildschirm nicht loeschbar — Aufrufer muss "
                            "die Ausgabe selbst entsorgen; optional: history -c)",
                            "   (--yes without TTY: cannot clear screen — the caller must "
                            "dispose of the output; optionally: history -c)") + C.RESET)
        return
    try:
        input(C.BOLD + t("   Seed sicher auf Papier notiert? [Enter] loescht jetzt die komplette Bildschirmanzeige … ", "   Seed safely written down on paper? [Enter] now erases the entire screen display … ") + C.RESET)
    except (EOFError, KeyboardInterrupt):
        pass
    # Bildschirm + Scrollback-Puffer des Terminals loeschen
    _wipe_screen()
    print(C.GRN + t(" \u2714 Bildschirmanzeige und Scrollback geloescht.", " \u2714 Screen display and scrollback erased.") + C.RESET)
    try:
        antwort = input(t("   Bash-Verlaufsdateien (.bash_history) zusaetzlich leeren? [ja/nein]: ", "   Also clear bash history files (.bash_history)? [yes/no]: ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        antwort = "nein"
    if antwort in ("ja", "yes", "y"):
        kandidaten = ["/root/.bash_history"]
        su = os.environ.get("SUDO_USER")
        if su:
            kandidaten.append(f"/home/{su}/.bash_history")
        for p in kandidaten:
            try:
                if os.path.exists(p):
                    open(p, "w").close()
                    print(C.GRN + t(f"   \u2714 geleert: {p}", f"   \u2714 cleared: {p}") + C.RESET)
            except Exception as e:
                print(C.YEL + f"   \u26a0 {p}: {e}" + C.RESET)
        print(C.DIM + t("   Hinweis: Die laufende Shell haelt ihren Verlauf im RAM — dieses Terminalfenster", "   Note: the running shell keeps its history in RAM — CLOSE this terminal window") + C.RESET)
        print(C.DIM + t("   jetzt SCHLIESSEN (oder 'history -c' ausfuehren), damit nichts zurueckgeschrieben wird.", "   now (or run 'history -c') so nothing gets written back.") + C.RESET)
    else:
        print(C.DIM + t("   Verlaufsdateien unveraendert. Empfehlung: Terminalfenster schliessen.", "   History files unchanged. Recommendation: close the terminal window.") + C.RESET)

# ----------------------------------------------------------------------------
# Hardware-Initialisierungstest (Healthcheck vor Beginn)
# ----------------------------------------------------------------------------
def startup_healthcheck(mock: bool, light: bool = False):
    """Jede Hardware-Quelle muss 10 unterschiedliche Signale in Folge liefern,
    die Daten werden angezeigt. Erst danach laeuft das Skript weiter."""
    hr()
    print(C.BOLD + t(" Hardware-Initialisierungstest — je 10 Signale pro Quelle", " Hardware initialization test — 10 signals per source") + C.RESET)
    print(C.DIM + t(" (Wuerfel sind eine manuelle Quelle und werden hier nicht getestet)", " (Dice are a manual source and are not tested here)") + C.RESET)

    if light:
        print(C.DIM + t(" LIGHT-Modus: nur der HWRNG wird geprueft.",
                        " LIGHT mode: only the HWRNG is tested.") + C.RESET)
    # ---- Check 1: BCM2712 HWRNG --------------------------------------------
    print(C.BOLD + f"\n [Check 1/{'1' if light else '3'}] BCM2712 HWRNG" + C.RESET)
    proben = []
    for i in range(10):
        if mock:
            raw = os.urandom(8)
        else:
            try:
                with open("/dev/hwrng", "rb") as f:
                    raw = f.read(8)
            except Exception as e:
                fail_abort("HWRNG (Initialisierungstest)",
                           t(f"Lesefehler: {e} — Skript mit sudo starten!",
                             f"Read error: {e} — start the script with sudo!"))
        if not raw or len(raw) != 8:
            fail_abort("HWRNG (Initialisierungstest)", "Unvollstaendige Probe gelesen.")
        proben.append(raw)
        print(f"   Probe {i+1:2d}/10: {raw.hex()}")
    if len(set(proben)) != 10:
        fail_abort("HWRNG (Initialisierungstest)",
                   "Mindestens zwei von 10 Proben identisch — RNG liefert keine frischen Daten.")
    print(C.GRN + t("   ✔ 10/10 unterschiedliche Zufallsproben", "   ✔ 10/10 distinct random samples") + C.RESET)
    if light:
        hr()
        print(C.GRN + C.BOLD + t(" ✔ HARDWARE-CHECK BESTANDEN (LIGHT) — HWRNG liefert lebendige Signale.",
                                 " ✔ HARDWARE CHECK PASSED (LIGHT) — HWRNG delivers live signals.") + C.RESET)
        play_success_jingle()
        return None

    # ---- Check 2/3: Radiozerfall (CAJOE) -----------------------------------
    print(C.BOLD + t("\n [Check 2/3] Radiozerfall (CAJOE) — warte auf 10 Ereignisse …", "\n [Check 2/3] Radioactive decay (CAJOE) — waiting for 10 events …") + C.RESET)
    ts_list = []
    if mock:
        import random
        ts_val = time.monotonic_ns()
        for i in range(10):
            ts_val += int(random.expovariate(0.5) * 1e9)
            ts_list.append(ts_val)
            d = (ts_list[-1] - ts_list[-2]) / 1e9 if i else 0.0
            print(f"   Signal {i+1:2d}/10: t = {ts_val} ns   Δ = {d:7.3f} s  [MOCK]")
    else:
        try:
            import lgpio
        except ImportError:
            fail_abort("Radiozerfall (Initialisierungstest)",
                       "Python-Modul 'lgpio' fehlt: sudo apt install python3-lgpio")
        handle, edge = find_rp1_chip(lgpio, GPIO_GEIGER)
        if handle is None:
            fail_abort("Radiozerfall (Initialisierungstest)",
                       f"GPIO{GPIO_GEIGER} konnte nicht belegt werden.")
        def _cb(chip, gpio, level, ts_ns):
            if ts_list and ts_ns - ts_list[-1] < DECAY_DEBOUNCE_NS:
                return
            ts_list.append(ts_ns)
        cb = lgpio.callback(handle, GPIO_GEIGER, edge, _cb)
        gezeigt = 0
        letzte_aktivitaet = time.monotonic()
        try:
            while gezeigt < 10:
                time.sleep(0.1)
                while gezeigt < min(len(ts_list), 10):
                    ts_val = ts_list[gezeigt]
                    d = (ts_val - ts_list[gezeigt-1]) / 1e9 if gezeigt else 0.0
                    print(f"   Signal {gezeigt+1:2d}/10: t = {ts_val} ns   Δ = {d:7.3f} s")
                    gezeigt += 1
                    letzte_aktivitaet = time.monotonic()
                if time.monotonic() - letzte_aktivitaet > DECAY_TIMEOUT_S:
                    fail_abort("Radiozerfall (Initialisierungstest)",
                               f"{DECAY_TIMEOUT_S}s ohne Zerfallsereignis.")
        except KeyboardInterrupt:
            fail_abort("Radiozerfall (Initialisierungstest)", "Vom Benutzer abgebrochen.")
        finally:
            try:
                cb.cancel(); lgpio.gpiochip_close(handle)
            except Exception:
                pass
    if sorted(ts_list) != ts_list or len(set(ts_list)) != len(ts_list):
        fail_abort("Radiozerfall (Initialisierungstest)",
                   "Zeitstempel nicht streng aufsteigend — Messung unplausibel.")
    deltas = [round((b - a) / 1e9, 2) for a, b in zip(ts_list, ts_list[1:])]
    if len(set(deltas)) < 3:
        fail_abort("Radiozerfall (Initialisierungstest)",
                   "Pulsintervalle nahezu konstant — Stoerquelle statt Zerfall?")
    span_s = (ts_list[-1] - ts_list[0]) / 1e9
    cpm_mess = (len(ts_list) - 1) / span_s * 60 if span_s > 0 else 0.0
    print(C.DIM + t(f"   Gemessene Zaehlrate: {cpm_mess:.1f} CPM",
                    f"   Measured count rate: {cpm_mess:.1f} CPM") + C.RESET)
    print(C.GRN + t("   ✔ 10/10 Ereignisse, Intervalle unregelmaessig (zerfallstypisch)", "   ✔ 10/10 events, irregular intervals (decay-typical)") + C.RESET)

    # ---- Check 3/3: MLX90640 IR-Kamera -------------------------------------
    print(C.BOLD + "\n [Check 3/3] MLX90640 IR-Kamera" + C.RESET)
    hashes = []
    if mock:
        for i in range(10):
            frame = os.urandom(832 * 2)
            h = hashlib.sha256(frame).hexdigest()
            hashes.append(h)
            print(f"   Frame {i+1:2d}/10: SHA256 {h[:16]}…  (" + t("erste Rohworte", "first raw words") + f": {frame[:6].hex()}) [MOCK]")
    else:
        try:
            from smbus2 import SMBus, i2c_msg
        except ImportError:
            fail_abort("MLX90640 (Initialisierungstest)",
                       "Python-Modul 'smbus2' fehlt: sudo apt install python3-smbus2")
        try:
            bus = SMBus(MLX_I2C_BUS)
        except OSError as e:
            fail_abort("MLX90640 (Initialisierungstest)", f"I2C-Bus nicht verfuegbar: {e}")
        try:
            for i in range(10):
                t0 = time.monotonic()
                while True:
                    st = _mlx_read_words(bus, 0x8000, 1)
                    if st[1] & 0x08:
                        break
                    if time.monotonic() - t0 > 5:
                        fail_abort("MLX90640 (Initialisierungstest)",
                                   "Timeout beim Warten auf neues Frame (Adresse 0x33?).")
                    time.sleep(0.02)
                frame = _mlx_read_words(bus, 0x0400, 832)
                wmsg = i2c_msg.write(MLX_I2C_ADDR, [0x80, 0x00, 0x00, 0x30])
                bus.i2c_rdwr(wmsg)
                if len(set(frame)) < 8:
                    fail_abort("MLX90640 (Initialisierungstest)",
                               "Frame mit nahezu konstantem Inhalt — Sensor defekt?")
                h = hashlib.sha256(frame).hexdigest()
                hashes.append(h)
                print(f"   Frame {i+1:2d}/10: SHA256 {h[:16]}…  (" + t("erste Rohworte", "first raw words") + f": {bytes(frame[:6]).hex()})")
        except OSError as e:
            fail_abort("MLX90640 (Initialisierungstest)", f"I2C-Fehler: {e}")
        finally:
            try: bus.close()
            except Exception: pass
    if len(set(hashes)) != 10:
        fail_abort("MLX90640 (Initialisierungstest)",
                   "Identische Frames erkannt — kein lebendiges Sensorrauschen.")
    print(C.GRN + t("   ✔ 10/10 unterschiedliche Frames (Sensorrauschen vorhanden)", "   ✔ 10/10 distinct frames (sensor noise present)") + C.RESET)

    hr()
    print(C.GRN + C.BOLD + t(" ✔ HARDWARE-CHECK BESTANDEN — alle Quellen liefern lebendige Signale.", " ✔ HARDWARE CHECK PASSED — all sources deliver live signals.") + C.RESET)
    play_success_jingle()
    return cpm_mess

# ----------------------------------------------------------------------------
# Interaktive Konfiguration
# ----------------------------------------------------------------------------
def ask_int(prompt, default, lo, hi):
    """Frage in Orange, Nutzereingabe in Gruen (Erklaertexte bleiben normal)."""
    while True:
        s = input(C.ORA + f"   {prompt} [{default}]: " + C.RESET + C.GRN).strip()
        sys.stdout.write(C.RESET)
        sys.stdout.flush()
        if not s:
            return default
        try:
            v = int(s)
            if lo <= v <= hi:
                return v
        except ValueError:
            pass
        print(C.YEL + t(f"   Bitte Zahl zwischen {lo} und {hi} eingeben.", f"   Please enter a number between {lo} and {hi}.") + C.RESET)

def min_decay_events(target_bits: int) -> int:
    """Mindestzahl Zerfallsereignisse, damit die konservativ kreditierten
    2 Bit/Ereignis allein schon die Ziel-Entropie abdecken."""
    return math.ceil(target_bits / DECAY_BITS_PER_EVENT)

def configure(args, cpm_mess=None):
    cpm = cpm_mess if cpm_mess and cpm_mess > 0 else 9.0
    if args.yes:
        target = 256 if args.words == 24 else 128
        mind = min_decay_events(target)
        if args.decay < mind:
            fail_abort("Konfiguration",
                       f"--decay {args.decay} unterschreitet das Minimum von {mind} "
                       f"Ereignissen ({mind} x {DECAY_BITS_PER_EVENT} Bit = {target} Bit).")
        dice_min = 100 if args.light else DICE_MIN_ROLLS
        if args.dice < dice_min:
            fail_abort("Konfiguration",
                       f"--dice {args.dice} unterschreitet das Minimum von "
                       f"{dice_min} Wuerfelwuerfen"
                       + (" (LIGHT-Modus)." if args.light else "."))
        if args.light:
            return args.words, 0, 0, args.dice, args.transparenz
        if args.frames < CAM_MIN_FRAMES:
            fail_abort("Konfiguration",
                       t(f"--frames {args.frames} unterschreitet das Minimum von "
                         f"{CAM_MIN_FRAMES} Kamera-Frames.",
                         f"--frames {args.frames} is below the minimum of "
                         f"{CAM_MIN_FRAMES} camera frames."))
        return args.words, args.decay, args.frames, args.dice, args.transparenz
    print(C.BOLD + t("\n Modusauswahl", "\n Mode selection") + C.RESET)
    print(t("   [1] STANDARD-MODUS    — kompakte Fortschrittsanzeigen", "   [1] STANDARD MODE     — compact progress displays"))
    print(t("   [2] TRANSPARENZ-MODUS — alle Quelldaten & Hashwerte in Echtzeit", "   [2] TRANSPARENCY MODE — all source data & hashes in real time"))
    transparent = ask_int(t("Modus waehlen", "Select mode"), 2 if args.transparenz else 1, 1, 2) == 2
    if transparent:
        print(C.YEL + t("   ⚠ TRANSPARENZ-MODUS: Es werden geheime Zwischenwerte (bis hin zur Seed-Entropie)\n     am Bildschirm angezeigt. Sicherstellen, dass niemand mitliest/mitfilmt!", "   ⚠ TRANSPARENCY MODE: secret intermediate values (up to the seed entropy)\n     are shown on screen. Make sure nobody is watching/filming!") + C.RESET)
    print(C.BOLD + t("\n Konfiguration", "\n Configuration") + C.RESET)
    while True:
        w_in = ask_int(t("Seed-Laenge: 12 oder 24 Woerter", "Seed length: 12 or 24 words"), args.words, 12, 24)
        if w_in in (12, 24):
            words = w_in
            break
        print(C.YEL + t("   Bitte exakt 12 oder 24 eingeben.", "   Please enter exactly 12 or 24.") + C.RESET)
    target = 256 if words == 24 else 128
    rec_dice = math.ceil(target / DICE_BITS_PER_ROLL)
    print(C.DIM + t(f"   Ziel-Entropie: {target} Bit", f"   Target entropy: {target} bits") + C.RESET)
    print(C.DIM + t(f"   Betriebsart: {'LIGHT (HWRNG + Wuerfel)' if args.light else 'FULL (4 Quellen)'}",
                    f"   Operating mode: {'LIGHT (HWRNG + dice)' if args.light else 'FULL (4 sources)'}") + C.RESET)
    if args.light:
        print(C.DIM + t("   Wuerfel: 100 = volle 256-Bit-Unabhaengigkeit; mehr = Marge gegen unperfekte Wuerfel",
                        "   Dice: 100 = full 256-bit independence; more = margin against imperfect dice") + C.RESET)
        dice = ask_int(t("Wuerfelwuerfe (Minimum 100)", "Dice rolls (minimum 100)"),
                       max(args.dice, 100), 100, 1000)
        return words, 0, 0, dice, transparent
    mind = min_decay_events(target)
    print(C.DIM + t(f"   Minimum Zerfallsereignisse: {mind}  ({mind} x {DECAY_BITS_PER_EVENT} Bit konservativ = {target} Bit)", f"   Minimum decay events: {mind}  ({mind} x {DECAY_BITS_PER_EVENT} bits conservative = {target} bits)") + C.RESET)
    print(C.DIM + t(f"   Realistische Dauer bei gemessenen {cpm:.1f} CPM:  128 Ereignisse ≈ {128/cpm:.0f} min   ·   1024 Ereignisse ≈ {1024/cpm:.0f} min",
                    f"   Realistic duration at measured {cpm:.1f} CPM:  128 events ≈ {128/cpm:.0f} min   ·   1024 events ≈ {1024/cpm:.0f} min") + C.RESET)
    decay  = ask_int(t(f"Zerfallsereignisse (Minimum {mind}, Empf. \u2265{max(512, 2*target)}; ~{cpm:.0f} CPM \u21d2 {max(512,2*target)/cpm:.0f} min)", f"Decay events (minimum {mind}, recomm. \u2265{max(512, 2*target)}; ~{cpm:.0f} CPM \u21d2 {max(512,2*target)/cpm:.0f} min)"),
                     max(args.decay, mind), mind, 100000)

    frames = ask_int(t(f"Kamera-Frames MLX90640 (Minimum {CAM_MIN_FRAMES}, Empf. ≥16)", f"Camera frames MLX90640 (minimum {CAM_MIN_FRAMES}, recomm. ≥16)"), max(args.frames, CAM_MIN_FRAMES), CAM_MIN_FRAMES, 1000)
    print(C.DIM + t(f"   Minimum Wuerfelwuerfe: {DICE_MIN_ROLLS} (~{DICE_MIN_ROLLS*DICE_BITS_PER_ROLL:.0f} Bit) — fuer volle Hardware-Unabhaengigkeit {rec_dice} empfohlen", f"   Minimum dice rolls: {DICE_MIN_ROLLS} (~{DICE_MIN_ROLLS*DICE_BITS_PER_ROLL:.0f} bits) — {rec_dice} recommended for full hardware independence") + C.RESET)
    dice   = ask_int(t(f"Wuerfelwuerfe (Minimum {DICE_MIN_ROLLS}, Empf. \u2265{rec_dice})", f"Dice rolls (minimum {DICE_MIN_ROLLS}, recomm. \u2265{rec_dice})"),
                     max(args.dice, DICE_MIN_ROLLS), DICE_MIN_ROLLS, 1000)
    return words, decay, frames, dice, transparent

# ----------------------------------------------------------------------------
# Hauptablauf
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="BIP39-Seed-Generator mit Hardware-Entropie")
    ap.add_argument("--selftest", action="store_true", help="Krypto-Selbsttests ausfuehren")
    ap.add_argument("--mock", action="store_true",
                    help="Hardware simulieren — NUR ZUM TESTEN, NIE fuer echte Seeds!")
    ap.add_argument("--yes", action="store_true", help="Konfigurationsfragen ueberspringen")
    ap.add_argument("--light", action="store_true",
                    help="LIGHT-Modus: nur HWRNG + Wuerfel (ohne Geigerzaehler/Kamera)")
    ap.add_argument("--keep-wifi", action="store_true",
                    help="WLAN+Bluetooth NICHT deaktivieren (nicht empfohlen)")
    ap.add_argument("--transparenz", action="store_true",
                    help="Transparenz-Modus: alle Quelldaten & Hashes anzeigen")
    ap.add_argument("--lang", choices=("de", "en"), default="de",
                    help="Sprache / language (fuer --yes; interaktiv wird gefragt)")
    ap.add_argument("--words",  type=int, default=24, choices=(12, 24))
    ap.add_argument("--decay",  type=int, default=1024)
    ap.add_argument("--frames", type=int, default=32)
    ap.add_argument("--dice",   type=int, default=100)
    args = ap.parse_args()
    # Audit N1: Core-Dumps koennten Entropie/Seed auf die SD-Karte schreiben
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    # Harte Bereichsgrenzen fuer alle Pfade (Audit M5)
    if args.words not in (12, 24):
        ap.error("--words muss 12 oder 24 sein / must be 12 or 24")
    if not (1 <= args.decay <= 100000):
        ap.error("--decay ausserhalb 1..100000")
    if not (CAM_MIN_FRAMES <= args.frames <= 1000):
        ap.error(f"--frames ausserhalb {CAM_MIN_FRAMES}..1000")
    if not (1 <= args.dice <= 1000):
        ap.error("--dice ausserhalb 1..1000")

    if args.selftest:
        selftest()
        return

    global LANG
    if args.yes:
        LANG = args.lang
    else:
        print("\n Sprache / Language:   [1] Deutsch    [2] English")
        try:
            wahl = input(" > ").strip()
        except (EOFError, KeyboardInterrupt):
            wahl = "1"
        LANG = "en" if wahl == "2" else "de"

    if not args.yes:
        print(C.BOLD + t("\n Betriebsart / Umfang", "\n Operating mode / scope") + C.RESET)
        print(t("   [1] LIGHT-MODUS — HWRNG + Wuerfel (kein Geigerzaehler, keine Kamera; Pi 4 + Pi 5)",
                "   [1] LIGHT MODE  — HWRNG + dice (no Geiger counter, no camera; Pi 4 + Pi 5)"))
        print(t("   [2] FULL-MODUS  — alle 4 Quellen inkl. Quanten-Zerfall (Referenz: Pi 5)",
                "   [2] FULL MODE   — all 4 sources incl. quantum decay (reference: Pi 5)"))
        args.light = ask_int(t("Betriebsart waehlen", "Select operating mode"),
                             1 if args.light else 2, 1, 2) == 1
        if args.light:
            print(C.DIM + t("   LIGHT: Die Sicherheitslast traegt der HMAC-Kombinierer — Minimum 100 Wuerfe.",
                            "   LIGHT: the HMAC combiner carries the security — minimum 100 rolls.") + C.RESET)

    banner()
    time.sleep(3)       # Logo 3 s wirken lassen, bevor weiterer Output folgt
    security_briefing(args)
    selftest()          # Selbsttest laeuft VOR jeder echten Erzeugung
    hr()
    require_root(args)
    check_remote_session(args)
    disable_wifi(args)
    enforce_permanent_radio_off(args)
    require_ethernet_unplugged(args)
    offer_ethernet_off(args)
    check_swap(args)
    hr()

    if args.mock:
        print(C.RED + C.BOLD + t(" ⚠  MOCK-MODUS: simulierte Hardware — erzeugte Seeds NIEMALS fuer echte Wallets verwenden!", " ⚠  MOCK MODE: simulated hardware — NEVER use generated seeds for real wallets!") + C.RESET)

    words_list, wl_path = load_wordlist()
    if words_list is None and not args.mock:
        fail_abort("BIP39-Wortliste",
                   "Keine verifizierbare english.txt gefunden. Bitte die offizielle "
                   "BIP39-Wortliste als 'english.txt' neben das Skript legen "
                   "(SHA-256 wird automatisch geprueft).")

    cpm_mess = startup_healthcheck(args.mock, args.light)

    n_words, n_decay, n_frames, n_dice, transparent = configure(args, cpm_mess)
    if transparent:
        print(C.CYA + C.BOLD + t(" ► TRANSPARENZ-MODUS AKTIV", " ► TRANSPARENCY MODE ACTIVE") + C.RESET)
    target_bits = 256 if n_words == 24 else 128
    n_bytes = target_bits // 8

    hr()
    print(C.BOLD + t(" Ablaufplan (feste Reihenfolge)", " Process plan (fixed order)") + C.RESET)
    status_line(1, 4, "BCM2712 HWRNG",        "wait", t("einmalige Entnahme (512 Bit)", "one-time extraction (512 bits)"))
    status_line(2, 4, t("Radiozerfall (CAJOE)", "Radioactive decay (CAJOE)"), "wait", t(f"{n_decay} Ereignisse", f"{n_decay} events"))
    status_line(3, 4, t("MLX90640 IR-Kamera", "MLX90640 IR camera"), "wait", t(f"{n_frames} Roh-Frames", f"{n_frames} raw frames"))
    status_line(4, 4, t("Wuerfel (manuell)", "Dice (manual)"), "wait", t(f"{n_dice} Wuerfe — letzte Quelle", f"{n_dice} rolls — final source"))
    hr()

    results = []
    t0 = time.monotonic()

    ph_total = 2 if args.light else 4
    print(C.BOLD + t(f"\n Phase 1/{ph_total} — BCM2712 HWRNG", f"\n Phase 1/{ph_total} — BCM2712 HWRNG") + C.RESET)
    r = collect_hwrng(args.mock, transparent); results.append(r)
    status_line(1, ph_total, r.name, "ok", r.info)

    if not args.light:
        print(C.BOLD + t("\n Phase 2/4 — Radioaktiver Zerfall", "\n Phase 2/4 — Radioactive decay") + C.RESET)
        cpm_hint = cpm_mess if cpm_mess and cpm_mess > 0 else 9.0
        print(C.DIM + t(f"   (Erwartete Dauer bei gemessenen {cpm_hint:.1f} CPM: ca. {n_decay/cpm_hint:.0f} min fuer {n_decay} Ereignisse)", f"   (Expected duration at measured {cpm_hint:.1f} CPM: approx. {n_decay/cpm_hint:.0f} min for {n_decay} events)") + C.RESET)
        r = collect_decay(n_decay, args.mock, transparent); results.append(r)
        status_line(2, 4, r.name, "ok", r.info)

        print(C.BOLD + t("\n Phase 3/4 — MLX90640 IR-Kamera", "\n Phase 3/4 — MLX90640 IR camera") + C.RESET)
        r = collect_camera(n_frames, args.mock, transparent); results.append(r)
        status_line(3, 4, r.name, "ok", r.info)

    print(C.BOLD + t(f"\n Phase {ph_total}/{ph_total} — Wuerfel (hardwareunabhaengige letzte Quelle)", f"\n Phase {ph_total}/{ph_total} — Dice (hardware-independent final source)") + C.RESET)
    r = collect_dice(n_dice, target_bits, args.mock, transparent); results.append(r)
    status_line(ph_total, ph_total, r.name, "ok", r.info)

    if args.light:
        hw, dice = results
        dec = cam = None
    else:
        hw, dec, cam, dice = results
    hr()
    print(C.BOLD + t(" Entropie-Bilanz (konservativ kreditiert)", " Entropy balance (conservatively credited)") + C.RESET)
    total_credit = 0.0
    for s in results:
        total_credit += s.credited_bits
        print(t(f"   {s.name:<24} {s.credited_bits:8.0f} Bit   ({s.raw_len} B roh)", f"   {s.name:<24} {s.credited_bits:8.0f} bits  ({s.raw_len} B raw)"))
    print(t(f"   {'SUMME':<24} {total_credit:8.0f} Bit   (Ziel: {target_bits} Bit)", f"   {'TOTAL':<24} {total_credit:8.0f} bits  (target: {target_bits} bits)"))
    if total_credit < 2 * target_bits:
        fail_abort("Entropie-Bilanz",
                   f"Kreditierte Gesamtentropie ({total_credit:.0f} Bit) unter dem "
                   f"Sicherheitsminimum von {2*target_bits} Bit — Parameter erhoehen.")

    if args.light:
        print(C.BOLD + t("\n Kombiniere: FINAL = HMAC-SHA512(key=H(Wuerfel), msg=Pool(HWRNG,OS))  [LIGHT]", "\n Combining: FINAL = HMAC-SHA512(key=H(dice), msg=pool(HWRNG,OS))  [LIGHT]") + C.RESET)
    else:
        print(C.BOLD + t("\n Kombiniere: FINAL = HMAC-SHA512(key=H(Wuerfel), msg=Pool(HWRNG,Zerfall,Kamera,OS))", "\n Combining: FINAL = HMAC-SHA512(key=H(dice), msg=pool(HWRNG,decay,camera,OS))") + C.RESET)
    entropy = combine(hw, dec, cam, dice, n_bytes, transparent, light=args.light)
    idx = bip39_indices(entropy)

    dur = (time.monotonic() - t0) / 60
    hr("━")
    final_offline_check(args)
    modus = "LIGHT" if args.light else "FULL"
    print(C.GRN + C.BOLD + t(f" ✔ SEED ERZEUGT  ({n_words} Woerter, {target_bits} Bit, {modus}-Modus, Dauer {dur:.1f} min)", f" ✔ SEED GENERATED  ({n_words} words, {target_bits} bits, {modus} mode, duration {dur:.1f} min)") + C.RESET)
    play_success_jingle()
    hr("━")
    if words_list and not args.mock:
        for i in range(0, len(idx), 4):
            row = "   ".join(f"{C.DIM}{j+1:2d}.{C.RESET} {C.BOLD}{words_list[idx[j]]:<10}{C.RESET}"
                             for j in range(i, min(i + 4, len(idx))))
            print("  " + row)
    else:
        if args.mock:
            # Audit N3: Mock-Seeds duerfen nicht abtippbar sein -> nur Indizes
            print(C.YEL + t("  MOCK-MODUS: nur BIP39-Wortindizes (bewusst keine Woerter):",
                            "  MOCK MODE: BIP39 word indices only (deliberately no words):") + C.RESET)
        else:
            print(C.YEL + t("  (Keine Wortliste — zeige BIP39-Wortindizes:)",
                            "  (No wordlist — showing BIP39 word indices:)") + C.RESET)
        print("  " + " ".join(str(i) for i in idx))
    hr("━")
    print(C.RED + C.BOLD + t("  WICHTIG:", "  IMPORTANT:") + C.RESET + C.RED +
          t(" Seed NUR handschriftlich auf Papier/Metall sichern. Kein Foto,\n  kein Cloud-Backup, keine Datei. Geraet offline lassen. Seed vor Nutzung\n  auf einem zweiten, unabhaengigen Offline-Geraet verifizieren.",
            " Back up the seed ONLY handwritten on paper/metal. No photo,\n  no cloud backup, no file. Keep the device offline. Verify the seed on a\n  second, independent offline device before use.") + C.RESET)
    verify_seed_transcription(idx, words_list, args)
    secure_cleanup(args)
    show_donation()

if __name__ == "__main__":
    main()
