#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Quantum Seed Generator Project
# This file is part of the Quantum Seed Generator project.
# License: MIT License — full text in the LICENSE file of the repository.
"""btc_seedgen.py — high-security BIP39 seed generator with hardware entropy
=========================================================================

Generates BIP39 seed phrases (12/24 words) from four mutually independent
physical entropy sources on a Raspberry Pi 5:

  1. BCM2712 hardware TRNG (/dev/hwrng), 5 spaced samples
  2. Radioactive decay timing (CAJOE Geiger counter on GPIO17)
  3. Thermal sensor noise (MLX90640 IR camera, raw frames via I2C)
  4. Physical dice entered by the user (HMAC key — trust anchor)

Sources are hashed with domain separation (SHA-512) and combined via
HMAC-SHA512 with the dice digest as the key: the result is unpredictable
as long as at least ONE side is honest. Entropy is credited conservatively
and a balance of >= 2x the target is enforced. All secrets live in RAM
only; no SECRET is ever written to disk. The only disk writes are the
explicit, announced hardening steps (config.txt overlays, the optional
systemd unit, the history truncation). See the project documentation for
the full security model, and LICENSE for terms (MIT).

Fault detection (v1.1) — dual-computation validation against transient
memory errors (bit flips; the Pi 5 has no ECC RAM). The crypto scheme is
unchanged; this is purely error DETECTION:
  * The whole chain (H_hw, H_dec, H_cam, H_os -> POOL -> HMAC-SHA512 with
    H_dice -> FINAL -> entropy truncation -> BIP39 word coding) is computed
    TWICE, independently, from the stored inputs (source digests + one
    os.urandom nonce sampled once). No intermediate of run 1 is reused.
  * FINAL and the finished word sequences of both runs are compared
    immediately before display; only on a match is anything shown.
  * BIP39 roundtrip: words -> entropy, checksum verified, re-encoded,
    strings compared.
  * Wordlist re-verification: right before output the in-memory list is
    serialized identically to the load format and its SHA-256 is checked
    against the known reference hash again (the roundtrip alone is blind
    to a list corrupted in RAM, since both directions use the same table).
  * Any mismatch aborts loudly (exit code 4), no partial word display.

Documented limits of the dual run:
  * Deterministic bugs affect both runs identically and are NOT caught
    here — that is what the self-test vectors are for.
  * Bit flips in the raw data BEFORE both runs are harmless: corrupted
    randomness is still randomness.
  * A flip that occurs only in the display buffer is caught by the BIP39
    checksum during the test restore — verifying the seed on a second,
    independent offline device before the first deposit remains mandatory.
  * RAM hygiene: Python cannot guarantee wiping of immutable
    bytes objects, and pages swapped out BEFORE swapoff may persist in the
    swap blocks. Recommendation: one fresh boot per seed ceremony.

Usage:  sudo python3 btc_seedgen.py            (interactive)
        sudo python3 btc_seedgen.py --selftest (crypto self-test only)
Modes:  FULL (all four sources) or LIGHT (HWRNG + dice)."""

import argparse
import hashlib
import hmac
import math
import os
import atexit
import shutil
import signal
import sys
import time
from dataclasses import dataclass

# ----------------------------------------------------------------------------
# Konstanten
# ----------------------------------------------------------------------------
VERSION            = "1.5"   # audit v1.5: Umsetzung der Audit-46-Befunde
LANG               = "de"   # set at startup

def t(de, en):
    """Zweisprachige Programmfuehrung."""
    return en if LANG == "en" else de

DOMAIN             = b"BTC-SEEDGEN-v1"          # Domain-Separation-Tag
GPIO_GEIGER        = 17                          # BCM-Nummer (phys. Pin 11)
GPIO_PULL_MODE     = "up"   # audit-47: Pull-Widerstand fuer den CAJOE-Eingang,
                            # per --gpio-pull auf up/none/down setzbar.
                            # audit-46 HW-3 hatte SET_PULL_NONE -> SET_PULL_UP
                            # geaendert (Open-Collector-Ausgaenge schwimmen
                            # ohne Pull). Bei einem HOCHOHMIGEN Spannungsteiler
                            # als 5V->3,3V-Pegelwandler uebersteuert der interne
                            # Pull-up (~50 kOhm) den Eingang jedoch, die
                            # LOW-Pulse kommen nicht mehr durch -> keine
                            # Ereignisse. Beide Faelle sind real, deshalb
                            # konfigurierbar mit Auto-Fallback im Healthcheck.
DECAY_PULL_PROBE_S = 60     # audit-47: so lange wartet der Healthcheck je
                            # Pull-Modus auf den ERSTEN Puls, bevor er den
                            # naechsten probiert. 60 s deckt bei >= 4 CPM
                            # (CPM_WARN_MIN) praktisch jeden ehrlichen Zaehler
                            # ab: P(kein Puls in 60 s bei 4 CPM) = e^-4 ~ 1.8%.
                            # Greift ohnehin nur, solange NULL Pulse kamen.

MLX_I2C_BUS        = 1
MLX_I2C_ADDR       = 0x33
WORDLIST_SHA256    = ("2f5eed53a4727b4bf8880d8f3f199efc"
                      "90e58503646d9ff8eff3a2ed3b24dbda")   # offizielle english.txt
DECAY_DEBOUNCE_NS  = 30_000_000   # 30 ms dead time: one audio burst = one decay
DECAY_TIMEOUT_S    = 360      # abort if no decay event is registered for this long
DECAY_TIMEOUT_EFF  = 360      # audit F2-M4: rate-adaptive (set after the health
                              # check: max(360, 20 mean intervals) — at 1 CPM a
                              # 360 s gap is EXPECTED (P=e^-6 per gap), the fixed
                              # timeout aborted up to 92% of honest long runs;
                              # audit-46 CODE-5: Faktor ist 20, nicht 10)
CPM_WARN_MIN          = 4     # below this CPM the poti hint is shown in the health check
HWRNG_SAMPLES         = 5     # Proben a 64 B, 2 s Abstand (Warmlauf-Dekorrelation)
HWRNG_BYTES        = 64       # 512 bits per sample (x HWRNG_SAMPLES samples)
# Note (audit F2-N20): the monobit window 0.30-0.70 is a DEFECT detector
# (stuck/dead source), not a bias test — p=0.35 is caught in only ~0.8%
# per sample (~4% across all 5 samples); statistical quality rests on crediting + the combiner.
CAM_ENTROPY_PER_FRAME = 64    # konservativ kreditierte Bits pro Frame
CAM_MIN_DIFF          = 0.85  # accept a frame only if >= 85% of pixels differ
CAM_MIN_FRAMES        = 12    # hartes Minimum akzeptierter Frames
CAM_ACCEPT_TIMEOUT_S  = 300   # 5 minutes for the user to create change by hand movement
                              # einen akzeptablen Frame zu erzeugen
CAM_FROZEN_DIFF       = 0.05  # below this a frame counts as 'frozen'
CAM_FROZEN_LIMIT      = 200   # this many frozen frames in a row = defect
DECAY_BITS_PER_EVENT  = 2     # konservativ kreditierte Bits pro Zerfallsereignis
DICE_BITS_PER_ROLL    = math.log2(6)   # ~2.585 Bit pro Wurf
DICE_MIN_ROLLS        = 52    # hartes Minimum (~134 Bit); 100 empfohlen
DICE_MIN_ROLLS_LIGHT  = 110   # audit F3-H3 + audit-46 KRYPTO-1: 104 x log2(6) + 256
                              # = 524.8 >= 2x256 hatte nur 2.5% Marge (nominal, fairer
                              # Wuerfel vorausgesetzt); 110 x log2(6) + 256 = 540.3
                              # => ~28 Bit Marge gegen unperfekte Wuerfel

# ----------------------------------------------------------------------------
# Konsolen-Hilfsfunktionen (ANSI)
# ----------------------------------------------------------------------------
_FARBEN_AN = (sys.stdout.isatty()
              and os.environ.get("TERM", "") != "dumb"
              and not os.environ.get("NO_COLOR"))   # audit F3-N12

class C:
    RESET  = "\033[0m";  BOLD = "\033[1m";  DIM = "\033[2m"
    RED    = "\033[31m"; GRN  = "\033[32m"; YEL = "\033[33m"
    CYA    = "\033[36m"; MAG  = "\033[35m"; WHT = "\033[97m"
    ORA    = "\033[38;5;208m"   # Orange (256-Farben-Modus)
    HBL    = "\033[38;5;45m"    # helles Blau (Deko/Titel)

if not _FARBEN_AN:
    for _attr in ("RESET", "BOLD", "DIM", "RED", "GRN", "YEL", "CYA",
                  "MAG", "WHT", "ORA", "HBL"):
        setattr(C, _attr, "")

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

ASCII_DEKO_LIGHT_DE = r"""                      ⌁ HWRNG ─┐          ┌─ ⚄ Wuerfel
                               └──────────┘
                 ▓▒░ Hardware-Entropie → HMAC-SHA512 → BIP39 ░▒▓"""

ASCII_DEKO_LIGHT_EN = r"""                      ⌁ HWRNG ─┐          ┌─ ⚄ Dice
                               └──────────┘
                 ▓▒░ Hardware entropy → HMAC-SHA512 → BIP39 ░▒▓"""

def banner(light: bool = False):
    w = term_width()
    if w >= 92:   # audit F3-N12: the logo itself is 91 columns wide
        print(C.ORA + ASCII_LOGO + C.RESET)
        if light:
            print(C.HBL + t(ASCII_DEKO_LIGHT_DE, ASCII_DEKO_LIGHT_EN) + C.RESET)
        else:
            print(C.HBL + t(ASCII_DEKO_DE, ASCII_DEKO_EN) + C.RESET)
        print()
        titel = t(f"QUANTUM SEED GENERATOR v{VERSION} · Hardware-Entropie · Raspberry Pi 5", f"QUANTUM SEED GENERATOR v{VERSION} · Hardware Entropy · Raspberry Pi 5")
        print(C.HBL + C.BOLD + titel.center(84) + C.RESET)
    else:
        # fallback for narrow terminals
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
    # audit F3-N11: \033[K erases the previous, possibly longer line tail
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
    """Heats the CPU for the pause duration with SHA-512 loops: the next
    HWRNG sample is taken under changed physical conditions (die
    temperature, supply load) — decorrelation reinforcement, NOT an
    entropy source. As an honest by-product the iteration count and the
    exact duration are harvested (scheduler/cache jitter) and mixed into
    the raw data uncredited."""
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
    """Reads HWRNG_SAMPLES samples of 64 B each, 2 s apart: temporal
    decorrelation (cold-start/warm-up protection) + cross-comparison of
    the samples. Crediting stays at a conservative 256 bits."""
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
        if len(raw) < HWRNG_BYTES:
            # audit F3-N7: short reads are legal on char devices — top up
            try:
                with open("/dev/hwrng", "rb") as f2:
                    for _ in range(3):
                        if len(raw) >= HWRNG_BYTES:
                            break
                        raw += f2.read(HWRNG_BYTES - len(raw))
            except OSError:
                pass
        if len(raw) != HWRNG_BYTES:
            fail_abort("BCM2712 HWRNG", f"Nur {len(raw)} von {HWRNG_BYTES} Bytes gelesen.")
        # Pruefungen PRO Probe: Diversitaet + Monobit (Audit H5: erkennt
        # defects, never manipulation — the HMAC combiner counters the latter).
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
    # cross-check: all samples must be pairwise distinct
    if len(set(proben)) != HWRNG_SAMPLES:
        fail_abort("BCM2712 HWRNG",
                   t("Mindestens zwei der 5 Proben identisch — RNG liefert keine "
                     "frischen Daten.",
                     "at least two of the 5 samples identical — RNG not delivering "
                     "fresh data."))
    raw = b"".join(proben) + jitter   # Jitter-Beiprodukt: unkreditiert, schadet nie
    res = SourceResult("BCM2712 HWRNG", dsha512("hwrng", raw), len(raw),
                       credited_bits=256,   # conservative, independent of the sample count
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

# ---------- 2) Radioactive decay (CAJOE / GPIO) ------------------------------
def _pull_konstante(lgpio, modus: str):
    """Mappt den Textmodus auf die lgpio-Konstante (Fallback: up)."""
    return {"up": lgpio.SET_PULL_UP,
            "none": lgpio.SET_PULL_NONE,
            "down": lgpio.SET_PULL_DOWN}.get(modus, lgpio.SET_PULL_UP)


def find_rp1_chip(lgpio, gpio_nr, pull_modus=None):
    """Finds the Pi 5 40-pin header (RP1, 54 lines) dynamically.
    The chip number varies with the kernel (0, 4, 15, ...).
    audit-47: der Pull-Widerstand ist parametrierbar — siehe GPIO_PULL_MODE."""
    pull_modus = pull_modus or GPIO_PULL_MODE
    pull = _pull_konstante(lgpio, pull_modus)
    kandidaten = []
    for n in range(0, 32):
        try:
            h = lgpio.gpiochip_open(n)
        except Exception:
            continue
        label = ""
        lines = 0
        try:
            info = lgpio.gpio_get_chip_info(h)
            # audit-46 HW-2/CODE-3: lgpio liefert eine Liste
            # [status, lines, name, label] — strukturiert zugreifen statt
            # str(info) zu parsen (bricht sonst bei Formataenderung still).
            if isinstance(info, (list, tuple)) and len(info) >= 4:
                lines = int(info[1])
                label = str(info[3]).lower()
            else:
                label = str(info).lower()   # Fallback fuer exotische Versionen
        except Exception:
            pass
        # "rp1" im Label ist der Primaertreffer. Der 54-Leitungen-Fallback
        # gilt nur, wenn das Label NICHT den SoC-Pinctrl nennt — auf dem Pi 5
        # hat auch pinctrl-bcm2712 54 Lines, GPIO17 ist dort elektrisch eine
        # andere Leitung (audit-46 HW-2).
        if "rp1" in label or (lines == 54 and "bcm2712" not in label):
            kandidaten.insert(0, (n, h, label))   # prefer rp1 chips at the front
        else:
            kandidaten.append((n, h, label))
    handle = None
    edge_used = None
    chip_label = ""
    for n, h, label in kandidaten:
        if handle is None:
            try:
                # Ruhepegel messen -> Flankenrichtung automatisch bestimmen.
                # audit-46 HW-3 / audit-47: Pull ist parametrierbar
                # (GPIO_PULL_MODE, --gpio-pull). "up" ist der Standard fuer
                # Open-Collector-Ausgaenge; bei hochohmigem Spannungsteiler
                # als Pegelwandler uebersteuert der interne Pull-up (~50 kOhm)
                # den Eingang und "none"/"down" ist noetig.
                lgpio.gpio_claim_input(h, gpio_nr, pull)
                ruhe = lgpio.gpio_read(h, gpio_nr)
                lgpio.gpio_free(h, gpio_nr)
                edge = lgpio.RISING_EDGE if ruhe == 0 else lgpio.FALLING_EDGE
                lgpio.gpio_claim_alert(h, gpio_nr, edge, pull)
                handle, edge_used, chip_label = h, edge, label
                print(C.DIM + t(f"   GPIO{gpio_nr} auf gpiochip{n} ('{label}'): Pull={pull_modus}, "
                                f"Ruhepegel={'HIGH' if ruhe else 'LOW'}, "
                                f"Flanke={'FALLING' if ruhe else 'RISING'}",
                                f"   GPIO{gpio_nr} on gpiochip{n} ('{label}'): pull={pull_modus}, "
                                f"idle={'HIGH' if ruhe else 'LOW'}, "
                                f"edge={'FALLING' if ruhe else 'RISING'}") + C.RESET)
                continue
            except Exception:
                pass
        try: lgpio.gpiochip_close(h)
        except Exception: pass
    if handle is not None and chip_label and "rp1" not in chip_label:
        # audit F2-N13: claiming GPIO17 on a non-rp1 chip is electrically a
        # different line on the Pi 5 — loud hint instead of a silent 360 s
        # timeout later
        print(C.YEL + t(f"   ⚠ GPIO17 auf Chip '{chip_label}' belegt (nicht rp1) — auf dem "
                        "Pi 5 ist das vermutlich die falsche Leitung!",
                        f"   ⚠ GPIO17 claimed on chip '{chip_label}' (not rp1) — on the "
                        "Pi 5 this is probably the wrong line!") + C.RESET)
    return (handle, edge_used) if handle is not None else (None, None)


def _decay_stats_check(timestamps, mock: bool):
    """Audit M4: detects jittery periodicity (mains hum, function
    generators). Genuine decay is a Poisson process -> intervals are
    exponentially distributed: coefficient of variation ~1, small
    chi-square against the exponential distribution."""
    deltas = [(b - a) / 1e9 for a, b in zip(timestamps, timestamps[1:])]
    if not mock:
        # audit M3: the debounce dead time shifts the exponential
        # distribution (interval = dead time + Exp) — the CV and chi-square
        # tests below expect the UNSHIFTED exponential and would falsely
        # reject genuine decay (significantly from ~300 CPM upward).
        # Subtract the dead time.
        tot = DECAY_DEBOUNCE_NS / 1e9
        deltas = [max(d - tot, 1e-9) for d in deltas]
    n = len(deltas)
    if n < 32:
        return  # too little data for statistics (the health check only tests coarsely)
    m = sum(deltas) / n
    if m <= 0:
        fail_abort("Radiozerfall (CAJOE)", "Intervall-Mittelwert <= 0 — Messung defekt.")
    # CPM plausibility window (real hardware only; mock is time-compressed)
    if not mock:
        cpm = 60.0 / m
        # audit-46 HW-4: Obergrenze 3000 -> 2000 CPM. Die 30-ms-Totzeit kappt
        # die messbare Rate bei 1/0.03 s = ~2000 CPM; ein hoeherer Schwellwert
        # war unerreichbar und damit wirkungslos.
        if not (0.3 <= cpm <= 2000.0):   # audit F3-N3: 0.5 edge rejected honest 0.5 CPM tubes ~49%
            # audit F2-N4: lower bound 1.0 rejected an honest tube at exactly
            # 1.0 CPM in ~48% of runs (estimator scatter) — widen to 0.5
            fail_abort("Radiozerfall (CAJOE)",
                       t(f"Zaehlrate {cpm:.0f} CPM ausserhalb des Plausibilitaetsfensters "
                         "0.3-2000 — Stoerquelle statt Roehre? (Audit M4)",
                         f"count rate {cpm:.0f} CPM outside plausibility window "
                         "0.3-2000 — interference instead of tube? (audit M4)"))
    # coefficient of variation: an exponential distribution has CV = 1; periodic
    # jitter yields CV << 1 (pairwise-distinct values no longer suffice there)
    var = sum((d - m) ** 2 for d in deltas) / n
    cv = (var ** 0.5) / m
    if cv < 0.25:
        fail_abort("Radiozerfall (CAJOE)",
                   t(f"Intervalle zu regelmaessig (CV={cv:.2f}, erwartet ~1.0) — "
                     "periodisches Stoersignal statt Zerfall? (Audit M4)",
                     f"intervals too regular (CV={cv:.2f}, expected ~1.0) — "
                     "periodic interference instead of decay? (audit M4)"))
    # chi-square against an exponential distribution with estimated mean
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
    # df = k-2 = 6, alpha ~ 0.0005 -> critical ~24  (deliberately strict against
    # false alarms — a 40-minute run must not die without cause)
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
        # simulated Poisson process, heavily time-compressed (FOR TESTING ONLY)
        import random
        ts_val = time.monotonic_ns()
        for i in range(n_events):
            ts_val += int(random.expovariate(0.5) * 1e6)  # time-compressed for test runs
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
                return                       # edge belongs to the same click burst
            timestamps.append(ts_ns)
            last_event = time.monotonic()

        cb = None
        try:
            cb = lgpio.callback(handle, GPIO_GEIGER, edge, _cb)   # audit N3
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
                if time.monotonic() - last_event > DECAY_TIMEOUT_EFF:
                    fail_abort("Radiozerfall (CAJOE)",
                               f"{DECAY_TIMEOUT_EFF}s ohne Zerfallsereignis — "
                               "Verkabelung/Board/Roehrenspannung pruefen.")
        except KeyboardInterrupt:
            print(C.RED + t("\n Abbruch durch Benutzer (Strg+C).",
                            "\n aborted by user (Ctrl+C).") + C.RESET)
            sys.exit(130)   # audit F3-N8: consistent user-abort code
        except Exception as e:
            # audit-46 CODE-1: lgpio-Fehler (z. B. bei callback()) schlugen als
            # nackter Traceback durch (Exit 1). Kontrolliert abbrechen; das
            # finally unten raeumt Handle + Chip korrekt auf.
            fail_abort("Radiozerfall (CAJOE)",
                       t(f"GPIO-Fehler: {e}", f"GPIO error: {e}"))
        finally:
            try:                              # audit F3-M9: split so a None
                if cb is not None:            # callback can't eat the close
                    cb.cancel()
            except Exception:
                pass
            try:
                lgpio.gpiochip_close(handle)
            except Exception:
                pass

    print()
    if len(timestamps) < n_events:
        fail_abort("Radiozerfall (CAJOE)", "Zu wenige Ereignisse erfasst.")
    # health check: intervals must vary (no stuck pin)
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

# ---------- 3) MLX90640 IR camera (I2C, raw frames) --------------------------
def _mlx_read_words(bus, reg: int, n_words: int) -> bytes:
    """Write a 16-bit register address, then read n_words*2 bytes."""
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

def _mlx_ensure_2hz(bus):
    """audit F3-M5: an EEPROM-flashed 64 Hz sensor tears virtually every
    frame silently (read ~200 ms >> subpage 15.6 ms). Verify the control
    register once; set 2 Hz if it deviates.
    audit-46 HW-1: als gemeinsamer Helper — auch der Healthcheck nutzt ihn
    jetzt (vorher scheiterte dort ein 64-Hz-Sensor am Tearing-Abort, ohne
    dass der Fix je griff). Best effort: Fehler zeigen sich im Frame-Timeout.
    audit-46 HW-7: Read-back-Verifikation des Schreibzugriffs."""
    try:
        ctrl = _mlx_read_words(bus, 0x800D, 1)
        wort = (ctrl[0] << 8) | ctrl[1]
        rate_bits = (wort >> 7) & 0b111
        if rate_bits != 0b010:      # power-on default: 2 Hz
            neu_wort = (wort & ~(0b111 << 7)) | (0b010 << 7)
            from smbus2 import i2c_msg as _im
            bus.i2c_rdwr(_im.write(MLX_I2C_ADDR,
                         [0x80, 0x0D, (neu_wort >> 8) & 0xFF, neu_wort & 0xFF]))
            rb = _mlx_read_words(bus, 0x800D, 1)
            if (((rb[0] << 8) | rb[1]) >> 7) & 0b111 == 0b010:
                print(C.YEL + t(f"   ⚠ Refresh-Rate stand auf {rate_bits:03b} — auf 2 Hz gesetzt (verifiziert).",
                                f"   ⚠ refresh rate was {rate_bits:03b} — set to 2 Hz (verified).") + C.RESET)
            else:
                print(C.YEL + t(f"   ⚠ Refresh-Rate stand auf {rate_bits:03b} — 2-Hz-Schreibzugriff NICHT verifizierbar.",
                                f"   ⚠ refresh rate was {rate_bits:03b} — 2 Hz write could NOT be verified.") + C.RESET)
    except Exception:
        pass                        # best effort; Fehler zeigt sich im Frame-Timeout

def frame_diff_ratio(a: bytes, b: bytes) -> float:
    """Fraction of the 768 image pixels (16-bit words) that differ."""
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
            fail_abort("MLX90640",
                       t("Python-Modul 'smbus2' fehlt: sudo apt install python3-smbus2  (oder pip install smbus2)",
                         "Python module 'smbus2' missing: sudo apt install python3-smbus2  (or pip install smbus2)"))
        try:
            bus = SMBus(MLX_I2C_BUS)
        except OSError as e:
            fail_abort("MLX90640", f"I2C-Bus {MLX_I2C_BUS} nicht verfuegbar: {e} "
                       "(I2C in raspi-config aktivieren).")
        try:
            consec_reject = 0
            frozen_count = 0
            last_accept = time.monotonic()
            _mlx_ensure_2hz(bus)
            while len(frames) < n_frames:
                # wait for a new frame (status register 0x8000, bit 3)
                t0 = time.monotonic()
                while True:
                    st = _mlx_read_words(bus, 0x8000, 1)
                    if st[1] & 0x08:
                        break
                    if time.monotonic() - t0 > 5:
                        fail_abort("MLX90640", "Timeout beim Warten auf neues Frame — "
                                   "Sensor antwortet nicht (Adresse 0x33?).")
                    time.sleep(0.02)
                # audit F2-N12: Melexis reference handshake — clear the
                # status BEFORE reading, then re-check; if new data arrived
                # mid-read (tearing at 2 Hz vs ~150 ms read) retry (<=5x)
                from smbus2 import i2c_msg
                for _versuch in range(5):
                    wmsg = i2c_msg.write(MLX_I2C_ADDR, [0x80, 0x00, 0x00, 0x30])
                    bus.i2c_rdwr(wmsg)
                    frame = _mlx_read_words(bus, 0x0400, 832)   # kompletter RAM-Block
                    st2 = _mlx_read_words(bus, 0x8000, 1)
                    if not (st2[1] & 0x08):
                        break               # read finished before the next frame
                else:
                    # audit F3-M4: after 5 torn reads the reference driver
                    # reports an error (-8) — do not silently accept tearing
                    fail_abort("MLX90640",
                               t("5x zerrissene Frames in Folge (neue Daten waehrend des "
                                 "Lesens) — Refresh-Rate pruefen (0x800D).",
                                 "5 torn frames in a row (new data during the read) — "
                                 "check the refresh rate (0x800D)."))
                # CAM_MIN_DIFF filter (currently 85%): accept only clearly changed frames
                d = frame_diff_ratio(frame, frames[-1]) if frames else 1.0
                if frames and d < CAM_MIN_DIFF:
                    rejected += 1
                    consec_reject += 1
                    # Healthcheck: wirklich EINGEFRORENES Bild (Sensordefekt) ...
                    if d < CAM_FROZEN_DIFF:
                        frozen_count += 1
                        if frozen_count >= CAM_FROZEN_LIMIT:
                            fail_abort("MLX90640",
                                       t(f"{CAM_FROZEN_LIMIT} eingefrorene Frames in Folge "
                                         f"(Diff < {CAM_FROZEN_DIFF*100:.0f}%) — Sensor defekt?",
                                         f"{CAM_FROZEN_LIMIT} frozen frames in a row "
                                         f"(diff < {CAM_FROZEN_DIFF*100:.0f}%) — sensor defective?"))
                    else:
                        frozen_count = 0
                    # ... but give the human 5 minutes for the hand movement
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
    # health check: frames must be neither empty/constant nor identical
    if any(len(set(f)) < 8 for f in frames):
        fail_abort("MLX90640", t("Frame mit nahezu konstantem Inhalt — Sensor defekt?",
                                 "frame with nearly constant content — sensor defective?"))
    if n_frames >= 2 and len({hashlib.sha256(f).digest() for f in frames}) < n_frames:
        fail_abort("MLX90640", "Identische Frames erkannt — kein Sensorrauschen vorhanden.")
    raw = b"".join(frames)
    res = SourceResult(t("MLX90640 IR-Kamera", "MLX90640 IR camera"), dsha512("cam", raw), len(raw),
                       credited_bits=n_frames * CAM_ENTROPY_PER_FRAME,
                       info=t(f"{n_frames} Frames akzeptiert, {rejected} verworfen ({len(raw)} B)", f"{n_frames} frames accepted, {rejected} rejected ({len(raw)} B)"))
    if transparent:
        print(f"   H_cam = {res.digest.hex()}")
    return res

# ---------- 4) Dice (manual, FINAL source) -----------------------------------
_DICE_TRANS = []   # audit F2-N2: buffered dice transparency lines

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
    if n_rolls >= DICE_MIN_ROLLS and worst > 0.40:   # audit F2-N5: active from the hard minimum
        fail_abort("Wuerfel", f"Eine Augenzahl macht {worst*100:.0f}% aller Wuerfe aus — "
                   "Wuerfel/Eingabe pruefen.")
    # audit M5: H_dice is the HMAC key and trust anchor — a loaded die must
    # not pass just because n < 60. Chi-square over the 6 faces from the
    # hard minimum on (df=5, alpha ~1e-3 -> critical ~20.5; deliberately
    # lenient so honest dice with normal fluctuation never trip it).
    if len(rolls) >= DICE_MIN_ROLLS:
        erw = len(rolls) / 6.0
        chi2 = sum((counts[v] - erw) ** 2 / erw for v in range(1, 7))
        if chi2 > 20.52:
            fail_abort("Wuerfel",
                       t(f"Augenzahl-Verteilung extrem unausgeglichen (Chi²={chi2:.1f} "
                         f"> 20.5, Verteilung {counts}) — gezinkter Wuerfel oder "
                         "Eingabefehler? (Audit M5)",
                         f"face distribution extremely unbalanced (chi²={chi2:.1f} "
                         f"> 20.5, distribution {counts}) — loaded die or input "
                         "errors? (audit M5)"))
    # audit N4: minimum diversity even for small sample sizes
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
        # audit F2-N2: H_dice is the HMAC key — like the combiner values it
        # must not appear before the final offline check. Buffered here,
        # printed by main() after the check.
        _DICE_TRANS.clear()
        if mock:
            _DICE_TRANS.append(t("   Wuerfelfolge/H_dice: «im Mock maskiert»",
                                 "   dice sequence/H_dice: «masked in mock mode»"))
        else:
            _DICE_TRANS.append(t(f"   Wuerfelfolge : {''.join(str(r) for r in rolls)}", f"   Dice sequence: {''.join(str(r) for r in rolls)}"))
        if not mock:
            _DICE_TRANS.append(t(f"   Kodiert (hex): {raw.hex()}", f"   Encoded (hex): {raw.hex()}"))
            _DICE_TRANS.append(f"   H_dice = {res.digest.hex()}")
        print(C.DIM + t("   (Transparenzwerte der Wuerfel werden bis nach der finalen Offline-Pruefung zurueckgehalten.)",
                        "   (dice transparency values are withheld until after the final offline check.)") + C.RESET)
    return res

# ----------------------------------------------------------------------------
# Kombinierer + BIP39
# ----------------------------------------------------------------------------
def derive_chain(h_hw: bytes, h_dec, h_cam, h_dice: bytes,
                 os_nonce: bytes, n_bytes: int, light: bool):
    """ONE complete, independent computation of the derivation chain from
    stored inputs (source digests + the os.urandom nonce sampled ONCE).
    Pure function: no randomness, no state — calling it twice with the
    same inputs must yield identical results unless memory flipped."""
    h_os = dsha512("os", os_nonce)
    mode_tag = b"light" if light else b"full"
    parts = h_hw + (h_dec or b"") + (h_cam or b"") + h_os
    pool = dsha512("pool", mode_tag + parts)
    final = hmac.new(h_dice, pool, hashlib.sha512).digest()
    return final, final[:n_bytes], h_os, pool


class DualComputationError(Exception):
    """Raised when the dual computation / roundtrip / wordlist re-check
    detects a mismatch (suspected transient memory error)."""


def _roundtrip_check(entropy: bytes, idx, words_list):
    """BIP39 roundtrip: decode the finished words/indices back to entropy,
    verify the checksum, re-encode, compare. Raises on any mismatch."""
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    num = 0
    for i in idx:
        num = (num << 11) | i
    ent2 = (num >> cs_bits).to_bytes(len(entropy), "big")
    cs = num & ((1 << cs_bits) - 1)
    cs_soll = hashlib.sha256(ent2).digest()[0] >> (8 - cs_bits)
    if ent2 != entropy:
        raise DualComputationError(t("Roundtrip: Entropie nach Dekodierung abweichend",
                                     "roundtrip: entropy mismatch after decode"))
    if cs != cs_soll:
        raise DualComputationError(t("Roundtrip: BIP39-Pruefsumme ungueltig",
                                     "roundtrip: BIP39 checksum invalid"))
    idx2 = bip39_indices(ent2)
    if idx2 != list(idx):
        raise DualComputationError(t("Roundtrip: neu kodierte Indizes weichen ab",
                                     "roundtrip: re-encoded indices differ"))
    if words_list:
        p1 = " ".join(words_list[i] for i in idx)
        p2 = " ".join(words_list[i] for i in idx2)
        if p1 != p2:
            raise DualComputationError(t("Roundtrip: neu kodierte Wortfolge weicht ab",
                                         "roundtrip: re-encoded word string differs"))


def _wordlist_recheck(words_list):
    """Serialize the in-memory wordlist identically to the load format
    (official file: one word per line, LF, trailing newline) and verify
    its SHA-256 against the known reference hash AGAIN. Catches a list
    corrupted in RAM after the initial load check."""
    blob = ("\n".join(words_list) + "\n").encode("utf-8")
    if hashlib.sha256(blob).hexdigest() != WORDLIST_SHA256:
        raise DualComputationError(t("Wortliste im Speicher entspricht nicht mehr dem Referenzhash",
                                     "wordlist in memory no longer matches the reference hash"))


def _dual_abort(reason: str):
    """Loud abort on suspected transient memory error: red message, no
    partial word display, dedicated exit code 4."""
    print("\n")
    hr("━")
    print(C.RED + C.BOLD + t(" ✘ ABBRUCH — Doppelberechnungs-Validierung fehlgeschlagen",
                             " ✘ ABORTED — dual-computation validation failed") + C.RESET)
    print(C.RED + t(f"   Abweichung: {reason}", f"   Mismatch: {reason}") + C.RESET)
    print(C.RED + t("   Es wurde KEIN Seed angezeigt. Lauf wiederholen — moeglicher transienter Speicherfehler (Bitflip).",
                    "   NO seed was displayed. Repeat the run — possible transient memory error (bit flip).") + C.RESET)
    hr("━")
    sys.exit(4)


def validated_derive(hw, dec, cam, dice, n_bytes: int,
                     transparent: bool, light: bool, words_list,
                     mock: bool = False):
    """Runs the derivation chain TWICE independently and compares FINAL,
    indices and word strings; then verifies the BIP39 roundtrip. Returns
    (entropy, idx) only if everything matches; otherwise aborts loudly.
    The os nonce is sampled ONCE and fed to both runs as raw input."""
    os_nonce = os.urandom(64)
    runs = []
    for _ in range(2):
        final, entropy, h_os, pool = derive_chain(
            hw.digest, dec.digest if dec else None, cam.digest if cam else None,
            dice.digest, os_nonce, n_bytes, light)
        idx = bip39_indices(entropy)
        phrase = " ".join(words_list[i] for i in idx) if words_list else None
        runs.append((final, entropy, idx, phrase, h_os, pool))
    (f1, e1, i1, p1, h_os, pool), (f2, e2, i2, p2, _, _) = runs
    try:
        if f1 != f2:
            raise DualComputationError(t("FINAL von Lauf 1 und Lauf 2 weichen ab",
                                         "FINAL of run 1 and run 2 differ"))
        if e1 != e2 or i1 != i2:
            raise DualComputationError(t("Entropie/Indizes von Lauf 1 und Lauf 2 weichen ab",
                                         "entropy/indices of run 1 and run 2 differ"))
        if p1 != p2:
            raise DualComputationError(t("Wortfolgen von Lauf 1 und Lauf 2 weichen ab",
                                         "word sequences of run 1 and run 2 differ"))
        _roundtrip_check(e1, i1, words_list)
    except DualComputationError as ex:
        _dual_abort(str(ex))
    trans = []
    if transparent:
        # audit M1: these lines contain the HMAC key and the seed entropy —
        # they are only BUFFERED here and printed by main() AFTER the final
        # offline check has passed (the last line of defence stays last).
        trans.append(C.DIM + t("   — Transparenz: alle Zwischenwerte des Kombinierers (Lauf 1; Lauf 2 identisch verifiziert) —",
                               "   — Transparency: all intermediate values of the combiner (run 1; run 2 verified identical) —") + C.RESET)
        trans.append(C.DIM + t(f"   Modus-Tag im Pool: {'light' if light else 'full'}",
                               f"   mode tag in pool: {'light' if light else 'full'}") + C.RESET)
        trans.append(f"   H_hw   = {hw.digest.hex()}")
        if dec: trans.append(f"   H_dec  = {dec.digest.hex()}")
        if cam: trans.append(f"   H_cam  = {cam.digest.hex()}")
        trans.append(f"   H_os   = {h_os.hex()}")
        trans.append(f"   POOL   = {pool.hex()}")
        if mock:
            # audit F3-H5: with --transparenz these three lines are a COMPLETE
            # valid seed — while mock skips every air-gap/TTY/swap gate. The
            # H3 index masking must not be bypassable this way.
            maskiert = t("«im Mock maskiert»", "«masked in mock mode»")
            trans.append("   H_dice = " + maskiert + t("  (HMAC-Schluessel)", "  (HMAC key)"))
            trans.append("   FINAL  = HMAC-SHA512(H_dice, POOL) = " + maskiert)
            trans.append(f"   ENTROPY= FINAL[:{n_bytes}] = " + maskiert)
        else:
            trans.append(f"   H_dice = {dice.digest.hex()}" + t("  (HMAC-Schluessel)", "  (HMAC key)"))
            trans.append(f"   FINAL  = HMAC-SHA512(H_dice, POOL) = {f1.hex()}")
            trans.append(f"   ENTROPY= FINAL[:{n_bytes}] = {e1.hex()}")
    return e1, i1, trans


def bip39_indices(entropy: bytes):
    if len(entropy) not in (16, 20, 24, 28, 32):
        # audit F2-KRYPTO-1: out-of-spec lengths silently dropped bits
        raise ValueError(f"BIP39 ENT length must be 16/20/24/28/32 bytes, got {len(entropy)}")
    ent_bits = len(entropy) * 8
    cs_bits  = ent_bits // 32
    cs = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    num = (int.from_bytes(entropy, "big") << cs_bits) | cs
    total = ent_bits + cs_bits
    return [(num >> (total - 11 * (i + 1))) & 0x7FF for i in range(total // 11)]

def load_wordlist():
    """Looks for english.txt next to the script or in the 'mnemonic'
    package; verifies the SHA-256 hash."""
    candidates = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "english.txt")]
    try:
        # audit-46 SEC-8: "import mnemonic" fuehrte fremden Paket-Code mit
        # root-Rechten aus, bevor irgendein Hash geprueft war. find_spec
        # liefert den Paketpfad OHNE Modulausfuehrung.
        import importlib.util as _ilu
        _spec = _ilu.find_spec("mnemonic")
        if _spec is not None and _spec.submodule_search_locations:
            candidates.append(os.path.join(
                list(_spec.submodule_search_locations)[0],
                "wordlist", "english.txt"))
    except Exception:
        pass
    for p in candidates:
        if os.path.exists(p):
            try:
                data = open(p, "rb").read()
            except OSError as e:
                # audit-46 SEC-12: kontrollierter Abbruch statt Traceback
                fail_abort("BIP39-Wortliste",
                           t(f"Lesefehler: {e}", f"read error: {e}"))
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
    """Explicit self-test check — unlike assert this is NOT stripped by
    python3 -O (audit M1)."""
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
    #    ("abandon" x 11 + "about", since 'about' is index 3 of the wordlist)
    idx = bip39_indices(b"\x00" * 16)
    _st(idx == [0] * 11 + [3], t(f"Vektor 0x00: {idx}", f"vector 0x00: {idx}"))
    # 2) Vektor 16x 0xFF: erste 11 Indizes = 2047, letzter = (0x7F<<4)|cs
    idx = bip39_indices(b"\xff" * 16)
    cs = hashlib.sha256(b"\xff" * 16).digest()[0] >> 4
    _st(idx[:11] == [2047] * 11 and idx[11] == (0x7F << 4) | cs, t("Vektor 0xFF", "vector 0xFF"))
    # 3) Laengen: 128 Bit -> 12 Indizes, 256 Bit -> 24 Indizes
    _st(len(bip39_indices(os.urandom(16))) == 12, "Laenge 128 Bit")
    _st(len(bip39_indices(os.urandom(32))) == 24, "Laenge 256 Bit")
    # 4) checksum roundtrip for 256 bits
    e = os.urandom(32)
    idx = bip39_indices(e)
    num = 0
    for i in idx: num = (num << 11) | i
    ent = (num >> 8).to_bytes(32, "big")
    cs  = num & 0xFF
    _st(ent == e and cs == hashlib.sha256(e).digest()[0], t("Roundtrip 256", "roundtrip 256"))
    # 5) combiner: deterministic & sensitive to every source
    # audit F3-M10: combine() was production dead code with an unbuffered
    # transparency path — removed; freshness is tested on derive_chain with
    # two independently sampled os nonces (exactly what main() does).
    a = derive_chain(dsha512("hwrng", b"A"), dsha512("decay", b"B"),
                     dsha512("cam", b"C"), dsha512("dice", b"D"),
                     os.urandom(64), 32, False)[1]
    b = derive_chain(dsha512("hwrng", b"A"), dsha512("decay", b"B"),
                     dsha512("cam", b"C"), dsha512("dice", b"D"),
                     os.urandom(64), 32, False)[1]
    _st(a != b and len(a) == 32, t("Kombinierer nicht frisch/32B", "combiner not fresh/32B"))
    # 6) verify the HMAC combiner core deterministically (without the urandom part)
    pool = dsha512("pool", b"x")
    k1 = hmac.new(dsha512("dice", b"D1"), pool, hashlib.sha512).digest()
    k2 = hmac.new(dsha512("dice", b"D2"), pool, hashlib.sha512).digest()
    _st(k1 != k2, t("HMAC-Key-Sensitivitaet", "HMAC key sensitivity"))
    # 7) Wuerfel-Kodierung
    _st(dice_to_bytes([1, 1, 1]) == (3).to_bytes(4, "big") + b"\x00", t("Wuerfelkodierung 111", "dice encoding 111"))
    _st(dice_to_bytes([6]) == (1).to_bytes(4, "big") + b"\x05", t("Wuerfelkodierung 6", "dice encoding 6"))
    # 8) dual computation: deterministic chain, both runs identical
    nonce = b"N" * 64
    d1 = derive_chain(dsha512("hwrng", b"A"), dsha512("decay", b"B"),
                      dsha512("cam", b"C"), dsha512("dice", b"D"), nonce, 32, False)
    d2 = derive_chain(dsha512("hwrng", b"A"), dsha512("decay", b"B"),
                      dsha512("cam", b"C"), dsha512("dice", b"D"), nonce, 32, False)
    _st(d1 == d2 and len(d1[0]) == 64 and len(d1[1]) == 32,
        t("Doppellauf: identische Eingaben muessen identische Ketten liefern", "dual run: identical inputs must yield identical chains"))
    _st(derive_chain(dsha512("hwrng", b"A"), dsha512("decay", b"B"),
                     dsha512("cam", b"C"), dsha512("dice", b"D"), nonce, 32, True) != d1,
        t("Doppellauf: light/full muessen sich unterscheiden (Modus-Tag)", "dual run: light/full must differ (mode tag)"))
    # audit F2-KRYPTO-2: known-answer vector for the WHOLE derivation chain —
    # a deterministic combiner bug affects both dual runs identically and
    # would pass every other test; this vector pins the expected FINAL.
    kat_f, kat_e, _, _ = derive_chain(dsha512("hwrng", b"KAT"), dsha512("decay", b"KAT"),
                                      dsha512("cam", b"KAT"), dsha512("dice", b"KAT"),
                                      b"\x42" * 64, 32, False)
    _st(kat_f.hex() == ("4c320892672fb717c1efaf02cfe5ddee27ee43ab4a6465a8"
                        "4c534f8c1879023c16cec1ce977e9624e540becdfe7d99c5"
                        "99090287bdcc628ef72c423b2789fab5"),
        t("Known-Answer-Vektor der Ableitungskette (FINAL)", "known-answer vector of the derivation chain (FINAL)"))
    _st(bip39_indices(kat_e)[:3] == [609, 1154, 292],
        t("Known-Answer-Vektor der Ableitungskette (Indizes)", "known-answer vector of the derivation chain (indices)"))
    try:
        bip39_indices(b"\x00" * 17)
        _st(False, t("ENT-Laengenvalidierung: 17 Byte wurden NICHT abgewiesen", "ENT length validation: 17 bytes were NOT rejected"))
    except ValueError:
        pass
    # 9) fault injection: a deliberately corrupted intermediate MUST take
    #    the abort path (DualComputationError) — proves the check can fire
    ent = os.urandom(32)
    idx_ok = bip39_indices(ent)
    _roundtrip_check(ent, idx_ok, None)             # correct -> no exception
    kaputt = list(idx_ok); kaputt[5] ^= 1           # flip one bit in one index
    try:
        _roundtrip_check(ent, kaputt, None)
        _st(False, t("Fault-Injection: verfaelschter Index wurde NICHT erkannt", "fault injection: corrupted index was NOT detected"))
    except DualComputationError:
        pass
    ent_kaputt = bytearray(ent); ent_kaputt[0] ^= 0x80
    try:
        _roundtrip_check(bytes(ent_kaputt), idx_ok, None)
        _st(False, t("Fault-Injection: verfaelschte Entropie wurde NICHT erkannt", "fault injection: corrupted entropy was NOT detected"))
    except DualComputationError:
        pass
    # 10) verify the wordlist (if present)
    words, path = load_wordlist()
    if words:
        _st(words[0] == "abandon" and words[3] == "about" and words[2047] == "zoo", t("Wortliste Stichprobe", "wordlist spot check"))
        _wordlist_recheck(words)                    # in-memory serialization -> reference hash
        w_kaputt = list(words); w_kaputt[1000] = "notaword"
        try:
            _wordlist_recheck(w_kaputt)
            _st(False, t("Fault-Injection: korrumpierte Wortliste wurde NICHT erkannt", "fault injection: corrupted wordlist was NOT detected"))
        except DualComputationError:
            pass
        print(t(f"  Wortliste verifiziert (inkl. RAM-Recheck + Fault-Injection): {path}",
                f"  Wordlist verified (incl. RAM re-check + fault injection): {path}"))
    else:
        print(t("  Hinweis: keine english.txt gefunden — Wortlistentest uebersprungen.", "  Note: no english.txt found — wordlist test skipped."))
    print(C.GRN + t("  ✔ Alle Selbsttests bestanden.", "  ✔ All self-tests passed.") + C.RESET)



# ----------------------------------------------------------------------------
# Security briefing at startup (confirmation required)
# ----------------------------------------------------------------------------
def security_briefing(args):
    """Offline ground rules in a red box. Without explicit confirmation
    the program exits. In --yes/mock mode the box is shown but not
    prompted (no interaction possible)."""
    B = 78  # inner width of the box
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
    zeile(t("   und uebertragen).", "   and transmit)."))   # audit-46 CODE-6: EN ergaenzt
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
def _remote_ancestors():
    """Audit H1: sudo strips SSH_*/TMUX/STY by default (env_reset), so the
    env-based checks are blind in the documented 'sudo python3 …' call.
    Walk the process ancestry via /proc instead — sudo-robust."""
    gefunden = set()
    try:
        pid = os.getpid()
        for _ in range(64):
            with open(f"/proc/{pid}/stat") as f:
                kopf, rest = f.read().rsplit(")", 1)
            comm = kopf.split("(", 1)[1].lower()
            felder = rest.split()
            # audit F2-M2/N7: broader marker set (VNC/xrdp/telnet/mosh/
            # dropbear ship with Raspberry Pi OS or are common), prefix
            # matching instead of substring (no 'javascriptsrv' hits)
            for marker in ("sshd", "tmux", "screen", "script", "xrdp",
                           "telnetd", "in.telnetd", "mosh-server", "dropbear",
                           "nxnode", "xvnc", "x11vnc", "wayvnc", "tigervnc",
                           "tightvnc", "vino", "vncserver", "novnc",
                           # audit F3-M7: browser terminals stream the tty
                           # over the network like SSH does
                           "ttyd", "wetty", "shellinabox", "cockpit-ws",
                           "websockify", "gotty",
                           # audit-46 SEC-2: weitere Rekorder/Remote-Zugaenge
                           # (ttyrec = lokaler pty-Rekorder; x0vncserver wird
                           # vom Praefix 'xvnc' NICHT erfasst; krfb = KDE-VNC)
                           "ttyrec", "x0vncserver", "krfb", "waypipe"):
                if comm == marker or comm.startswith(marker):
                    gefunden.add("vnc" if "vnc" in marker or marker == "vino"
                                 else ("telnetd" if "telnet" in marker else marker))
            ppid = int(felder[1])
            if ppid <= 1:
                break
            pid = ppid
    except Exception:
        pass
    return gefunden


def check_remote_session(args):
    """Over SSH the seed would leave the air gap and end up in the remote
    client's scrollback; tmux/screen can record sessions. Detection uses
    BOTH the environment and the process ancestry (audit H1)."""
    if args.mock:
        return
    ahnen = _remote_ancestors()
    ssh = (os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY")
           or bool(ahnen & {"sshd", "dropbear", "telnetd", "mosh-server",
                            "vnc", "xrdp", "nxnode", "ttyd", "wetty",
                            "shellinabox", "cockpit-ws", "websockify", "gotty",
                            "krfb", "waypipe"}))   # audit-46 SEC-2
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
        try:
            antwort = input(t("   Trotzdem fortfahren? Nur 'ja' setzt fort: ",
                              "   Continue anyway? Only 'yes' continues: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            antwort = ""
        if antwort not in ("ja", "yes", "y"):
            fail_abort("SSH-Erkennung / SSH detection",
                       t("Vom Benutzer abgebrochen — bitte lokal an Tastatur/Monitor arbeiten.",
                         "aborted by user — please work locally on keyboard/monitor."))
    if (os.environ.get("TMUX") or os.environ.get("STY") or ("tmux" in ahnen)
            or ("screen" in ahnen) or ("ttyrec" in ahnen)):   # audit-46 SEC-2: ttyrec = lokaler Rekorder
        # audit F2-N7: only a yellow note before — but the wipe demonstrably
        # does not reach these buffers, so require confirmation like SSH
        print(C.RED + C.BOLD + t(
            " ⚠ tmux/screen/ttyrec erkannt: Die Scrollback-Loeschung erreicht deren "
            "Puffer/Logs NICHT zuverlaessig — der Seed koennte dort verbleiben!",
            " ⚠ tmux/screen/ttyrec detected: the scrollback erase does NOT reliably reach "
            "their buffers/logs — the seed could persist there!") + C.RESET)
        if args.yes:
            fail_abort("tmux/screen-Erkennung / tmux/screen detection",
                       t("Automatikmodus bricht in tmux/screen-Sitzungen ab.",
                         "automatic mode aborts inside tmux/screen sessions."))
        try:
            antwort = input(t("   Trotzdem fortfahren? Nur 'ja' setzt fort: ",
                              "   Continue anyway? Only 'yes' continues: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            antwort = ""
        if antwort not in ("ja", "yes", "y"):
            fail_abort("tmux/screen-Erkennung / tmux/screen detection",
                       t("Vom Benutzer abgebrochen.", "aborted by user."))


def require_tty_stdout(args):
    """Audit H2: if stdout is not a terminal (pipe, tee, redirect), the seed
    words would be written PERSISTENTLY — the ANSI wipe sequences only work
    on a real TTY. Loud abort for real runs; mock is exempt (tests pipe).
    script(1) allocates a pty (isatty() is true) but logs everything, so it
    is detected via the process ancestry and needs explicit confirmation."""
    if args.mock:
        return
    if not sys.stdout.isatty():
        fail_abort("Ausgabekanal / output channel",
                   t("stdout ist kein Terminal (Pipe/Umleitung/tee erkannt) — der Seed "
                     "wuerde dauerhaft gespeichert (Wipe-Sequenzen wirkungslos). Bitte "
                     "direkt im Terminal starten, ohne | > oder tee.",
                     "stdout is not a terminal (pipe/redirect/tee detected) — the seed "
                     "would be stored persistently (wipe sequences ineffective). Please "
                     "run directly in a terminal, without | > or tee."))
    if "script" in _remote_ancestors():
        print(C.RED + C.BOLD + t(
            " ⚠ script(1)-SITZUNG ERKANNT — alles (auch der Seed) wird in die "
            "Typescript-Datei geschrieben!",
            " ⚠ script(1) SESSION DETECTED — everything (including the seed) is "
            "written to the typescript file!") + C.RESET)
        if args.yes:
            fail_abort("Ausgabekanal / output channel",
                       t("Automatikmodus bricht in script(1)-Sitzungen ab (Audit H2).",
                         "automatic mode aborts inside script(1) sessions (audit H2)."))
        try:
            antwort = input(t("   Trotzdem fortfahren? Nur 'ja' setzt fort: ",
                              "   Continue anyway? Only 'yes' continues: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            antwort = ""
        if antwort not in ("ja", "yes", "y"):
            fail_abort("Ausgabekanal / output channel",
                       t("Vom Benutzer abgebrochen.", "aborted by user."))


# ----------------------------------------------------------------------------
# Root-Pruefung: Hardware-Zugriff erfordert sudo
# ----------------------------------------------------------------------------
def require_root(args):
    """/dev/hwrng, rfkill, swapoff and history cleanup require root.
    Clear guidance instead of a 'Permission denied' mid-run."""
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
# WLAN disable at startup (Ethernet remains untouched)
# ----------------------------------------------------------------------------
def disable_wifi(args):
    """Blocks WLAN AND Bluetooth via rfkill (persistent across reboots,
    since systemd-rfkill stores the state). Ethernet is not affected."""
    if args.mock:
        # audit F3-H2: a mock run must NOT mutate the host (rfkill block is
        # reboot-persistent via systemd-rfkill)
        print(C.DIM + t("   [Mock] Funk-Deaktivierung nur simuliert.",
                        "   [mock] radio disable simulated only.") + C.RESET)
        return
    if getattr(args, "keep_wifi", False):
        print(C.YEL + t(" ⚠ Funkmodule (WLAN+Bluetooth) bleiben auf Wunsch AKTIV (--keep-wifi) — fuer echte Seeds nicht empfohlen!", " ⚠ Radios (WLAN+Bluetooth) stay ACTIVE on request (--keep-wifi) — not recommended for real seeds!") + C.RESET)
        return
    import subprocess
    methode = None
    try:
        subprocess.run(["rfkill", "block", "all"], check=True,   # audit F2-N8: also wwan/uwb/gps/nfc
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
            print(C.YEL + t(" ⚠ Funk-Deaktivierung nicht moeglich (rfkill/nmcli fehlen) "
                  "— im MOCK-Modus toleriert.",
                  " ⚠ radio disable not possible (rfkill/nmcli missing) "
                  "— tolerated in MOCK mode.") + C.RESET)
            return
        print(C.RED + C.BOLD + t(" ⚠ Funkmodule konnten NICHT deaktiviert werden "
              "(rfkill/nmcli fehlgeschlagen — sudo? rfkill installiert?).",
              " ⚠ Radios could NOT be disabled (rfkill/nmcli failed — sudo? "
              "rfkill installed?).") + C.RESET)
        if args.yes:
            fail_abort("Funk-Deaktivierung", "Automatikmodus (--yes) bricht ohne "
                       "bestaetigte Netztrennung ab.")
        try:
            antwort = input(t("   Trotzdem fortfahren? Nur 'ja' setzt fort: ", "   Continue anyway? Only 'yes' continues: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            antwort = ""
        if antwort not in ("ja", "yes", "y"):
            fail_abort("Funk-Deaktivierung", "Vom Benutzer abgebrochen — bitte Funk "
                       "manuell trennen und neu starten.")


# ----------------------------------------------------------------------------
# Success sound in Atari style (square wave via HDMI, entirely in RAM)
# ----------------------------------------------------------------------------
def play_success_jingle():
    """Ascending square-wave arpeggio like in early video games.
    Best-effort: every failure condition (no aplay, no audio) is silently
    ignored — the sound must never affect the run. No file is written
    (the WAV is built in memory, aplay reads stdin)."""
    try:
        import io as _io
        import shutil as _shutil
        import struct
        import subprocess
        import wave
        if not _shutil.which("aplay"):
            return
        rate = 22050
        # The original power-up jingle (C5 E5 G5 C6), stretched to ~3x length:
        # gestreckt: gemaechlichere Achtel + lang gehaltener Schlusston.
        noten = [(523.25, 0.18), (659.25, 0.18), (783.99, 0.18), (1046.50, 1.05)]
        frames = bytearray()
        for freq, dauer in noten:
            n = int(rate * dauer)
            periode = rate / freq
            for i in range(n):
                # square wave (50% duty) + decay envelope as in the original
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
# Permanent radio disable at firmware level (device-tree overlays)
# ----------------------------------------------------------------------------
def enforce_permanent_radio_off(args):
    """ENFORCED (confirmed via the security rules): WLAN+Bluetooth are
    permanently disabled at firmware level via dtoverlay entries in
    config.txt — the chips are no longer initialized from the next boot
    on."""
    if args.mock:
        return
    if getattr(args, "keep_wifi", False):
        # audit M2: never write persistent overlays against the user's will
        print(C.YEL + t(" ⚠ --keep-wifi: dauerhafte Firmware-Abschaltung wird NICHT eingetragen.",
                        " ⚠ --keep-wifi: permanent firmware disable is NOT written.") + C.RESET)
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
    # audit F2-M1: substring matching counted commented-out lines
    # ("#dtoverlay=disable-wifi") as active -> silent fails-open at the
    # exact spot sold as the permanence guarantee. Parse line-wise and
    # accept only UNcommented directives.
    # audit F3-H1: an entry below a conditional filter ([pi4], [cm5], …)
    # does nothing on a Pi 5 but used to count as "already disabled", and
    # appending to a file that ENDS in such a section wrote dead entries.
    # Parse section-aware: only unconditional context, [all] and [pi5]
    # count; always append under an explicit [all] header.
    hat_wifi = hat_bt = False
    sektion = "all"        # unconditional start of file behaves like [all]
    for z in (z.strip() for z in inhalt.split("\n")):
        if not z or z.startswith("#"):
            continue
        if z.startswith("[") and z.endswith("]"):
            sektion = z[1:-1].lower()
            continue
        if sektion in ("all", "pi5"):
            # audit-46 SEC-4: exakter Match — z.startswith() akzeptierte auch
            # "dtoverlay=disable-wifi-extra" o. ae., das die Firmware ignoriert
            # (fail-open der Persistenzgarantie bei manipulierter Vorkonfiguration)
            if z == "dtoverlay=disable-wifi":
                hat_wifi = True
            elif z == "dtoverlay=disable-bt":
                hat_bt = True
    if hat_wifi and hat_bt:
        print(C.GRN + t(" ✔ Funkchips sind bereits auf Firmware-Ebene deaktiviert.",
                        " ✔ Radio chips are already disabled at firmware level.") + C.RESET)
        return
    try:
        try:      # audit F3-H1: restore point (vfat has no journal)
            with open(pfad + ".seedgen.bak", "w") as bf:
                bf.write(inhalt)
                bf.flush()
                os.fsync(bf.fileno())   # audit-46 HW-7: Stromausfall darf auch das Backup nicht fressen
        except Exception:
            pass
        zusatz = "\n[all]\n# QUANTUM SEED GENERATOR: Funk dauerhaft deaktiviert\n"
        if not hat_wifi:
            zusatz += "dtoverlay=disable-wifi\n"
        if not hat_bt:
            zusatz += "dtoverlay=disable-bt\n"
        with open(pfad, "a") as f:
            f.write(zusatz)
            f.flush()
            os.fsync(f.fileno())   # audit F3-H1: power loss must not eat the entry
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
# Mandatory check: the Ethernet cable must be removed
# ----------------------------------------------------------------------------
# audit-46 SEC-3/HW-5: EIN einheitlicher Filter fuer Wake-Schleife und
# permanente Abschaltung — virtuelle/Spezial-Interfaces (docker, veth,
# Bridges, Bluetooth-PAN, VPN, Modem) werden weder geweckt noch in die
# systemd-Unit aufgenommen. _eth_verbunden behaelt absichtlich seinen
# engeren Filter (fail-safe: usb0/enx*/wwan werden als "Kabel" gemeldet).
_IF_SKIP_PREFIXES = ("wlan", "wl", "blu", "docker", "veth", "br-", "virbr",
                     "bnep", "ppp", "tun", "tap", "wwan")

def _eth_verbunden():
    """List of wired interfaces with an active link (cable plugged in)."""
    aktiv = []
    try:
        for n in os.listdir("/sys/class/net"):
            if n == "lo" or n.startswith(("wlan", "wl", "blu", "docker",
                                          "veth", "br-", "virbr", "bnep")):
                continue   # audit F3-N13: virtual/BT-tether ifaces are not cables
            try:
                if open(f"/sys/class/net/{n}/carrier").read().strip() == "1":
                    aktiv.append(n)
            except OSError:
                pass          # interface down -> no active link
    except Exception:
        pass
    return aktiv

def require_ethernet_unplugged(args):
    """Forces the physical removal of the Ethernet cable: as long as a
    link is detected the program does not continue. After the 'yes'
    confirmation the state is re-measured technically."""
    if args.mock:
        return
    # audit M4: a DOWN interface hides its carrier state ("cable plugged,
    # interface down" reads as "no link") — exactly the state the optional
    # systemd unit creates at every boot. Wake wired DOWN interfaces up for
    # the duration of this gate, then restore their state.
    geweckt = []
    try:
        import subprocess
        for n in os.listdir("/sys/class/net"):
            if n == "lo" or n.startswith(_IF_SKIP_PREFIXES):
                continue
            try:
                oper = open(f"/sys/class/net/{n}/operstate").read().strip()
            except OSError:
                continue
            if oper == "down":
                subprocess.run(["ip", "link", "set", n, "up"],
                               capture_output=True, timeout=10)   # audit-46 HW-5
                geweckt.append(n)
        if geweckt:
            # audit F2-N9: link auto-negotiation can take > 1 s — poll the
            # carrier up to 5 s instead of a fixed single wait
            for _ in range(10):
                time.sleep(0.5)
                if _eth_verbunden():
                    break
            print(C.DIM + t(f"   (Pruefe auch abgeschaltete Interfaces: {', '.join(geweckt)})",
                            f"   (also probing interfaces that were down: {', '.join(geweckt)})") + C.RESET)
            # audit F3-M2: interfaces without a cable go straight back down —
            # only a genuinely plugged one stays up for the unplug dialog
            # (NM/dhcpcd could otherwise pull a lease in the background)
            mit_kabel = set(_eth_verbunden())
            for n in list(geweckt):
                if n not in mit_kabel:
                    subprocess.run(["ip", "link", "set", n, "down"],
                                   capture_output=True, timeout=10)   # audit-46 HW-5
    except Exception:
        pass
    try:
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
            time.sleep(1.0)   # give the link status a moment to settle after unplugging
            if _eth_verbunden():
                print(C.RED + t("   ✘ Nachpruefung: Es wird WEITERHIN ein aktiver "
                                    "Ethernet-Link erkannt!",
                                "   ✘ Re-check: an active Ethernet link is STILL "
                                "detected!") + C.RESET)


    finally:
        try:
            import subprocess
            for n in geweckt:   # audit M4: restore previous DOWN state
                subprocess.run(["ip", "link", "set", n, "down"], capture_output=True)
        except Exception:
            pass

# ----------------------------------------------------------------------------
# Optional Ethernet shutdown (immediate and/or permanent)
# ----------------------------------------------------------------------------
ETH_UNIT_PATH = "/etc/systemd/system/seedgen-ethernet-off.service"

# Project donation address (leave empty = the notice is never shown).
# IMPORTANT: publish the address in the README/docs as well so users can
# cross-check it against the one displayed here (address-swap protection).
DONATION_BTC = ""

def offer_ethernet_off(args):
    """Two separate, optional questions: 1) disable Ethernet NOW
    (ip link down, until reboot). 2) disable PERMANENTLY (a systemd unit
    takes the interfaces down at every boot)."""
    if args.yes or args.mock:
        return
    try:
        ifaces = [n for n in os.listdir("/sys/class/net")
                  if n != "lo" and not n.startswith(_IF_SKIP_PREFIXES)]   # audit-46 HW-5: keine virtuellen Interfaces in Unit/NM-Conf
    except Exception:
        return
    if not ifaces:
        return
    import subprocess
    liste = ", ".join(ifaces)
    print(C.DIM + t(f"   Optional: Kabelnetzwerk ({liste}) laesst sich hier ebenfalls abschalten.",
                    f"   Optional: wired network ({liste}) can also be disabled here.") + C.RESET)
    # ---- Question 1: now ----
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
    # ---- Question 2: permanent ----
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
        # audit F2-M3: interface names went unescaped into 'sh -c' — a
        # root command-injection surface (kernel allows e.g. 'x;cmd' as a
        # name). No shell at all: one ExecStart per interface (systemd
        # execs directly), names strictly validated beforehand.
        import re as _re
        sichere = [i for i in ifaces if _re.fullmatch(r"[A-Za-z0-9_.-]+", i)]
        for verdaechtig in set(ifaces) - set(sichere):
            print(C.YEL + t(f"   ⚠ Interface '{verdaechtig}' uebersprungen (unerwarteter Name).",
                            f"   ⚠ interface '{verdaechtig}' skipped (unexpected name).") + C.RESET)
        if not sichere:
            print(C.YEL + t("   ⚠ Kein gueltiges Interface — Unit wird nicht angelegt.",
                            "   ⚠ no valid interface — unit not created.") + C.RESET)
            return
        # audit F3-H4: without ordering the unit raced NetworkManager/dhcpcd
        # (which re-raise the link on the next carrier event), '-' hid every
        # failure and the hardcoded ip path could silently not exist.
        ip_bin = shutil.which("ip") or "/usr/sbin/ip"
        exec_zeilen = "".join(f"ExecStart={ip_bin} link set {i} down\n" for i in sichere)
        unit = ("[Unit]\n"
                "Description=QUANTUM SEED GENERATOR: Ethernet dauerhaft deaktiviert\n"
                "DefaultDependencies=no\n"
                "Before=network-pre.target\n"
                "Wants=network-pre.target\n\n"
                "[Service]\nType=oneshot\n"
                f"{exec_zeilen}\n"
                "[Install]\nWantedBy=multi-user.target\n")
        # NetworkManager wuerde die Interfaces sonst beim naechsten
        # Carrier-Event wieder aktivieren -> dauerhaft auf unmanaged setzen
        nm_conf_dir = "/etc/NetworkManager/conf.d"
        if os.path.isdir(nm_conf_dir):
            geraete = ";".join(f"interface-name:{i}" for i in sichere)
            with open(os.path.join(nm_conf_dir, "99-seedgen-unmanaged.conf"), "w") as nf:
                nf.write("# QUANTUM SEED GENERATOR: Ethernet dauerhaft unmanaged\n"
                         f"[keyfile]\nunmanaged-devices={geraete}\n")
                nf.flush()
                os.fsync(nf.fileno())   # audit-46 HW-7
            print(C.DIM + t("   NetworkManager: Interfaces dauerhaft auf 'unmanaged' gesetzt.",
                            "   NetworkManager: interfaces set to 'unmanaged' permanently.") + C.RESET)
        with open(ETH_UNIT_PATH, "w") as f:
            f.write(unit)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=15)
        subprocess.run(["systemctl", "enable", os.path.basename(ETH_UNIT_PATH)],
                       check=True, capture_output=True, timeout=15)
        # audit F3-H4: prove the unit actually works instead of hoping
        probe = subprocess.run(["systemctl", "start", os.path.basename(ETH_UNIT_PATH)],
                               capture_output=True, timeout=20)
        if probe.returncode != 0:
            print(C.YEL + t("   ⚠ Test-Start der Unit fehlgeschlagen — bitte manuell pruefen: "
                            "systemctl status " + os.path.basename(ETH_UNIT_PATH),
                            "   ⚠ test start of the unit failed — please check manually: "
                            "systemctl status " + os.path.basename(ETH_UNIT_PATH)) + C.RESET)
        print(C.GRN + t(f" ✔ Dauerhaft eingerichtet ({ETH_UNIT_PATH}) — Ethernet wird ab "
                        "jetzt bei jedem Boot stillgelegt.",
                        f" ✔ Permanently installed ({ETH_UNIT_PATH}) — Ethernet will be "
                        "taken down at every boot.") + C.RESET)
    except Exception as e:
        print(C.YEL + t(f"   ⚠ Dauerhafte Einrichtung fehlgeschlagen ({e}).",
                        f"   ⚠ Permanent setup failed ({e}).") + C.RESET)


# ----------------------------------------------------------------------------
# Final offline check immediately BEFORE the seed display
# ----------------------------------------------------------------------------
def _sys_rfkill_unblocked_types():
    """audit F2-N8: types beyond wlan/bluetooth (wwan, uwb, gps, nfc) read
    directly from /sys — plugged USB radios must not slip through."""
    offen = set()
    try:
        basis = "/sys/class/rfkill"
        for d in os.listdir(basis):
            try:
                typ = open(f"{basis}/{d}/type").read().strip()
                soft = open(f"{basis}/{d}/soft").read().strip()
                hard = open(f"{basis}/{d}/hard").read().strip()
                if soft == "0" and hard == "0":
                    offen.add(typ)
            except OSError:
                continue
    except Exception:
        pass
    return offen


def _rfkill_blockiert(typ):
    """True = all devices of this type blocked OR none present
    (firmware-disabled). False = at least one device active.
    None = rfkill not available / failed (audit-46 SEC-1: a failing rfkill
    returned empty stdout and used to count as 'blocked' — fail-open.
    Non-zero exit code now means 'unverifiable', never 'blocked')."""
    import re as _re
    import subprocess
    try:
        r = subprocess.run(["rfkill", "list", typ], capture_output=True,
                           text=True, timeout=10)
    except Exception:
        return None
    if r.returncode != 0:
        return None                    # audit-46 SEC-1: Fehler != blockiert
    out = r.stdout
    if not out.strip():
        return True
    for block in _re.split(r"\n(?=\d+:)", out):
        if ("Soft blocked: no" in block) and ("Hard blocked: no" in block):
            return False
    return True

def final_offline_check(args):
    """Last line of defence: immediately before the seed becomes visible,
    WLAN, Bluetooth and Ethernet are checked again. If any channel was
    (re-)activated in the meantime (tampering), the program exits
    IMMEDIATELY — the seed never appears on screen."""
    if args.mock:
        return
    keep = getattr(args, "keep_wifi", False)
    if keep:
        # audit M2: with --keep-wifi the WLAN/BT requirement would make a
        # seed display impossible — skip it consistently, but say so loudly.
        print(C.RED + C.BOLD + t(
            " ⚠ --keep-wifi: WLAN/Bluetooth-Teil der finalen Offline-Pruefung UEBERSPRUNGEN — Air-Gap NICHT garantiert!",
            " ⚠ --keep-wifi: WLAN/Bluetooth part of the final offline check SKIPPED — air gap NOT guaranteed!") + C.RESET)
    probleme = []
    # WLAN
    rf = None if keep else _rfkill_blockiert("wlan")
    if rf is False:
        probleme.append("WLAN")
    elif rf is None and not keep:
        # audit F3-N4b: without rfkill a merely DOWN wlan interface counted
        # as "off" (fail-open) — an existing wlan device without a verified
        # block is "unverifiable", not "fine".
        try:
            wlans = [n for n in os.listdir("/sys/class/net")
                     if n.startswith(("wlan", "wl"))]
            for n in wlans:
                if open(f"/sys/class/net/{n}/operstate").read().strip() == "up":
                    probleme.append("WLAN")
                    break
            else:
                if wlans:
                    probleme.append(t("WLAN (nicht pruefbar — rfkill fehlt)",
                                      "WLAN (unverifiable — rfkill missing)"))
        except Exception:
            probleme.append(t("WLAN (nicht pruefbar)", "WLAN (unverifiable)"))
    # Bluetooth
    rf = None if keep else _rfkill_blockiert("bluetooth")
    if rf is False:
        probleme.append("Bluetooth")
    elif rf is None and not keep:
        try:
            if os.path.isdir("/sys/class/bluetooth") and os.listdir("/sys/class/bluetooth"):
                probleme.append(t("Bluetooth (nicht pruefbar)", "Bluetooth (unverifiable)"))
        except Exception:
            pass
    # Ethernet (cable unplugged OR interface down)
    if _eth_verbunden():
        probleme.append("Ethernet")
    # audit F2-N8: plugged USB radios of any type (wwan/uwb/gps/nfc)
    # audit-46 SEC-1: wlan/bluetooth NICHT mehr exkludieren — der sysfs-Pfad
    # ist der daemon-/lokalitaetsunabhaengige Gegenbeweis zum rfkill-Kommando
    # (Dedup: "WLAN"/"Bluetooth" stehen ggf. bereits in probleme).
    # audit-46 SEC-11: laeuft auch mit --keep-wifi; nur die explizit
    # behaltenen Typen wlan/bluetooth werden dann toleriert.
    for typ in sorted(_sys_rfkill_unblocked_types()):
        if keep and typ in ("wlan", "bluetooth"):
            continue
        if typ == "wlan" and any("WLAN" in p for p in probleme):
            continue
        if typ == "bluetooth" and any("Bluetooth" in p for p in probleme):
            continue
        probleme.append(t(f"Funk: {typ}", f"radio: {typ}"))
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
# No traces on storage media: swap check + cleanup at the end
# ----------------------------------------------------------------------------
# audit-47: RAM-Haertung. Zwei Schichten zusaetzlich zu RLIMIT_CORE=0 und
# swapoff:
#   1) mlockall(MCL_CURRENT|MCL_FUTURE) pinnt alle Seiten im RAM. swapoff
#      hat eine dokumentierte Luecke — Seiten, die VOR dem swapoff ausgelagert
#      wurden, bleiben in den Swap-Bloecken liegen, und auf SD/eMMC ist
#      Loeschen wegen Wear-Leveling forensisch unzuverlaessig. mlockall greift
#      auch, wenn swapoff scheitert (zram, Swap-Datei, fehlende Rechte) oder
#      ein anderer Prozess waehrend des Laufs Swap reaktiviert.
#   2) PR_SET_DUMPABLE=0 macht /proc/<pid>/mem|maps fuer Nicht-root
#      unlesbar und blockt ptrace (gdb -p, strace). RLIMIT_CORE=0 verhindert
#      nur den Dump beim ABSTURZ — das hier verhindert das Auslesen im
#      BETRIEB (30-90 min Laufzeit).
# Beides ist Verteidigungstiefe, kein Ersatz fuer "ein frischer Boot pro
# Seed-Zeremonie": gegen root, Cold-Boot/DMA und CPythons unloeschbare
# bytes-Objekte hilft es nicht.
_PR_SET_DUMPABLE = 4

def harden_process_memory(args):
    """Best effort; jede Schicht wird einzeln gemeldet und einzeln
    abgesichert (ein Fehlschlag darf die andere nicht verhindern)."""
    if args.mock:
        print(C.DIM + t("   [Mock] RAM-Haertung nur simuliert.",
                        "   [mock] RAM hardening simulated only.") + C.RESET)
        return
    import ctypes
    import ctypes.util
    fehler = []
    try:
        _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                            use_errno=True)
    except Exception as e:
        print(C.YEL + t(f"   ⚠ RAM-Haertung nicht moeglich (libc: {e}).",
                        f"   ⚠ RAM hardening not possible (libc: {e}).") + C.RESET)
        return
    # ---- 1) mlockall ----
    # RLIMIT_MEMLOCK ist fuer Nicht-root oft auf wenige MB begrenzt und
    # mlockall scheitert dann mit ENOMEM. Als root das Limit vorher anheben.
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_MEMLOCK,
                           (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception:
        pass          # nicht root oder Limit gedeckelt — mlockall entscheidet
    try:
        MCL_CURRENT, MCL_FUTURE = 1, 2
        if _libc.mlockall(MCL_CURRENT | MCL_FUTURE) == 0:
            print(C.GRN + t(" ✔ RAM-Haertung: Speicherseiten im RAM gepinnt (mlockall) — "
                            "kein Auslagern auf die SD-Karte moeglich.",
                            " ✔ RAM hardening: memory pages pinned in RAM (mlockall) — "
                            "no paging to the SD card possible.") + C.RESET)
        else:
            err = ctypes.get_errno()
            fehler.append(f"mlockall (errno {err}: {os.strerror(err)})")
    except Exception as e:
        fehler.append(f"mlockall ({e})")
    # ---- 2) PR_SET_DUMPABLE ----
    try:
        if _libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
            print(C.GRN + t(" ✔ RAM-Haertung: Prozessspeicher gesperrt (PR_SET_DUMPABLE=0) — "
                            "kein ptrace/proc-Zugriff durch Fremdprozesse.",
                            " ✔ RAM hardening: process memory locked (PR_SET_DUMPABLE=0) — "
                            "no ptrace/proc access by other processes.") + C.RESET)
        else:
            err = ctypes.get_errno()
            fehler.append(f"prctl (errno {err}: {os.strerror(err)})")
    except Exception as e:
        fehler.append(f"prctl ({e})")
    for f in fehler:
        # Kein Abbruch: swapoff + RLIMIT_CORE=0 bleiben als Basisschutz aktiv.
        print(C.YEL + t(f"   ⚠ RAM-Haertung teilweise fehlgeschlagen: {f} — "
                        "Basisschutz (swapoff, RLIMIT_CORE=0) bleibt aktiv.",
                        f"   ⚠ RAM hardening partially failed: {f} — "
                        "base protection (swapoff, RLIMIT_CORE=0) stays active.") + C.RESET)


def check_swap(args):
    """Active swap could page entropy/seed from RAM to the SD card.
    It is disabled here (the script runs as root)."""
    if args.mock:
        # audit F3-H2: never run a real swapoff from a simulation
        print(C.DIM + t("   [Mock] Swap-Pruefung nur simuliert.",
                        "   [mock] swap check simulated only.") + C.RESET)
        return
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
        print(C.YEL + t(" \u26a0 Swap aktiv, Deaktivierung fehlgeschlagen \u2014 im MOCK-Modus "
              "toleriert.",
              " \u26a0 swap active, disabling failed \u2014 tolerated in MOCK mode.") + C.RESET)
        return
    print(C.RED + C.BOLD + t(" \u26a0 Swap ist AKTIV und konnte nicht deaktiviert werden \u2014 "
          "Seed-Daten koennten auf die SD-Karte gelangen!",
          " \u26a0 Swap is ACTIVE and could not be disabled \u2014 seed data could "
          "end up on the SD card!") + C.RESET)
    if args.yes:
        fail_abort("Swap-Pruefung", "Automatikmodus bricht mit aktivem Swap ab.")
    try:
        antwort = input(t("   Trotzdem fortfahren? Nur 'ja' setzt fort: ",
                          "   Continue anyway? Only 'yes' continues: ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        antwort = ""
    if antwort not in ("ja", "yes", "y"):
        fail_abort("Swap-Pruefung",
                   t("Vom Benutzer abgebrochen \u2014 sudo swapoff -a ausfuehren und neu starten.",
                     "aborted by user \u2014 run sudo swapoff -a and restart."))

def verify_seed_transcription(idx, words_list, args):
    """Audit H6: the user re-enters the written phrase; comparison against
    the generated words uncovers transcription errors. Optional.
    Loop instead of recursion (audit N5): a RecursionError after ~1000
    failed attempts would skip secure_cleanup with the seed on screen."""
    while True:
        if _verify_transcription_once(idx, words_list, args):
            return


def _verify_transcription_once(idx, words_list, args) -> bool:
    if args.yes or args.mock or not words_list or not sys.stdin.isatty():
        return True
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
        return True
    if antwort not in ("ja", "yes", "y"):
        return True
    print(C.DIM + t("   Alle Woerter VOM PAPIER in einer Zeile (Leerzeichen und/oder Kommas als Trenner):",
                    "   All words FROM YOUR PAPER on one line (spaces and/or commas as separators):") + C.RESET)
    try:
        roh = input(C.ORA + "   > " + C.RESET + C.GRN).strip().lower()
        sys.stdout.write(C.RESET); sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        sys.stdout.write(C.RESET)
        return True
    # tolerant parsing: treat commas/semicolons like spaces,
    # ignore numberings such as "1." or "(1)"
    import re as _re
    eingabe = [w for w in _re.split(r"[\s,;]+", roh)
               if w and not _re.fullmatch(r"\(?\d+[.)]?", w)]
    soll = [words_list[i] for i in idx]
    if eingabe == soll:
        print(C.GRN + t("   ✔ Verifikation erfolgreich — Abschrift stimmt exakt ueberein.",
                        "   ✔ Verification successful — transcription matches exactly.") + C.RESET)
        return True
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
    return False


_WIPE_ARMED = {"on": False}

def _atexit_wipe():
    """audit F2-N1: last-resort wipe on abnormal exit while a seed may be
    on screen; disarmed after the regular cleanup has wiped."""
    if _WIPE_ARMED["on"]:
        _wipe_screen()

def _signal_wipe(signum, frame):
    if _WIPE_ARMED["on"]:
        _wipe_screen()
    sys.exit(130)

def _wipe_screen():
    """Really erase screen + scrollback — in the ONLY safe order: home,
    then 2J (some terminals push the content into the scrollback at this
    point), then ONLY THEN 3J (purges the scrollback including what was
    just pushed). Afterwards 'clear' as a terminfo fallback and the
    sequence once more — belt and braces."""
    # audit-46 CODE-7/SEC-9: Docstring an den Funktionsanfang (war toter Code)
    if not sys.stdout.isatty():
        # audit F3-M11: ANSI erase sequences in a pipe/log are just noise
        return
    if os.environ.get("TERM", "") == "dumb":
        # audit-46 SEC-9: auf einem dumb-Terminal sind die Sequenzen
        # wirkungslos — laut warnen statt still zu versagen
        print(C.YEL + C.BOLD + t(
            " ⚠ TERM=dumb: Scrollback-Loeschung nicht garantierbar — Terminalfenster "
            "manuell schliessen!",
            " ⚠ TERM=dumb: scrollback erase not guaranteed — close the terminal "
            "window manually!") + C.RESET)
    seq = "\033[H\033[2J\033[3J"
    sys.stdout.write(seq)
    sys.stdout.flush()
    try:
        import subprocess as _sp                     # audit F3-N5: no PATH shell
        _clear = shutil.which("clear")
        if _clear:
            _sp.run([_clear], timeout=5)
    except Exception:
        pass
    sys.stdout.write(seq)
    sys.stdout.flush()

def show_donation():
    """Optional donation notice — appears only AFTER the screen erase,
    when no seed is visible any more. QR via qrencode (if installed),
    otherwise the address as text. Best-effort, never intrusive."""
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
    """After the seed display: erase the screen including scrollback and,
    on request, empty the bash history files. The script itself never
    writes a file at any point."""
    hr()
    print(C.BOLD + t(" Aufraeumen (keine Spuren)", " Cleanup (no traces)") + C.RESET)
    print(C.DIM + t("   Hinweis: Alle Entropie- und Seed-Daten wurden ausschliesslich im RAM verarbeitet;", "   Note: all entropy and seed data was processed exclusively in RAM;") + C.RESET)
    print(C.DIM + t("   dieses Skript hat kein GEHEIMNIS auf einen Datentraeger geschrieben.",
                    "   this script has not written any SECRET to storage.") + C.RESET)
    if args.yes:
        # audit-46 SEC-7: die Loeschbarkeit haengt von STDOUT ab (ANSI-Wipe),
        # nicht von stdin — bisher wurde bei stdout=TTY + stdin=Pipe nur eine
        # irrefuehrende Warnung gedruckt und der atexit-Wipe wischte sofort
        # beim Exit, ohne Zeit zum Notieren.
        if sys.stdout.isatty():
            if sys.stdin.isatty():
                # audit M2: human at the terminal -> same erase dialog as in interactive mode
                try:
                    input(C.BOLD + t("   [--yes] Seed notiert? [Enter] loescht Bildschirm + Scrollback … ",
                                     "   [--yes] Seed written down? [Enter] erases screen + scrollback … ") + C.RESET)
                except (EOFError, KeyboardInterrupt):
                    pass
            else:
                print(C.YEL + t("   (--yes: stdin ist keine TTY — loesche in 60 s automatisch; "
                                "Strg+C bricht ab, der Seed bleibt dann sichtbar.)",
                                "   (--yes: stdin is no TTY — auto-erasing in 60 s; "
                                "Ctrl+C aborts, the seed then stays visible.)") + C.RESET)
                try:
                    time.sleep(60)
                except KeyboardInterrupt:
                    # audit-47 NEU-1: ohne Entschaerfung haette der atexit-Wipe
                    # den Seed beim Programmende doch noch geloescht — die
                    # Zusage "der Seed bleibt dann sichtbar" waere falsch.
                    _WIPE_ARMED["on"] = False
                    try:
                        atexit.unregister(_atexit_wipe)
                    except Exception:
                        pass
                    print(C.YEL + t("\n   (Abbruch: Bildschirm wird NICHT geloescht — Seed bleibt "
                                    "sichtbar. Terminal nach dem Notieren selbst schliessen!)",
                                    "\n   (aborted: screen will NOT be erased — the seed stays "
                                    "visible. Close the terminal yourself once written down!)") + C.RESET)
                    return
            _WIPE_ARMED["on"] = False
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
    # erase the screen + the terminal's scrollback buffer
    _WIPE_ARMED["on"] = False   # audit F2-N1: regular wipe follows now
    _wipe_screen()
    print(C.GRN + t(" \u2714 Bildschirmanzeige und Scrollback geloescht.", " \u2714 Screen display and scrollback erased.") + C.RESET)
    try:
        antwort = input(t("   Shell-Verlaufsdateien (bash/zsh/fish) zusaetzlich leeren? [ja/nein]: ", "   Also clear shell history files (bash/zsh/fish)? [yes/no]: ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        antwort = "nein"
    if antwort in ("ja", "yes", "y"):
        kandidaten = ["/root/.bash_history", "/root/.zsh_history",
                      "/root/.local/share/fish/fish_history"]   # audit N7
        su = os.environ.get("SUDO_USER")
        if su:
            try:
                import pwd
                heim = pwd.getpwnam(su).pw_dir   # audit F3-M8: no path traversal via SUDO_USER
            except (KeyError, ImportError):
                heim = None
            if heim:
                kandidaten += [os.path.join(heim, ".bash_history"),
                               os.path.join(heim, ".zsh_history"),
                               os.path.join(heim, ".local/share/fish/fish_history")]
        for p in kandidaten:
            try:
                if os.path.exists(p):
                    st_p = os.lstat(p)               # audit F3-M8: no symlink following
                    import stat as _stat
                    if not _stat.S_ISREG(st_p.st_mode):
                        raise OSError("kein regulaeres File / not a regular file")
                    fd = os.open(p, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
                    os.close(fd)
                    print(C.GRN + t(f"   \u2714 geleert: {p}", f"   \u2714 cleared: {p}") + C.RESET)
            except Exception as e:
                print(C.YEL + f"   \u26a0 {p}: {e}" + C.RESET)
        print(C.DIM + t("   Hinweis: Leeren ersetzt kein sicheres Loeschen — alte Bloecke koennen auf", "   Note: truncation is not secure erasure — old blocks may remain forensically") + C.RESET)
        print(C.DIM + t("   SD/Flash forensisch lesbar bleiben (Wear-Leveling), analog zum Swap-Vorbehalt.", "   readable on SD/flash (wear leveling), analogous to the swap caveat.") + C.RESET)
        print(C.DIM + t("   Die laufende Shell haelt ihren Verlauf im RAM — dieses Terminalfenster", "   The running shell keeps its history in RAM — CLOSE this terminal window") + C.RESET)
        print(C.DIM + t("   jetzt SCHLIESSEN (oder 'history -c' ausfuehren), damit nichts zurueckgeschrieben wird.", "   now (or run 'history -c') so nothing gets written back.") + C.RESET)
    else:
        print(C.DIM + t("   Verlaufsdateien unveraendert. Empfehlung: Terminalfenster schliessen.", "   History files unchanged. Recommendation: close the terminal window.") + C.RESET)

# ----------------------------------------------------------------------------
# Low count-rate dialog: poti adjustment hint (repeat / continue)
# ----------------------------------------------------------------------------
def _low_cpm_dialog(cpm: float, interactive: bool) -> bool:
    """Shown when the health check measures fewer than CPM_WARN_MIN counts
    per minute. Returns True = repeat the health check, False = continue."""
    print()
    print(C.YEL + C.BOLD + t(
        " ⚠ Achtung! Beim HealthCheck wurde eine sehr geringe Counts-per-Minute-",
        " ⚠ Attention! The health check measured a very low counts-per-minute") + C.RESET)
    print(C.YEL + C.BOLD + t(
        f"   (CPM-)Zahl festgestellt: {cpm:.1f} CPM.",
        f"   (CPM) figure: {cpm:.1f} CPM.") + C.RESET)
    print(C.YEL + t(
        "   MOEGLICHERWEISE ist das Potentiometer auf der CAJOE-Platine nicht",
        "   POSSIBLY the potentiometer on the CAJOE board is not adjusted") + C.RESET)
    print(C.YEL + t(
        "   richtig eingestellt! (Blaues Rechteck mit kleiner Schraube oben.)",
        "   correctly! (Blue rectangle with a small screw on top.)") + C.RESET)
    print(C.YEL + t(
        "   Sie koennen den USB-Anschluss des CAJOE jetzt trennen und das Poti",
        "   You can disconnect the CAJOE's USB now and turn the potentiometer") + C.RESET)
    print(C.YEL + t(
        "   2-4 Umdrehungen GEGEN den Uhrzeigersinn drehen, um die Spannung und",
        "   2-4 turns COUNTER-clockwise to raise the voltage and increase the") + C.RESET)
    print(C.YEL + t(
        "   damit die Detektor-Sensibilitaet zu erhoehen. Nach dem Wieder-",
        "   detector sensitivity. After powering it back on there must be NO") + C.RESET)
    print(C.YEL + t(
        "   einschalten darf KEIN fiependes Geraeusch auftreten — sonst sofort",
        "   whining/squealing noise — otherwise switch it off immediately and") + C.RESET)
    print(C.YEL + t(
        "   wieder ausschalten und zurueckdrehen.",
        "   turn the screw back.") + C.RESET)
    print(C.RED + C.BOLD + t(
        "   ⚠ ACHTUNG! Auf Teilen der Platine herrscht HOCHSPANNUNG — niemals im",
        "   ⚠ WARNING! Parts of the board carry HIGH VOLTAGE — never work on or") + C.RESET)
    print(C.RED + C.BOLD + t(
        "   eingeschalteten Zustand am Geraet arbeiten oder es beruehren:",
        "   touch the device while it is powered:") + C.RESET)
    print(C.RED + C.BOLD + t(
        "   Gefahr gefaehrlicher Stromschlaege!!!",
        "   danger of hazardous electric shock!!!") + C.RESET)
    if not interactive:
        print(C.DIM + t("   (--yes: keine Rueckfrage moeglich — es wird fortgefahren.)",
                        "   (--yes: no prompt possible — continuing.)") + C.RESET)
        return False
    while True:
        try:
            antwort = input(C.ORA + t(
                "   Moechten Sie Aenderungen vornehmen und den HealthCheck "
                "wiederholen? [wiederholen/fortfahren]: ",
                "   Do you want to make changes and repeat the health check? "
                "[repeat/continue]: ") + C.RESET + C.GRN).strip().lower()
            sys.stdout.write(C.RESET); sys.stdout.flush()
        except (EOFError, KeyboardInterrupt):
            sys.stdout.write(C.RESET)
            return False
        if antwort in ("wiederholen", "w", "repeat", "r"):
            return True
        if antwort in ("fortfahren", "f", "continue", "c"):
            return False
        print(C.YEL + t("   Bitte 'wiederholen' oder 'fortfahren' eingeben.",
                        "   Please enter 'repeat' or 'continue'.") + C.RESET)


# ----------------------------------------------------------------------------
# Hardware initialization test (health check before the run)
# ----------------------------------------------------------------------------
_HC_REPEAT = object()   # audit F2-N19: sentinel instead of recursion

def startup_healthcheck(mock: bool, light: bool = False, interactive: bool = True):
    """Loop wrapper around one health-check pass (see _healthcheck_once)."""
    while True:
        r = _startup_healthcheck_once(mock, light, interactive)
        if r is not _HC_REPEAT:
            return r


def _startup_healthcheck_once(mock: bool, light: bool = False, interactive: bool = True):
    """Every hardware source must deliver 10 distinct signals in a row;
    the data is displayed. Only then does the script continue."""
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
        # audit-47: Wenn der eingestellte Pull binnen PULL_PROBE_S nichts
        # sieht, die uebrigen Pull-Modi durchprobieren, statt bis zum
        # 4000-s-Timeout blind zu warten. Haeufigste Ursache: hochohmiger
        # Spannungsteiler als Pegelwandler, den der interne Pull-up
        # uebersteuert (oder umgekehrt eine schwimmende Leitung ohne Pull).
        PULL_PROBE_S = DECAY_PULL_PROBE_S
        _pull_kandidaten = [GPIO_PULL_MODE] + [m for m in ("up", "none", "down")
                                               if m != GPIO_PULL_MODE]
        _pull_aktiv = GPIO_PULL_MODE
        def _cb(chip, gpio, level, ts_ns):
            if ts_list and ts_ns - ts_list[-1] < DECAY_DEBOUNCE_NS:
                return
            ts_list.append(ts_ns)
        cb = None
        gezeigt = 0
        letzte_aktivitaet = time.monotonic()
        _probe_start = time.monotonic()
        _naechster_pull = 1
        try:
            cb = lgpio.callback(handle, GPIO_GEIGER, edge, _cb)   # audit N3
            while gezeigt < 10:
                time.sleep(0.1)
                while gezeigt < min(len(ts_list), 10):
                    ts_val = ts_list[gezeigt]
                    d = (ts_val - ts_list[gezeigt-1]) / 1e9 if gezeigt else 0.0
                    print(f"   Signal {gezeigt+1:2d}/10: t = {ts_val} ns   Δ = {d:7.3f} s")
                    gezeigt += 1
                    letzte_aktivitaet = time.monotonic()
                # audit-46 CODE-5: an das 0.3-CPM-Fensterende angleichen
                # (mittleres Intervall 200 s; Faktor 20 wie DECAY_TIMEOUT_EFF
                # -> 4000 s; die festen 1440 s brachen ~0.7% ehrlicher
                # Healthchecks am Fensterende ab)
                _hc_timeout = max(DECAY_TIMEOUT_S * 4, int(20 * 60.0 / 0.3))
                # audit-47: Pull-Fallback, solange noch kein einziger Puls kam
                if (not ts_list and _naechster_pull < len(_pull_kandidaten)
                        and time.monotonic() - _probe_start > PULL_PROBE_S):
                    neu = _pull_kandidaten[_naechster_pull]
                    _naechster_pull += 1
                    print(C.YEL + t(f"\n   ⚠ {PULL_PROBE_S}s kein Puls mit Pull={_pull_aktiv} — "
                                    f"probiere Pull={neu} …",
                                    f"\n   ⚠ {PULL_PROBE_S}s without a pulse at pull={_pull_aktiv} — "
                                    f"trying pull={neu} …") + C.RESET)
                    try:
                        if cb is not None:
                            cb.cancel()
                    except Exception:
                        pass
                    try:
                        lgpio.gpiochip_close(handle)
                    except Exception:
                        pass
                    handle, edge = find_rp1_chip(lgpio, GPIO_GEIGER, pull_modus=neu)
                    if handle is None:
                        fail_abort("Radiozerfall (Initialisierungstest)",
                                   f"GPIO{GPIO_GEIGER} konnte nicht belegt werden.")
                    cb = lgpio.callback(handle, GPIO_GEIGER, edge, _cb)
                    _pull_aktiv = neu
                    # audit-47: Fund uebernehmen, damit collect_decay spaeter
                    # denselben Pull verwendet und nicht wieder blind ist.
                    globals()["GPIO_PULL_MODE"] = neu
                    _probe_start = time.monotonic()
                    letzte_aktivitaet = time.monotonic()
                    continue
                if time.monotonic() - letzte_aktivitaet > _hc_timeout:
                    fail_abort("Radiozerfall (Initialisierungstest)",
                               f"{_hc_timeout}s ohne Zerfallsereignis.")
        except KeyboardInterrupt:
            print(C.RED + t("\n Abbruch durch Benutzer (Strg+C).",
                            "\n aborted by user (Ctrl+C).") + C.RESET)
            sys.exit(130)   # audit F3-N8
        except Exception as e:
            # audit-46 CODE-1: kontrollierter Abbruch statt Traceback/Exit 1
            fail_abort("Radiozerfall (Initialisierungstest)",
                       t(f"GPIO-Fehler: {e}", f"GPIO error: {e}"))
        finally:
            # audit-46 CODE-2: gesplittet wie in collect_decay (F3-M9) — ein
            # fehlschlagendes cb.cancel() darf das gpiochip_close nicht fressen
            try:
                if cb is not None:
                    cb.cancel()
            except Exception:
                pass
            try:
                lgpio.gpiochip_close(handle)
            except Exception:
                pass
    if sorted(ts_list) != ts_list or len(set(ts_list)) != len(ts_list):
        fail_abort("Radiozerfall (Initialisierungstest)",
                   "Zeitstempel nicht streng aufsteigend — Messung unplausibel.")
    deltas = [round((b - a) / 1e9, 3) for a, b in zip(ts_list, ts_list[1:])]   # audit F2-N15: 0.01 s buckets collided from ~2000 CPM
    if len(set(deltas)) < 3:
        fail_abort("Radiozerfall (Initialisierungstest)",
                   t("Pulsintervalle nahezu konstant — Stoerquelle statt Zerfall?",
                     "pulse intervals nearly constant — interference instead of decay?"))
    span_s = (ts_list[-1] - ts_list[0]) / 1e9
    cpm_mess = (len(ts_list) - 1) / span_s * 60 if span_s > 0 else 0.0
    print(C.DIM + t(f"   Gemessene Zaehlrate: {cpm_mess:.1f} CPM",
                    f"   Measured count rate: {cpm_mess:.1f} CPM") + C.RESET)
    if not mock and cpm_mess < CPM_WARN_MIN:
        if _low_cpm_dialog(cpm_mess, interactive):
            print(C.DIM + t("\n   HealthCheck wird wiederholt …",
                            "\n   Repeating the health check …") + C.RESET)
            return _HC_REPEAT
    print(C.GRN + t("   ✔ 10/10 Ereignisse, Intervalle unregelmaessig (zerfallstypisch)", "   ✔ 10/10 events, irregular intervals (decay-typical)") + C.RESET)

    # ---- Check 3/3: MLX90640 IR camera -------------------------------------
    print(C.BOLD + t("\n [Check 3/3] MLX90640 IR-Kamera",
                     "\n [Check 3/3] MLX90640 IR camera") + C.RESET)
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
                       t("Python-Modul 'smbus2' fehlt: sudo apt install python3-smbus2",
                         "Python module 'smbus2' missing: sudo apt install python3-smbus2"))
        try:
            bus = SMBus(MLX_I2C_BUS)
        except OSError as e:
            fail_abort("MLX90640 (Initialisierungstest)",
                       t(f"I2C-Bus nicht verfuegbar: {e}", f"I2C bus not available: {e}"))
        try:
            _mlx_ensure_2hz(bus)   # audit-46 HW-1: Rate-Fix auch im Healthcheck
            for i in range(10):
                t0 = time.monotonic()
                while True:
                    st = _mlx_read_words(bus, 0x8000, 1)
                    if st[1] & 0x08:
                        break
                    if time.monotonic() - t0 > 5:
                        fail_abort("MLX90640 (Initialisierungstest)",
                                   t("Timeout beim Warten auf neues Frame (Adresse 0x33?).",
                                     "timeout waiting for a new frame (address 0x33?)."))
                    time.sleep(0.02)
                # audit F3-M6: same handshake as collect_camera (F2-N12):
                # clear BEFORE the read, re-check, retry on tearing
                for _versuch in range(5):
                    wmsg = i2c_msg.write(MLX_I2C_ADDR, [0x80, 0x00, 0x00, 0x30])
                    bus.i2c_rdwr(wmsg)
                    frame = _mlx_read_words(bus, 0x0400, 832)
                    st2 = _mlx_read_words(bus, 0x8000, 1)
                    if not (st2[1] & 0x08):
                        break
                else:
                    fail_abort("MLX90640 (Initialisierungstest)",
                               t("5x zerrissene Frames in Folge — Refresh-Rate pruefen (0x800D).",
                                 "5 torn frames in a row — check the refresh rate (0x800D)."))
                if len(set(frame)) < 8:
                    fail_abort("MLX90640 (Initialisierungstest)",
                               t("Frame mit nahezu konstantem Inhalt — Sensor defekt?",
                                 "frame with nearly constant content — sensor defective?"))
                h = hashlib.sha256(frame).hexdigest()
                hashes.append(h)
                print(f"   Frame {i+1:2d}/10: SHA256 {h[:16]}…  (" + t("erste Rohworte", "first raw words") + f": {bytes(frame[:6]).hex()})")
        except OSError as e:
            fail_abort("MLX90640 (Initialisierungstest)",
                   t(f"I2C-Fehler: {e}", f"I2C error: {e}"))
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
    """Question in orange, user input in green (explanatory text stays normal)."""
    while True:
        try:
            s = input(C.ORA + f"   {prompt} [{default}]: " + C.RESET + C.GRN).strip()
        except EOFError:
            sys.stdout.write(C.RESET)
            return default          # audit M7: EOF -> safe default
        except KeyboardInterrupt:
            sys.stdout.write(C.RESET + "\n")
            print(C.RED + t(" Abbruch durch Benutzer (Strg+C) — kein Seed erzeugt.",
                            " aborted by user (Ctrl+C) — no seed generated.") + C.RESET)
            sys.exit(130)           # audit M7: controlled instead of traceback
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
    """Minimum number of decay events so that the conservatively credited
    2 bits/event alone already cover the target entropy."""
    return math.ceil(target_bits / DECAY_BITS_PER_EVENT)

def _validate_yes_config(args):
    """audit-46 CODE-4: im --yes-Modus die CLI-Mindestwerte VOR dem
    Hardware-Healthcheck pruefen (real: minutenlange Wartezeit auf
    Zerfallsereignisse/Kamera, bevor ein sofort erkennbarer CLI-Fehler
    gemeldet wurde). configure() behaelt dieselben Checks als zweite Linie."""
    if not args.yes:
        return
    dice_min = DICE_MIN_ROLLS_LIGHT if args.light else DICE_MIN_ROLLS
    if args.dice < dice_min:
        fail_abort("Konfiguration",
                   t(f"--dice {args.dice} unterschreitet das Minimum von {dice_min} Wuerfelwuerfen",
                     f"--dice {args.dice} is below the minimum of {dice_min} dice rolls")
                   + (t(" (LIGHT-Modus).", " (LIGHT mode).") if args.light else "."))
    if not args.light:
        target = 256 if args.words == 24 else 128
        mind = min_decay_events(target)
        if args.decay < mind:
            fail_abort("Konfiguration",
                       f"--decay {args.decay} unterschreitet das Minimum von {mind} "
                       f"Ereignissen ({mind} x {DECAY_BITS_PER_EVENT} Bit = {target} Bit).")
        if args.frames < CAM_MIN_FRAMES:
            fail_abort("Konfiguration",
                       t(f"--frames {args.frames} unterschreitet das Minimum von "
                         f"{CAM_MIN_FRAMES} Kamera-Frames.",
                         f"--frames {args.frames} is below the minimum of "
                         f"{CAM_MIN_FRAMES} camera frames."))

def configure(args, cpm_mess=None):
    cpm = cpm_mess if cpm_mess and cpm_mess > 0 else 9.0
    if args.yes:
        target = 256 if args.words == 24 else 128
        dice_min = DICE_MIN_ROLLS_LIGHT if args.light else DICE_MIN_ROLLS
        if args.dice < dice_min:
            fail_abort("Konfiguration",
                       t(f"--dice {args.dice} unterschreitet das Minimum von {dice_min} Wuerfelwuerfen",
                         f"--dice {args.dice} is below the minimum of {dice_min} dice rolls")
                       + (t(" (LIGHT-Modus).", " (LIGHT mode).") if args.light else "."))
        if args.light:
            # audit M6: decay/frames are unused in LIGHT mode — their
            # minimum checks must not fire here
            return args.words, 0, 0, args.dice, args.transparenz
        mind = min_decay_events(target)
        if args.decay < mind:
            fail_abort("Konfiguration",
                       f"--decay {args.decay} unterschreitet das Minimum von {mind} "
                       f"Ereignissen ({mind} x {DECAY_BITS_PER_EVENT} Bit = {target} Bit).")
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
    rec_dice = max(DICE_MIN_ROLLS, math.ceil(target / DICE_BITS_PER_ROLL))   # audit F2-N17
    print(C.DIM + t(f"   Ziel-Entropie: {target} Bit", f"   Target entropy: {target} bits") + C.RESET)
    print(C.DIM + t(f"   Betriebsart: {'LIGHT (HWRNG + Wuerfel)' if args.light else 'FULL (4 Quellen)'}",
                    f"   Operating mode: {'LIGHT (HWRNG + dice)' if args.light else 'FULL (4 sources)'}") + C.RESET)
    if args.light:
        print(C.DIM + t("   Wuerfel: 100 = volle 256-Bit-Unabhaengigkeit; mehr = Marge gegen unperfekte Wuerfel",
                        "   Dice: 100 = full 256-bit independence; more = margin against imperfect dice") + C.RESET)
        dice = ask_int(t(f"Wuerfelwuerfe (Minimum {DICE_MIN_ROLLS_LIGHT})",
                         f"Dice rolls (minimum {DICE_MIN_ROLLS_LIGHT})"),
                       max(args.dice, DICE_MIN_ROLLS_LIGHT), DICE_MIN_ROLLS_LIGHT, 1000)
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
    ap.add_argument("--dice",   type=int, default=DICE_MIN_ROLLS_LIGHT)   # audit F3-H3: default must satisfy the strictest mode
    ap.add_argument("--gpio-pull", choices=("up", "none", "down"), default="up",
                    help="audit-47: Pull-Widerstand am CAJOE-Eingang GPIO17. "
                         "'up' = Standard (Open-Collector). 'none'/'down', wenn "
                         "ein hochohmiger Spannungsteiler als Pegelwandler "
                         "verwendet wird und keine Ereignisse ankommen. Der "
                         "Healthcheck probiert die uebrigen Modi ohnehin "
                         "automatisch durch.")
    args = ap.parse_args()
    # audit N1: core dumps could write entropy/seed to the SD card
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    # hard range limits for all paths (audit M5)
    if args.words not in (12, 24):
        ap.error("--words muss 12 oder 24 sein / must be 12 or 24")
    if not (1 <= args.decay <= 100000):
        ap.error("--decay ausserhalb 1..100000")
    if not (CAM_MIN_FRAMES <= args.frames <= 1000):
        ap.error(f"--frames ausserhalb {CAM_MIN_FRAMES}..1000")
    if not (1 <= args.dice <= 1000):
        ap.error("--dice ausserhalb 1..1000")

    global LANG
    LANG = args.lang          # audit F3-N10: early, so even the very first
                              # guards speak the chosen language (interactive
                              # choice below may override for non---yes runs)
    global GPIO_PULL_MODE     # audit-47: CLI-Wahl des Pull-Widerstands
    GPIO_PULL_MODE = args.gpio_pull
    # audit F2-N11: a direct root start (without sudo's env_reset) could
    # carry PYTHONINSPECT (post-main REPL with seed globals) or a poisoned
    # PYTHONSTARTUP. Scrub early; refuse interactive interpreter mode.
    for _var in ("PYTHONINSPECT", "PYTHONSTARTUP"):
        os.environ.pop(_var, None)
    if sys.flags.interactive:
        # audit F3-N2: sys.exit is swallowed by -i (the REPL still opens,
        # exit code 0) — terminate the interpreter hard instead
        print(C.RED + C.BOLD + t(
            " ✘ Interaktiver Interpreter-Modus (-i/PYTHONINSPECT) ist nicht zulaessig.",
            " ✘ interactive interpreter mode (-i/PYTHONINSPECT) is not permitted.") + C.RESET)
        os._exit(2)

    if args.selftest:
        selftest()
        return

    # audit-47 NEU-2: die --yes-Mindestwerte VOR jedem systemveraendernden
    # Schritt pruefen. Bisher lief die Pruefung zwar vor dem Healthcheck
    # (audit-46 CODE-4), aber erst NACH disable_wifi / enforce_permanent_
    # radio_off (persistenter config.txt-Eintrag!) / check_swap — ein
    # trivialer CLI-Fehler hinterliess also bereits dauerhafte System-
    # aenderungen. LANG ist hier bereits gesetzt, fail_abort spricht also
    # die richtige Sprache. Der Aufruf vor dem Healthcheck und die Kopie in
    # configure() bleiben als zweite bzw. dritte Linie bestehen.
    _validate_yes_config(args)

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
        print(t("   [1] LIGHT-MODUS — HWRNG + Wuerfel (kein Geigerzaehler, keine Kamera)",
                "   [1] LIGHT MODE  — HWRNG + dice (no Geiger counter, no camera)"))
        print(t("   [2] FULL-MODUS  — alle 4 Quellen inkl. Quanten-Zerfall (Referenz: Pi 5)",
                "   [2] FULL MODE   — all 4 sources incl. quantum decay (reference: Pi 5)"))
        args.light = ask_int(t("Betriebsart waehlen", "Select operating mode"),
                             1 if args.light else 2, 1, 2) == 1
        if args.light:
            print(C.DIM + t(f"   LIGHT: Die Sicherheitslast traegt der HMAC-Kombinierer — Minimum {DICE_MIN_ROLLS_LIGHT} Wuerfe.",
                            f"   LIGHT: the HMAC combiner carries the security — minimum {DICE_MIN_ROLLS_LIGHT} rolls.") + C.RESET)

    banner(args.light)
    time.sleep(3)       # Logo 3 s wirken lassen, bevor weiterer Output folgt
    security_briefing(args)
    selftest()          # self-test runs BEFORE every real generation
    hr()
    require_root(args)
    check_remote_session(args)
    require_tty_stdout(args)
    disable_wifi(args)
    enforce_permanent_radio_off(args)
    require_ethernet_unplugged(args)
    offer_ethernet_off(args)
    harden_process_memory(args)   # audit-47: mlockall + PR_SET_DUMPABLE
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

    if args.yes:
        _validate_yes_config(args)   # audit-46 CODE-4: fail fast vor dem Healthcheck
    cpm_mess = startup_healthcheck(args.mock, args.light, interactive=not args.yes)
    if cpm_mess and cpm_mess > 0:
        global DECAY_TIMEOUT_EFF     # audit F2-M4: ~10 mean intervals, never below 360 s
        DECAY_TIMEOUT_EFF = max(DECAY_TIMEOUT_S, int(20 * 60.0 / cpm_mess))   # audit F3-M3: factor 20 vs estimator scatter

    n_words, n_decay, n_frames, n_dice, transparent = configure(args, cpm_mess)
    if transparent:
        print(C.CYA + C.BOLD + t(" ► TRANSPARENZ-MODUS AKTIV", " ► TRANSPARENCY MODE ACTIVE") + C.RESET)
    target_bits = 256 if n_words == 24 else 128
    n_bytes = target_bits // 8

    hr()
    print(C.BOLD + t(" Ablaufplan (feste Reihenfolge)", " Process plan (fixed order)") + C.RESET)
    status_line(1, 4, "BCM2712 HWRNG",        "wait", t(f"{HWRNG_SAMPLES} Proben x 512 Bit", f"{HWRNG_SAMPLES} samples x 512 bits"))
    if not args.light:   # audit F2-N18: LIGHT showed "0 events/0 frames" phases
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
    entropy, idx, trans_zeilen = validated_derive(hw, dec, cam, dice, n_bytes,
                                                  transparent, args.light, words_list,
                                                  mock=args.mock)

    dur = (time.monotonic() - t0) / 60
    hr("━")
    final_offline_check(args)
    # audit F3-M1: the wordlist RAM re-check must run BEFORE any secret
    # transparency line hits the screen — "only on a match is anything
    # shown" has to include these lines. (Repeated cheaply below right at
    # the word output as before.)
    if words_list:
        try:
            _wordlist_recheck(words_list)
        except DualComputationError as ex:
            _dual_abort(str(ex))
    # audit F2-N1: from the moment the seed becomes visible, an abnormal
    # termination (SIGTERM/SIGHUP, terminal crash) must still wipe the
    # screen. Armed here, disarmed by secure_cleanup after its own wipe.
    _WIPE_ARMED["on"] = True
    atexit.register(_atexit_wipe)
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):   # audit F3-N1
        try:
            signal.signal(signum, _signal_wipe)
        except (OSError, ValueError):
            pass
    for _z in _DICE_TRANS + trans_zeilen:   # audits M1 + F2-N2: secrets AFTER the check
        print(_z)
    _DICE_TRANS.clear()
    modus = "LIGHT" if args.light else "FULL"
    print(C.GRN + C.BOLD + t(f" ✔ SEED ERZEUGT  ({n_words} Woerter, {target_bits} Bit, {modus}-Modus, Dauer {dur:.1f} min)", f" ✔ SEED GENERATED  ({n_words} words, {target_bits} bits, {modus} mode, duration {dur:.1f} min)") + C.RESET)
    play_success_jingle()
    hr("━")
    # Wordlist re-verification IMMEDIATELY before output (audit v1.1):
    # the roundtrip alone is blind to a list corrupted in RAM.
    if words_list:
        try:
            _wordlist_recheck(words_list)
        except DualComputationError as ex:
            _dual_abort(str(ex))
        print(C.GRN + t("  ✔ Doppelberechnung konsistent, BIP39-Roundtrip OK, Wortliste re-verifiziert.",
                        "  ✔ Dual computation consistent, BIP39 roundtrip OK, wordlist re-verified.") + C.RESET)
    else:
        print(C.GRN + t("  ✔ Doppelberechnung konsistent, BIP39-Roundtrip OK (keine Wortliste geladen).",
                        "  ✔ Dual computation consistent, BIP39 roundtrip OK (no wordlist loaded).") + C.RESET)
    if words_list and not args.mock:
        for i in range(0, len(idx), 4):
            row = "   ".join(f"{C.DIM}{j+1:2d}.{C.RESET} {C.BOLD}{words_list[idx[j]]:<10}{C.RESET}"
                             for j in range(i, min(i + 4, len(idx))))
            print("  " + row)
    else:
        if args.mock:
            # audit H3: the index->word table is public, so plain indices ARE
            # a usable seed. Mask them with fresh randomness (never shown):
            # the printed numbers carry zero information about the derived
            # values and are (except with prob. 2^-cs) no valid BIP39 phrase.
            maske = [int.from_bytes(os.urandom(2), "big") & 0x7FF for _ in idx]
            gezeigt = [i ^ m for i, m in zip(idx, maske)]
            # audit-46 SEC-6: die XOR-Maske ist uniform verteilt — bei 12
            # Woertern war ~jede 16. gezeigte Folge eine formal GUELTIGE
            # BIP39-Phrase ("absichtlich unbrauchbar" war zu stark).
            # Pruefsumme jetzt deterministisch VERDERBEN: die gezeigte Folge
            # ist garantiert keine gueltige Phrase.
            def _phrase_gueltig(indices):
                n = len(indices)
                cs_bits = (11 * n) // 33
                ent_bits = 11 * n - cs_bits
                num = 0
                for _i in indices:
                    num = (num << 11) | _i
                ent = (num >> cs_bits).to_bytes(ent_bits // 8, "big")
                soll = hashlib.sha256(ent).digest()[0] >> (8 - cs_bits)
                return (num & ((1 << cs_bits) - 1)) == soll
            _k = 1
            while _phrase_gueltig(gezeigt):
                # Pruefsummen-Bits des letzten Index variieren, bis die
                # Folge nachweislich ungueltig ist
                gezeigt[-1] = (gezeigt[-1] + _k) & 0x7FF
                _k += 1
            print(C.YEL + t("  MOCK-MODUS: zufaellig MASKIERTE Indizes — absichtlich unbrauchbar, KEINE gueltige Phrase:",
                            "  MOCK MODE: randomly MASKED indices — deliberately unusable, NO valid phrase:") + C.RESET)
            print("  " + " ".join(str(i) for i in gezeigt))
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
    try:
        main()
    except KeyboardInterrupt:
        # audit F2-N3: controlled abort instead of a raw traceback (thermal
        # burst, camera wait and health checks had no local handler)
        if _WIPE_ARMED["on"]:
            _wipe_screen()
        print(C.RED + t("\n Abbruch durch Benutzer (Strg+C) — kein Seed erzeugt bzw. Anzeige geloescht.",
                        "\n aborted by user (Ctrl+C) — no seed generated / display wiped.") + C.RESET)
        sys.exit(130)
