#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Quantum Seed Generator Project
# Lizenz: MIT License — Volltext in der Datei LICENSE des Repositories.
# License: MIT License — full text in the LICENSE file of the repository.
"""
install_seedgen.py — Richtet einen frischen Raspberry Pi (OS bookworm, Pi 5)
komplett fuer den QUANTUM SEED GENERATOR ein.

Erledigt:
  1. Systempakete:  python3-lgpio, python3-smbus2, i2c-tools, rfkill, alsa-utils
  2. I2C-Schnittstelle aktivieren (fuer die MLX90640)
  3. GPIO17 dauerhaft biasfrei konfigurieren (gpio=17=ip,pn in config.txt)
     -> DER Fix fuer die CAJOE-Signalerkennung: Pull-up/-down wuergten den
        hochohmigen Lautsprecher-Abgriff (J1 + 10k) ab. 'ip,pn' = Input,
        Pull None — ab Boot, unabhaengig vom Skript.
  4. BIP39-Wortliste english.txt laden und per SHA-256 verifizieren
  5. Umgebung pruefen: /dev/hwrng, I2C-Bus/Kamera (0x33), rfkill
  6. Falls btc_seedgen.py daneben liegt: Syntax + Selbsttest ausfuehren

Aufruf:   sudo python3 install_seedgen.py
Danach:   einmal neu starten (I2C + GPIO-Konfiguration werden beim Boot aktiv),
          dann  sudo python3 btc_seedgen.py
"""
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request

GPIO_GEIGER     = 17
WORDLIST_URL    = ("https://raw.githubusercontent.com/bitcoin/bips/"
                   "master/bip-0039/english.txt")
WORDLIST_SHA256 = ("2f5eed53a4727b4bf8880d8f3f199efc"
                   "90e58503646d9ff8eff3a2ed3b24dbda")
APT_PAKETE      = ["python3-lgpio", "python3-smbus2", "i2c-tools",
                   "rfkill", "alsa-utils", "qrencode"]

GRN, RED, YEL, BOLD, DIM, RST = ("\033[32m", "\033[31m", "\033[33m",
                                 "\033[1m", "\033[2m", "\033[0m")
fehler = []

CYA = "\033[38;5;45m"
ORA = "\033[38;5;208m"

def print_pinout():
    """Komplettes 40-Pin-Schema mit Orientierung + Verkabelung beider Sensoren."""
    K, C, P, G, D, B, R_ = CYA, ORA, RED, GRN, DIM, BOLD, RST
    print(B + "\n ANSCHLUSSPLAN — Raspberry Pi 5, 40-Pin-Header (Draufsicht)" + R_)
    print(D + " Orientierung: Platine mit USB/Ethernet nach UNTEN halten -> Header rechts," + R_)
    print(D + " Pin 1 ist dann OBEN LINKS am Header (Ecke naechst SD-Karte/USB-C)." + R_)
    print(D + " Legende: " + R_ + K + "MLX90640-Kamera" + R_ + "   " + C + "CAJOE-Geigerzaehler" + R_ + "   " + D + "grau = unbenutzt" + R_)
    Z = [
     (K+"Kamera VCC (gelb)  <--"+R_, K, "3V3",     " 1", " 2", "5V ",     C, C+"--> CAJOE 5V (P3, oder eig. USB-Netzteil)"+R_),
     (K+"Kamera SDA (violett)<--"+R_,K, "GPIO2 SDA"," 3", " 4", "5V ",     D, ""),
     (K+"Kamera SCL (gruen) <--"+R_, K, "GPIO3 SCL"," 5", " 6", "GND",     K, K+"--> Kamera GND (blau)"+R_),
     ("",                          D, "GPIO4    ", " 7", " 8", "GPIO14",   D, ""),
     (C+"CAJOE GND (schwarz)<--"+R_,C, "GND      ", " 9", "10", "GPIO15",  D, ""),
     (C+"CAJOE Signal: P3-VIN-Abgriff"+R_, C, "GPIO17  ","11", "12", "GPIO18", D, ""),
     (C+"  (weiss, 10k in Reihe)"+R_, C, "        ","  ", "  ", "",       D, None),
     ("",                          D, "GPIO27   ","13", "14", "GND",       D, ""),
     ("",                          D, "GPIO22   ","15", "16", "GPIO23",    D, ""),
     ("",                          D, "3V3      ","17", "18", "GPIO24",    D, ""),
     ("",                          D, "GPIO10   ","19", "20", "GND",       D, ""),
     ("",                          D, "GPIO9    ","21", "22", "GPIO25",    D, ""),
     ("",                          D, "GPIO11   ","23", "24", "GPIO8",     D, ""),
     ("",                          D, "GND      ","25", "26", "GPIO7",     D, ""),
     ("",                          D, "ID_SD    ","27", "28", "ID_SC",     D, ""),
     ("",                          D, "GPIO5    ","29", "30", "GND",       D, ""),
     ("",                          D, "GPIO6    ","31", "32", "GPIO12",    D, ""),
     ("",                          D, "GPIO13   ","33", "34", "GND",       D, ""),
     ("",                          D, "GPIO19   ","35", "36", "GPIO16",    D, ""),
     ("",                          D, "GPIO26   ","37", "38", "GPIO20",    D, ""),
     ("",                          D, "GND      ","39", "40", "GPIO21",    D, ""),
    ]
    print(D + " " + "─"*30 + "┬──────┬──────┬" + "─"*30 + R_)
    for links_txt, fl, lname, lpin, rpin, rname, fr, rechts_txt in Z:
        if rechts_txt is None:      # reine Kommentarzeile (CAJOE 10k)
            print(f" {links_txt:<52}")
            continue
        mark_l = "●" if lpin.strip() == "1" else "o"
        print(f" {links_txt:>42}  {fl}{lname:>9} ({lpin}){R_} {mark_l}|o "
              f"{fr}({rpin}) {rname:<9}{R_}  {rechts_txt}")
    print(D + " " + "─"*30 + "┴──────┴──────┴" + "─"*30 + R_)
    print(B + " CAJOE-Besonderheiten:" + R_)
    print("   • Signalabgriff an " + C + "P3-VIN" + R_ + ": weisses Kabel mit " +
          C + "10 kOhm IN REIHE" + R_ + " zu GPIO17 (Pin 11).")
    print("   • DER entscheidende Punkt ist die Software-Einstellung: GPIO17 muss")
    print("     " + C + "biasfrei" + R_ + " laufen (Pull None) — jeder interne Pull-up/-down")
    print("     wuergt den hochohmigen Abgriff ab. Dieses Skript verankert das")
    print("     dauerhaft (gpio=17=ip,pn in config.txt).")
    print(B + " Kamera-Besonderheiten:" + R_)
    print("   • " + K + "VCC an 3,3 V (Pin 1)" + R_ + " — NIEMALS an 5 V!  I2C-Adresse 0x33, Bus 1.")


def kopf(nr, txt):
    print(f"\n{BOLD}[{nr}/6] {txt}{RST}")

def ok(txt):
    print(f"{GRN}  ✔ {txt}{RST}")

def warn(txt):
    print(f"{YEL}  ⚠ {txt}{RST}")
    fehler.append(txt)

def run(cmd, timeout=600):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

def config_txt_pfad():
    for p in ("/boot/firmware/config.txt", "/boot/config.txt"):
        if os.path.exists(p):
            return p
    return None

def main():
    if "--pinout" in sys.argv:
        print_pinout()
        return
    print(BOLD + "QUANTUM SEED GENERATOR — Installationsskript" + RST)
    if os.geteuid() != 0:
        print(RED + "Bitte mit sudo starten:  sudo python3 install_seedgen.py" + RST)
        sys.exit(2)
    zielordner = os.path.dirname(os.path.abspath(__file__))

    # ---- 1) Systempakete -----------------------------------------------------
    kopf(1, "Systempakete installieren (apt)")
    r = run(["apt-get", "update"])
    if r.returncode != 0:
        warn("apt-get update fehlgeschlagen — Internet verbunden? "
             "(Fuer die Installation einmalig noetig, danach nie wieder.)")
    r = run(["apt-get", "install", "-y"] + APT_PAKETE)
    if r.returncode == 0:
        ok("Installiert: " + ", ".join(APT_PAKETE))
    else:
        warn("Paketinstallation fehlgeschlagen: " + r.stderr.strip()[:200])

    # ---- 2) I2C aktivieren ---------------------------------------------------
    kopf(2, "I2C-Schnittstelle aktivieren (MLX90640)")
    r = run(["raspi-config", "nonint", "do_i2c", "0"])
    if r.returncode == 0:
        ok("I2C aktiviert (raspi-config)")
    else:
        cfg = config_txt_pfad()
        if cfg:
            inhalt = open(cfg).read()
            if "dtparam=i2c_arm=on" not in inhalt:
                with open(cfg, "a") as f:
                    f.write("\ndtparam=i2c_arm=on\n")
            ok(f"I2C via {cfg} aktiviert")
        else:
            warn("I2C konnte nicht aktiviert werden (raspi-config/config.txt fehlen)")

    # ---- 3) GPIO17 biasfrei (der CAJOE-Fix) ----------------------------------
    kopf(3, f"GPIO{GPIO_GEIGER} dauerhaft biasfrei konfigurieren")
    print(DIM + "     Hintergrund: Der P3-VIN-Abgriff (mit 10k in Reihe) ist hochohmig —"
          "\n     jeder interne Pull-up/-down des Pi wuergt das Signal ab. 'ip,pn'"
          "\n     setzt den Pin ab Boot auf Input ohne Pull (DER Fix der Signalerkennung)." + RST)
    cfg = config_txt_pfad()
    if cfg:
        inhalt = open(cfg).read()
        zeile = f"gpio={GPIO_GEIGER}=ip,pn"
        if zeile in inhalt:
            ok(f"{zeile} bereits in {cfg}")
        else:
            with open(cfg, "a") as f:
                f.write(f"\n# SEEDGEN: Geigerzaehler-Eingang biasfrei (Signalerkennung)\n{zeile}\n")
            ok(f"{zeile} in {cfg} eingetragen (aktiv ab naechstem Boot)")
        # Zusaetzlich sofort setzen, falls pinctrl vorhanden (ohne Reboot nutzbar)
        if shutil.which("pinctrl"):
            run(["pinctrl", "set", str(GPIO_GEIGER), "ip", "pn"])
            ok(f"GPIO{GPIO_GEIGER} auch fuer diese Sitzung auf Input/Pull-None gesetzt")
    else:
        warn("config.txt nicht gefunden — gpio=17=ip,pn manuell eintragen")

    # ---- 4) BIP39-Wortliste --------------------------------------------------
    kopf(4, "BIP39-Wortliste english.txt laden und verifizieren")
    ziel = os.path.join(zielordner, "english.txt")
    daten = None
    if os.path.exists(ziel):
        daten = open(ziel, "rb").read()
        if hashlib.sha256(daten).hexdigest() == WORDLIST_SHA256:
            ok(f"Bereits vorhanden und verifiziert: {ziel}")
        else:
            warn(f"{ziel} vorhanden, aber SHA-256 FALSCH — wird neu geladen")
            daten = None
    if daten is None:
        try:
            daten = urllib.request.urlopen(WORDLIST_URL, timeout=30).read()
            if hashlib.sha256(daten).hexdigest() != WORDLIST_SHA256:
                warn("Download-SHA-256 stimmt NICHT — Datei NICHT gespeichert!")
            else:
                open(ziel, "wb").write(daten)
                ok(f"Geladen und verifiziert: {ziel} "
                   f"(SHA-256 {WORDLIST_SHA256[:16]}…)")
        except Exception as e:
            warn(f"Download fehlgeschlagen ({e}) — english.txt spaeter manuell "
                 "neben das Skript legen")

    # ---- 5) Umgebung pruefen -------------------------------------------------
    kopf(5, "Umgebung pruefen")
    if os.path.exists("/dev/hwrng"):
        ok("/dev/hwrng vorhanden (BCM2712 HWRNG)")
    else:
        warn("/dev/hwrng fehlt — Kernel/Firmware pruefen")
    try:
        import lgpio  # noqa: F401
        ok("Python-Modul lgpio importierbar")
    except ImportError:
        warn("lgpio nicht importierbar")
    try:
        import smbus2  # noqa: F401
        ok("Python-Modul smbus2 importierbar")
    except ImportError:
        warn("smbus2 nicht importierbar")
    r = run(["i2cdetect", "-y", "1"], timeout=30)
    if r.returncode == 0 and "33" in r.stdout:
        ok("MLX90640 auf I2C-Bus 1 gefunden (0x33)")
    else:
        warn("MLX90640 (0x33) nicht gefunden — Kamera verkabelt? "
             "(Nach Reboot erneut pruefen: i2cdetect -y 1)")
    if shutil.which("rfkill"):
        ok("rfkill vorhanden")
    else:
        warn("rfkill fehlt")

    # ---- 6) Seed-Generator testen (falls vorhanden) --------------------------
    kopf(6, "Seed-Generator pruefen")
    sg = os.path.join(zielordner, "btc_seedgen.py")
    if os.path.exists(sg):
        r = run([sys.executable, "-m", "py_compile", sg])
        if r.returncode == 0:
            ok("btc_seedgen.py: Syntax OK")
        else:
            warn("btc_seedgen.py: Syntaxfehler — Datei unvollstaendig uebertragen?")
        r = run([sys.executable, sg, "--selftest"], timeout=120)
        if r.returncode == 0:
            ok("btc_seedgen.py: Selbsttest bestanden (inkl. Wortlisten-Check)")
        else:
            warn("btc_seedgen.py: Selbsttest fehlgeschlagen")
    else:
        warn(f"btc_seedgen.py nicht in {zielordner} gefunden — Datei dorthin "
             "kopieren und Selbsttest manuell ausfuehren")

    # ---- Zusammenfassung -----------------------------------------------------
    print("\n" + BOLD + "─" * 62 + RST)
    if fehler:
        print(YEL + BOLD + f" Installation mit {len(fehler)} Hinweis(en) beendet:" + RST)
        for f_ in fehler:
            print(YEL + f"   • {f_}" + RST)
    else:
        print(GRN + BOLD + " ✔ Installation vollstaendig — keine Probleme." + RST)
    print_pinout()
    print(BOLD + "\n Naechste Schritte:" + RST)
    print("   1. sudo reboot          (I2C + GPIO-Konfiguration werden aktiv)")
    print("   2. sudo python3 btc_seedgen.py")
    print(DIM + "   (Fuer die Seed-Erzeugung danach: Sicherheitsregeln beachten —"
          "\n    das Hauptskript fuehrt durch alles Weitere.)" + RST)

if __name__ == "__main__":
    main()
