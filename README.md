# Quantum Seed Generator

**Open, verifiable BIP39 seed generation from four independent physical entropy sources.**

Every Bitcoin wallet you will ever own rests on one thing: the randomness used to create its seed
phrase. Hardware wallets produce that randomness inside a Secure Element — a proprietary chip whose
generator you cannot inspect, audit, or verify. You are asked to trust that it delivered a full 256
bits. A weak seed looks exactly like a strong one, and the difference only becomes visible when the
funds are gone.

This project's goal is to make seed *generation* fully transparent. It runs on a Raspberry Pi 5,
derives 12- or 24-word BIP39 phrases from four mutually independent physical sources, and lets you
watch every intermediate value while it does so.

## Why not just use the wallet's RNG?

| | Hardware wallet | Quantum Seed Generator |
|---|---|---|
| Entropy sources | 1 (chip RNG, black box) | 4 independent, incl. quantum decay and physical dice |
| Auditability | none (closed silicon) | full — open source, transparency mode shows every value |
| RNG backdoor | total loss of security | neutralised: HMAC combiner keyed by your own dice |
| Entropy evidence | vendor claim | conservatively accounted and enforced (min. 2× target) |
| Supply chain | device may arrive tampered | commodity parts, self-assembled, behaviour measurable |
| Display moment | device screen | forced offline re-check immediately before display |

The four sources are hashed with domain-separated SHA-512 and combined as
`FINAL = HMAC-SHA512(key = H_dice, msg = POOL(H_hwrng, H_decay, H_camera, H_os))`.
The resulting guarantee is easy to state: **the seed is unpredictable as long as at least one side
is honest** — if every chip were backdoored, your dice alone still carry it, and vice versa.

This does **not** replace a hardware wallet. It replaces the generation step. Store and sign with
whatever device you trust; this tool just makes sure the root of it all is sound.

## Compatibility

Standard BIP39 — the seed imports into virtually every hardware and software wallet (Ledger,
Trezor, Coldcard, BitBox, Electrum, Sparrow, …). BIP39 was chosen over the Electrum format
deliberately: it accepts externally supplied entropy directly, and universal interoperability
protects against the most realistic long-term risk of all — losing access to your own coins.
Record the derivation path (e.g. `m/84'/0'/0'`, native SegWit) alongside your words, since BIP39
does not encode it. Verify the phrase on a second, independent offline device before any deposit.

## Features

- **Four entropy sources** — radioactive decay (CAJOE Geiger counter, GPIO), thermal sensor noise
  (MLX90640 IR camera raw frames), BCM2712 hardware TRNG, and physical dice as the HMAC key
- **Statistical health checks** — Poisson/χ² tests on decay intervals with dead-time correction,
  dice fairness tests, frame-freshness and tearing detection, monobit defect detection
- **Conservative entropy accounting**, enforced at ≥ 2× the target before anything is derived
- **Dual computation** — the whole chain runs twice independently and is compared; BIP39 roundtrip
  and an in-RAM wordlist re-check run before display (the Pi 5 has no ECC RAM)
- **Air-gap enforcement** — WLAN/Bluetooth off (rfkill plus permanent `config.txt` overlays),
  Ethernet unplug required, SSH/tmux/`script`/VNC/recorder detection, swap disabled, core dumps
  blocked, memory locked (`mlockall`, `PR_SET_DUMPABLE=0`)
- **Final offline re-check immediately before the seed appears** — any re-activated channel aborts
  the run and the seed is never displayed
- **Transparency mode** — every digest, the pool and the final HMAC shown live and reproducible
- **Guided ceremony** — security briefing, transcription verification against your paper copy,
  screen and scrollback wipe, optional shell-history truncation
- **Self-test with known-answer vectors** on every run; LIGHT mode (HWRNG + dice) for setups
  without the sensors; bilingual DE/EN; mock mode for testing that never touches the host

## Getting started

```bash
sudo python3 install_seedgen.py     # packages, I2C, GPIO17 bias-free, wordlist + hash
sudo reboot
sudo python3 btc_seedgen.py --selftest
sudo python3 btc_seedgen.py
```

Wiring diagrams: `docs/connection_cajoe.svg`, `docs/connection_camera.svg`, or
`python3 install_seedgen.py --pinout`. Full documentation (DE/EN) in `docs/`.
Diagnostics for the sensors live in `tools/`.

> **Hard-won note:** GPIO17 must run **bias-free** (pull none). The high-impedance signal tap
> (10 kΩ in series) is choked by any internal pull-up or pull-down and no pulses arrive at all.
> The installer anchors `gpio=17=ip,pn`; the script sets pull none at runtime as well.

## Verify before you trust

Run `sha256sum -c sha256.txt` after cloning, then the self-test, then a `--mock` run. Do not skip
this — checking the code is the entire point of the project.

## Limits

Python cannot guarantee erasure of immutable objects in RAM; use one fresh boot per ceremony. The
system does not protect against a compromised operating system, physical surveillance, or an
untrusted monitor. Shor's algorithm remains a threat to ECDSA itself — the benefit here is a
*guaranteed* 256 bits of entropy, not quantum resistance. Seeds generated in mock mode are
deliberately unusable.

## License

MIT — see `LICENSE`. No warranty. You are responsible for your own funds. Contributions,
independent audits and reproductions of the test vectors are explicitly welcome.
