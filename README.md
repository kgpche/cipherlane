<div align="center">

<img src="logo/02-shield-lane.svg" width="96" height="96" alt="cipherlane logo" />

# cipherlane

**End-to-end encrypted transfers on your LAN — an AirDrop for your local network**

Send device-to-device (X25519 key agreement) or via shareable links. Content stays encrypted even over plain HTTP.

English | [简体中文](README.zh-CN.md)

![CI](https://github.com/kgpche/cipherlane/actions/workflows/ci.yml/badge.svg) ![version](https://img.shields.io/badge/version-0.2.2-37d4a0) ![node](https://img.shields.io/badge/node-%E2%89%A518-4285f4) ![tests](https://img.shields.io/badge/tests-7%20suites%20passing-f9ab00) ![license](https://img.shields.io/badge/license-MIT-8291b0)

</div>

---

## Contents

- [Two Ways to Send](#two-ways-to-send)
- [Screenshots](#screenshots)
- [Quick Start](#quick-start)
- [How It Works & Protocol](#how-it-works--protocol)
- [Security Model](#security-model)
- [Packaging & Deployment](#packaging--deployment)
- [Browser Compatibility](#browser-compatibility)
- [FAQ](#faq)
- [Project Layout](#project-layout)
- [Tests](#tests)
- [Changelog](#changelog)
- [Roadmap](#roadmap)
- [License](#license)

## Two Ways to Send

| | Device Direct (default) | Link Mode |
| --- | --- | --- |
| Best for | Same LAN, pick & send | Across subnets / via chat apps or email |
| Key | X25519 negotiated inside both browsers, **never crosses the network** | Random key lives in the URL `#fragment`, delivered out of band |
| Passive sniffing / server logs | ✓ protected / ✓ protected | ✓ / ✓ |
| Malicious-server MITM | ✗ (public keys are distributed by the server — see [Security Model](#security-model)) | ✓ (key never reaches the server, fully zero-knowledge) |

One LAN IP = one device: each device gets a **name** (editable), a **geometric avatar** (deterministically generated from its IP, Material-flat style), and an **X25519 identity key** (kept in the browser's localStorage).

## Screenshots

| Device-direct home (online device grid + avatars) | Link mode, transfer done | Text receive (decrypt & display) |
| :---: | :---: | :---: |
| <img src="docs/screenshots/landing.png" width="280" alt="Landing device grid" /> | <img src="docs/screenshots/send-done.png" width="280" alt="Send done" /> | <img src="docs/screenshots/recv-text.png" width="280" alt="Text receive" /> |

`Ctrl+V` anywhere on the page sends your clipboard: screenshots/files go straight out, text goes directly if a device is selected (or fills the input box otherwise).

## Quick Start

```bash
node server.js            # or: npm start. Default port 7777 (PORT= to change);
                          # binds 127.0.0.1 + LAN (RFC1918) interfaces by default (HOST=0.0.0.0 for all interfaces)
```

The server prints its LAN address (e.g. `http://192.168.1.117:7777`). On any device on the **same Wi-Fi**, open it in a browser:

1. Set your name on the home page → the other side appears under "online devices"
2. Select a device → drop a file / paste text → the other side gets an invitation card (with the decrypted file name and size) → accept to receive

Machines without a browser can use the CLI (fully interoperable with the web UI):

```bash
node cli.mjs devices --server http://192.168.1.117:7777        # list online devices
node cli.mjs send big.zip --to 192.168.1.50 --server http://... # direct send (no link needed)
node cli.mjs listen --yes -o ~/downloads --server http://...    # resident receiver (can be direct-sent to)
node cli.mjs send big.zip --server http://...                   # link mode: prints a receive link
node cli.mjs recv 'http://.../#ROOM.KEY' [-o output path]       # link-mode receive
```

## How It Works & Protocol

<details>
<summary>Architecture diagram (click to expand)</summary>

```
Sender browser/CLI                    LAN (plain HTTP, sniffable)             Receiver browser/CLI
┌─────────────┐  discovery/X25519 pub  ┌──────────────┐                     ┌─────────────┐
│ pick target  │ ◀─────────────────▶ │  dumb relay    │ ◀────────────────▶ │ picked from  │
│ ECDH → key   │    (sees only pubs)  │ sees only      │   (sees only pubs)  │ ECDH → key   │
│ AES-GCM enc  │ ──── ciphertext ───▶ │ ciphertext     │ ──── ciphertext ───▶ │ AES-GCM dec  │
└─────────────┘                      └──────────────┘                     └─────────────┘
   room key = SHA-256( X25519 shared secret ‖ both public keys ‖ room id ), derived identically on both sides
```

</details>

**Protocol at a glance** (all endpoints in `server.js`; limits are defaults):

| Endpoint | Purpose |
| --- | --- |
| `POST /api/presence` | Device heartbeat (last writer wins per IP, 5s heartbeat / 20s TTL) |
| `GET /api/devices` | Online device list (IP / name / X25519 public key) |
| `POST /api/rooms` | Create a transfer room (10-char base62 id ≈ 59.6 bits) |
| `POST /api/rooms/:id/chunk` | Post ciphertext chunk (1 MiB plaintext each, backpressure window 64, requires room token) |
| `GET /api/rooms/:id/chunk?i=N` | Sequential pull (25s long-poll, one-shot consumption) |
| `POST /api/rooms/:id/offer` | Attach a direct-send invitation (encrypted preview hint, must precede chunks) |
| `GET /api/offers` | Long-poll this device's pending invitations (**secret + source IP double binding**) |
| `POST /api/offers/:id/accept\|reject` | Accept / reject (rejected rooms live 2 more minutes for the sender to observe) |
| `POST /api/rooms/:id/done` / `ack` | Sender finished / receiver confirmed (ack carries a key proof verified locally by the sender); idle rooms are reclaimed after 15 min |

Limits: 64 chunks / 64 MB backpressure per room, 256 MB global, ≤ 8 pending offers per device (5 min TTL), ≤ 256 devices.

## Security Model

| Threat | Defense |
| --- | --- |
| LAN sniffing (plain HTTP) | Content, file names and types are all AES-256-GCM encrypted; every chunk is individually authenticated |
| The server operator (link mode) | Zero knowledge: the random key travels in the URL `#fragment`, peer to peer, and never reaches the server |
| The server operator (device direct) | Room key derived via X25519; the server sees only public keys and ciphertext — old logs stay useless |
| Stolen device secret | Useless: claiming an invitation requires **both the secret and the matching source IP** — a different machine gets 401 |
| Link obtained by a third party | Room ids are unenumerable; chunks are consumed one-shot — once someone pulls them, others get 410 |
| Tampering in transit | GCM auth tags verified per chunk; invitations whose preview fails verification are auto-rejected |
| Impersonating the sender | Posting chunks requires the random room token (held only in the sender's memory) |
| Forged delivery confirmation | ack carries a key proof SHA256(key‖label‖room); sender verifies locally and flags proof-less acks |
| Small-order / invalid public keys | X25519 all-zero shared secret is rejected (RFC 7748 requirement) |
| Room abuse | Hard limits above; idle rooms reclaimed automatically |

**Known boundaries (stated honestly)**:

- **Device-direct mode cannot automatically stop an active MITM by the server**: device public keys are distributed by the server, so a malicious server could substitute keys and impersonate the receiver. The mitigation is **public-key fingerprints** (TOFU): device cards and your own card show an 8-hex fingerprint, and a changed key is flagged "⚠ key changed" persistently — comparing fingerprints out loud defeats substitution, but the system will not compare them for you. For the highest assurance, use link mode
- **The page itself is served over plain HTTP**: E2EE protects against passive observers only; an active on-path attacker could in principle replace the served JavaScript (the same class of risk as opening any plain-http site). Use a VPN on untrusted networks
- Device names and presence are visible to the server and to anyone who opens the page on the LAN — the inherent cost of device discovery
- The server binds 127.0.0.1 + LAN (RFC1918) interfaces by default, not VPN/tun or virtual adapters; explicit `HOST=0.0.0.0` (as the deb service template does) binds everywhere
- No resume support: chunks are consumed one-shot; if the receiver refreshes, the sender must resend
- Malicious packet dropping is DoS — detectable (stalled transfer / errors) but not preventable
- Room ids travel in plaintext HTTP requests: on fully sniffable networks (open Wi-Fi), an attacker can race the receiver for chunks (getting ciphertext they cannot decrypt, starving the receiver); confidentiality is unaffected, availability is
- Multiple **different browsers** on one IP: the device entry belongs to the last one to register (same-browser tabs share the secret and coexist)

**How encryption works over plain http**: browsers only expose `crypto.subtle` in secure contexts. This project ships pure-JS implementations and degrades automatically: AES-256-GCM (`public/aesgcm.js`), SHA-256 (`public/sha256.js`), X25519 (`public/x25519.js`, BigInt + RFC 7748 Montgomery ladder). On localhost/https, AES uses native WebCrypto. The pure-JS output is byte-identical to node:crypto (verified by tests).

## Packaging & Deployment

One command produces installers for three platforms (target machines **do not need Node**):

```bash
sh build/package.sh            # artifacts in build/dist/
```

| Artifact | Platform | Install / use |
| --- | --- | --- |
| `cipherlane_<v>_amd64.deb` | Linux x64 (Ubuntu/Debian) | `sudo dpkg -i …deb && sudo systemctl enable --now cipherlane` (ships a systemd unit, starts on boot) |
| `cipherlane_<v>_windows_x64.zip` | Windows x64 | Unzip and double-click `cipherlane.exe` (console shows address + QR code) |
| `cipherlane_<v>_macos_universal.tar.gz` | macOS arm64 + x64 | Unzip and double-click `cipherlane.command` (if Gatekeeper complains: right-click → Open) |

Built on Node **SEA (single executable applications)**: the server and all frontend assets are embedded into official Node binaries per platform. Linux/Windows are true single files (125MB/87MB, 31MB/33MB compressed); macOS ships a dual-arch source bundle (75MB). The build script caches official binaries and postject, verifies downloads against SHASUMS256, and emits a `SHA256SUMS_<v>.txt` alongside the artifacts.

Source deployment stays zero-dependency: `node server.js` (Node ≥ 18).

## Browser Compatibility

| Requirement | Notes |
| --- | --- |
| BigInt (for X25519) | Chrome 67+ / Edge 79+ / Firefox 68+ / Safari 14+ |
| Streaming save (optional) | Chromium-based browsers support `showSaveFilePicker`; others fall back to in-memory download |
| Paste-to-send (optional) | Any modern browser with clipboard events; on mobile, long-press paste into the text box |

The CLI needs Node ≥ 18 (native X25519 and AES-GCM).

## FAQ

**The page still looks old after an upgrade / server restart?**
Static assets are loaded into memory at server start, and the browser may reuse an old tab — **close and reopen the tab** or hard-refresh (Ctrl+Shift+R).

**`EADDRINUSE: 7777` on startup?**
The port is taken. Start with `PORT=7788 node server.js`, or stop the old process.

**My phone can't see devices / others can't see me?**
All devices must be on the **same Wi-Fi/subnet**; check that the OS firewall allows the port (Windows asks once); make sure you opened the LAN address printed at startup, not `127.0.0.1` (loopback is local-only).

**Popups don't work in ZCode / Electron embedded browsers?**
Some embedded webviews lack `alert/confirm` and file savers — a host limitation. Use a real browser (Chrome / Edge / Safari) for serious work.

**QR code looks distorted in an IDE integrated terminal?**
IDE terminals (Electron/xterm.js) deviate from the standard 2:1 cell geometry, which can distort ASCII QR art — a rendering quirk of those environments; standard terminals (GNOME Terminal / Windows Terminal / iTerm) are fine. In an IDE terminal use the fallbacks: `cipherlane-qr.png` in the working directory (pixel-exact), or the SVG QR on the send page. `CIPHERLANE_QR_RATIO=<measured ratio>` corrects manually.

**Receiver refreshed mid-transfer of a big file?**
No resume support yet — just send again (roadmap item).

**How fast is the pure-JS path?**
Encryption runs in a ×4 worker pool; a single worker does ~10–20 MB/s, scaling with cores. localhost/https uses native WebCrypto and is faster. X25519 is milliseconds, imperceptible.

## Project Layout

```
cipherlane/
├── server.js           # zero-dependency relay: rooms + presence + invitations (Node builtins only)
├── cli.mjs             # CLI: devices / direct send / listen / link send & receive
├── sea-config.json     # SEA single-executable config (asset manifest)
├── build/package.sh    # one-shot packaging: .deb / Windows exe / macOS universal
├── logo/               # logo art (main + favicon master)
├── docs/screenshots/   # README screenshots
├── public/
│   ├── index.html      # SPA (device grid · geometric avatars · invitation cards · dual receive layouts)
│   ├── app.js          # send/receive logic + dual crypto paths + X25519 identity
│   ├── aesgcm.js       # pure-JS AES-256-GCM (plain-http fallback path)
│   ├── sha256.js       # pure-JS SHA-256 (KDF)
│   ├── x25519.js       # pure-JS X25519 (device-direct key agreement)
│   ├── avatar.js       # geometric avatars (Material-flat, deterministic from IP)
│   └── style.css
└── test/               # seven suites: aesgcm / sha256 / x25519 / qrcode / avatar / protocol / browser
```

## Tests

```bash
npm test    # or run individually: node test/<name>.test.mjs
```

- **aesgcm**: FIPS-197 S-box vectors, GHASH cross-validation, byte-identical to node:crypto for 0B–1MiB
- **sha256**: FIPS 180-4 vectors + 500 random cross-checks
- **x25519**: RFC 7748 vectors + 200 random pairs vs node ECDH (both directions), small-order rejection
- **qrcode**: RS algebra self-checks, finder/timing/format structure assertions
- **avatar**: determinism, neighbor-IP distinctness, palette & luminance constraints
- **protocol**: spawns a real server; covers presence/invitations/accept/reject/limits/same-IP rotation/concurrent pulls/ack proofs/bind surface/link mode end to end
- **browser**: CDP-driven real-Chrome smoke tests (two-page send/receive, error paths, worker-pool assertion); auto-skips when no browser is available

## Changelog

**v0.2.2** (2026-10-13)
- Adversarial-review fix batch: concurrent pulls of the same chunk are now first-come-first-served (runner-up gets 409; previously the sender got a 500 and the runner-up hung forever); setup-phase failures now have an escape path (previously a dead-end view with no button); per-transfer key scoping (concurrent send/receive in one tab no longer cross-contaminate); CLI short-read fix / dotfile defense (`.bashrc` lands as `bashrc`) / atomic `.part` writes
- Unique sequence numbers on chunk GETs: closes an in-flight request-coalescing hole where the browser/proxy could hand the same one-shot chunk to two waiters
- Performance: ×4 crypto worker pool (pure-JS AES scales with cores) + 3-deep receive prefetch pipeline
- Security: ack carries a key proof (forged acks detectable by the sender); device public-key fingerprints + change warnings (TOFU); default binding narrowed to loopback + LAN interfaces (no more default 0.0.0.0, avoids exposing VPN/tun segments)
- Engineering: zero-dependency browser smoke tests ×6 (CDP-driven Chrome — the frontend finally has automated tests); GitHub Actions CI (Node 18/20/22); packaging script checked in with supply-chain verification (SHASUMS256); deb systemd unit least-privilege hardened; stalled-connection timeouts; listen heartbeat warnings

**v0.2.1** (2026-10-12)
- QR codes: pure-JS encoder (V1–5 byte mode ECC-L, structural tests with RS algebra self-checks); SVG QR on the send page, ASCII QR in the server banner and CLI — scan with a phone and go
- Web Worker crypto: chunk encryption off the main thread (big transfers no longer stall the progress UI), one-chunk pre-encryption pipeline; automatic main-thread fallback
- Arrival alerts: system notifications (localhost/https) + tab-title flashing (anywhere) + mobile vibration

**v0.2.0** (2026-10-12)
- Device direct send: one IP = one device (name / geometric avatar / X25519 identity), pick-to-send, invitation cards, accept/reject
- Pure-JS X25519 + SHA-256 (RFC 7748 / FIPS 180-4, interop-tested against node natives)
- Separate text/file receive layouts; Ctrl+V anywhere to send
- Send-view terminal states fixed (return home on completion, 100% progress, rejection message no longer overwritten)
- CLI: `devices` / `--to` direct send / `listen` resident receiver
- Final logo "secret path on a shield", integrated into the header and favicon

**v0.1.0** (2026-10-11)
- Link-mode E2EE transfer: AES-256-GCM, zero-knowledge relay, pure-JS crypto fallback, CLI send/receive

## Roadmap

- [ ] Pure-JS AES performance work (T-tables / SIMD GHASH)
- [x] QR codes for receive links (scan with a phone) — v0.2.1
- [ ] Multi-file / directory transfers
- [ ] Resume support (replayable chunks + position negotiation)
- [x] Device public-key fingerprints + change warnings (TOFU defense against server MITM)

## License

[MIT](LICENSE) © 2026 kgpche
