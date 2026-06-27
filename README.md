# SecureChannel — A Secure Communication Application

**ENCS4320 — Applied Cryptography (Term 1252)**
**Birzeit University, Faculty of Engineering and Technology**
**Department of Electrical and Computer Engineering**

A from-scratch, pure-Python implementation of a two-party secure chat
application. A client and a server exchange messages over TCP with full
confidentiality, integrity, authenticity, and replay protection, using the
same cryptographic primitives that power TLS 1.3, Signal, and WireGuard:
X25519, HMAC, HKDF, and ChaCha20-Poly1305 AEAD.

Every cryptographic primitive is implemented directly from its RFC
specification — no crypto libraries are used anywhere in the implementation
or in the tests.

---

## Team Members

| Name            | ID       |
|-----------------|----------|
| Wadee Owaise    | 1230482  |
| Hakam Snoubar   | 1230152  |

---

## Project Structure

```
SecureChannel/
├── README.md                    # This file
├── requirements.txt             # Python dependencies (none required)
├── validator.py                 # Test suite — runs all RFC test vectors
├── secret.py                    # Loads the PSK from a local file (NOT committed)
├── sha256.py                    # SHA-256 (RFC 4634)
├── hmac.py                      # HMAC-SHA-256 (RFC 2104)
├── hdkf.py                      # HKDF extract + expand (RFC 5869)
├── chacha20_poly1305_AEAD.py    # ChaCha20, Poly1305, AEAD (RFC 8439)
├── X25519.py                    # X25519 key exchange (RFC 7748)
├── secure_channel.py            # SecureChannel class (AEAD messaging)
├── general.py                   # Worker thread, channel factory, UI helpers
├── server.py                    # Server entry point
├── client.py                    # Client entry point
└── report/
    └── encs4320_report.pdf      # Project report
```

---

## Prerequisites

- **Python 3.8 or newer** (tested on Python 3.14)
- No third-party packages are required. The project uses only the Python
  standard library (`os`, `socket`, `struct`, `threading`).

See `requirements.txt` for details.

---

## Generating the Pre-Shared Key (PSK) Locally

The two parties authenticate each other using a long-term pre-shared key
(PSK) that **must never be committed to the repository**. Generate it
locally on each machine that will run the server or the client.

### Option A — using Python

```bash
python -c "import os; print(os.urandom(32).hex())" > psk.hex
```

### Option B — using openssl

```bash
openssl rand -hex 32 > psk.hex
```

Then place `psk.hex` in the project root (it is already in `.gitignore`).
The `secret.py` module reads this file at startup and exposes the PSK as
`Secret.PSK` (a 32-byte `bytes` object).

> **Important:** Both the server and the client must use the **same** PSK.
> Share it out of band (e.g., in person, via a secure messenger) — never
> over the same network the chat will run on.

The `.gitignore` file in this repository excludes `psk.hex`, `secret.py`
(if it contains the literal key), and any other secret material. **Never
commit a real PSK.**

---

## Running the Application

Open **two terminals** on the same machine (or on two machines on the same
LAN).

### Terminal 1 — start the server

```bash
python server.py
```

The server listens on `127.0.0.1:65432` by default and waits for a client
to connect.

### Terminal 2 — start the client

```bash
python client.py
```

The client connects to `127.0.0.1:65432` by default.

### Using the chat

Once the handshake completes, both sides can type messages and press
**Enter** to send. Incoming messages are printed with the prefix `HIM: `.

| Command   | Action                                  |
|-----------|-----------------------------------------|
| (any text)| Sends a normal text message (type 1).   |
| `:eq`     | Sends a close frame (type 2) and exits. |

To run on two different machines, edit the `host` and `port` arguments at
the bottom of `server.py` and `client.py`, or pass them on the command
line (the functions accept `host` and `port` parameters).

---

## Running the Test Suite

The test suite validates every primitive against the official test vectors
published in its RFC. It uses **only the team's own modules** — no
reference crypto libraries are used.

```bash
python validator.py
```

Expected output (all tests pass):

```
Validating ChaCha20-Poly1305 AEAD
PASS: b'Ladies and'...
Validating ChaCha20
PASS: b'Ladies and'...
Validating Poly1305
PASS: b'Cryptograp'...
Validating SHA256
PASS: b''...
PASS: b'abc'...
PASS: b'abcdbcdecd'...
PASS: b'aaaaaaaaaa'...
Validating HMAC
PASS: b'Hi There'...
PASS: b'what do ya'...
PASS: b'\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd'...
PASS: b'\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd'...
PASS: b'Test With '...
PASS: b'Test Using'...
PASS: b'This is a '...
Validating HDKF
PASS: b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9'...
PASS: b'\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9'...
PASS: b''...
Validating X25519
PASS: b'w\x07m\ns\x18\xa5}<\x16'...
PASS: b']\xab\x08~bJ\x8aKy\xe1'...

Process finished with exit code 0
```

Any `FAIL` line indicates a bug in the corresponding primitive and must be
fixed before submission.

---

## Cryptographic Primitives

| Primitive           | Specification | Implemented in                |
|---------------------|---------------|-------------------------------|
| SHA-256             | RFC 4634      | `sha256.py`                   |
| HMAC-SHA-256        | RFC 2104      | `hmac.py`                     |
| HKDF (extract+expand) | RFC 5869    | `hdkf.py`                     |
| ChaCha20            | RFC 8439      | `chacha20_poly1305_AEAD.py`   |
| Poly1305            | RFC 8439      | `chacha20_poly1305_AEAD.py`   |
| ChaCha20-Poly1305 AEAD | RFC 8439   | `chacha20_poly1305_AEAD.py`   |
| X25519              | RFC 7748      | `X25519.py`                   |

HMAC test vectors come from RFC 4231.

---

## Protocol Overview

The session has two phases:

### Phase A — Handshake

1. **Key exchange.** Each side generates an ephemeral X25519 key pair and
   they exchange public keys. Both compute the same shared secret.
2. **Mutual authentication.** Each side computes an HMAC tag (keyed by the
   PSK) over the transcript: `version ‖ server_id ‖ client_id ‖ A ‖ B`,
   prefixed with a role label (`b"client_auth"` or `b"server_auth"`). A
   mismatching tag aborts the connection. The role label prevents
   reflection attacks.
3. **Key derivation.** HKDF derives 88 bytes from the shared secret (with
   the PSK as salt and `version ‖ b"PhaseA"` as info), split into two
   directional 32-byte keys and two 12-byte initial nonces.

### Phase B — Secure Messaging

Every message is protected with ChaCha20-Poly1305 AEAD:

- **AAD header (plaintext, authenticated):**
  `[version 2B] [msg_type 1B] [seq 1B] [sender_len 1B] [sender NB]`
- **Frame:**
  `[AAD header] [ciphertext_len 4B] [ciphertext NB] [tag 16B]`
- **Nonce:** `initial_nonce XOR seq` (12-byte little-endian), unique per
  message per direction.
- **Replay protection:** the receiver only accepts a frame whose sequence
  number equals its expected counter; any mismatch tears down the channel.
- **Message types:** `1` = text, `2` = close.

See `report/encs4320_report.pdf` for the full design and security
analysis.

---

## Security Notes

- The PSK is the long-term secret. If it is compromised, an attacker can
  impersonate either party in future sessions — protect it accordingly.
- The 8-bit sequence number limits a session to 256 messages per
  direction before counter wrap-around. For longer sessions, re-run the
  handshake or extend the counter.
- The implementation is **not** post-quantum secure.

---

## References

- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
- RFC 4231 — Identifiers and Test Vectors for HMAC-SHA-256
- RFC 4634 — US Secure Hash Algorithms (SHA and HMAC-SHA)
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- RFC 7748 — Elliptic Curves for Security (X25519)
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols