# RetroMessenger

RetroMessenger is a small peer-to-peer (P2P) encrypted messenger written in C++ with a wxWidgets GUI. It uses Boost.Asio for direct TCP connections and libsodium for cryptography. The project demonstrates a simple invitation-based P2P protocol, end-to-end encryption using a double-ratchet style design, and adaptive compression.

## Goals

- Provide direct, serverless encrypted messaging between peers.
- Demonstrate a practical double-ratchet message flow for forward secrecy.
- Use adaptive compression (tANS for short messages, Zstandard for longer payloads) to save bandwidth.
- Keep the UI minimal and easy to use via wxWidgets.

## High-level overview

1. Peer A connects to Peer B using a one-line invitation exchange over TCP.
2. Peers exchange static public keys in the invitation/accept exchange and compute a shared secret with `crypto_box_beforenm`.
3. The shared secret initializes a ratchet state (root key + send/recv chain keys).
4. Messages are sealed with a per-message symmetric message key derived from the send chain key, encrypted with XChaCha20-Poly1305, and sent inside a framed TCP message.
5. Receiving peers advance their receive chain and decrypt messages, performing a DH ratchet when a new ephemeral public key is observed.

## Protocol (invitation & session setup)

- Invitation (initiator -> receiver):
   - Send a single line: `INVITE:<initiator_static_pub_hex>:<initiator_id>\n`
- Response (receiver -> initiator):
   - `ACCEPT:<receiver_static_pub_hex>:<receiver_id>\n` to accept and continue the handshake
   - `REJECT\n` to decline

On accept, both sides compute `shared_key = crypto_box_beforenm(peer_static_pk, my_static_sk)`. That `shared_key` seeds the ratchet initialization.

## Message framing and wire format

- Each TCP message is framed with a 4-byte big-endian length prefix (frame length includes payload only).
- Encrypted ratchet message wire layout (bytes, in order):
   - 1 byte: message type (0x01 = data)
   - 32 bytes: sender ephemeral public key
   - 32 bytes: previous-message-hash (32 bytes)
   - 4 bytes: message counter (big-endian)
   - 24 bytes: XChaCha20-Poly1305 nonce
   - remaining bytes: ciphertext (XChaCha20-Poly1305 tag appended)

Notes:
- The application packs additional authenticated data (AAD) composed of the sender ephemeral public key, the previous message hash, and the counter when encrypting.
- After successful encryption the sender updates its last-sent hash (a keyed hash of the ciphertext + counter) and increments the send counter.

## Compression & padding

- Before encryption the plaintext is passed to `compress_data`:
   - If input length < 64 bytes: no compression (flag 0x00)
   - If 64 <= length < 256: try tANS (flag 0x02) and use it if it is smaller
   - If length >= 256: try Zstandard (flag 0x01) and use it if it is smaller
- The compressed payload is padded to 256-byte blocks using a custom 0x80 + 0x00.. padding scheme to hide exact plaintext length.
- On receipt the receiver unpads and then decompresses based on the compression flag byte.

## Cryptography & ratchet details

- Crypto primitives (libsodium):
   - Static keypair for the application (`crypto_box_keypair`) exchanged in invitations/accepts.
   - `crypto_box_beforenm` to compute an initial symmetric shared key.
   - Ephemeral keypairs (`crypto_box_keypair`) used in per-message ratcheting and DH (`crypto_scalarmult`).
   - AEAD encryption: `crypto_aead_xchacha20poly1305_ietf` for message confidentiality and integrity.
   - Generic hashing (`crypto_generichash`) for KDF and message hashes.

- Ratchet design (simplified double-ratchet style):
   - A root key and two chain keys (send/recv) are derived from the initial shared secret.
   - For each message, the sender advances their send chain: `chain_advance(chain_key)` → (message_key, next_chain_key).
   - Message encryption uses the derived `message_key` and includes AAD to bind ratchet state.
   - When a new ephemeral public key is observed from the peer, a DH ratchet step is performed to derive a new root key and a new receive chain key.
   - The implementation zeroes ephemeral secrets and derived keys after use.

## Message flow summary

1. Initiator sends `INVITE` containing its static public key (hex) and an ID.
2. Receiver accepts and replies `ACCEPT` with its static public key and ID.
3. Both compute shared secret and initialize ratchets.
4. Initiator and receiver exchange encrypted, framed messages as described above.

## Security considerations

- Uses well-known primitives from libsodium (XChaCha20-Poly1305, crypto_box, generic hash).
- Keys and sensitive material are cleared from memory when no longer needed.
- Padding reduces leakage of exact plaintext length, but does not fully hide traffic patterns (message timing, frequency).
- No delivery or replay protection beyond the included counters and per-message hashes — in a hostile network additional replay protection could be added.

## Build & run

Dependencies (typical on Debian/Ubuntu):

```bash
sudo apt install build-essential cmake libwxgtk3.0-gtk3-dev libboost-system-dev libboost-thread-dev libsodium-dev libzstd-dev
```

Build:

```bash
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

Run (after build):

```bash
./RetroMessenger
```

The listening port is displayed in the window header. Use "Start New Chat" to invite another peer by address and port.

## Files of interest

- `main.cpp` — main application logic, network protocol, ratchet, compression and GUI glue.

## Contributing and notes

- This is an experimental demo of P2P encrypted messaging and is not production hardened.
- If you plan to extend or reuse parts of the code:
   - Prefer standard libsodium APIs and avoid rolling custom cryptography.
   - Add stronger replay protection and persistent identity management for production use.


