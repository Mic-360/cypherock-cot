# Cypherock COT

Correlated Oblivious Transfer (COT) based 2-party multiplication over secp256k1.

This project contains:

- **Alice / Server**: C++ (`Boost.Asio` + `trezor-crypto`)
- **Bob / Client**: TypeScript (`Node.js` + `protobufjs`)

The protocol computes additive shares $(U, V)$ of the product of private multiplicative shares $(x, y)$:

$$
U + V \equiv x \cdot y \pmod n
$$

where $n$ is the secp256k1 curve order.

---

## Why this repository exists

This codebase is a practical, readable implementation of COT-style share conversion from multiplicative shares to additive shares. It is designed for:

- protocol experimentation,
- interoperability between languages (C++ and TypeScript),
- and correctness verification in a local/dev environment.

> ⚠️ **Security notice**
>
> This repository is currently focused on protocol correctness and developer testing.
> It is **not production-hardened**: no authenticated transport, no TLS, and no advanced session hardening.

---

## Protocol summary

For each bit $y_i$ of the client scalar $y$, one OT round is executed (256 rounds total):

1. Server samples round scalar $a_i$ and sends $A_i = a_iG$.
2. Client uses choice bit $c_i = y_i$ and replies with:
   - $B_i = b_iG$ if $c_i = 0$
   - $B_i = b_iG + A_i$ if $c_i = 1$
3. Server derives two keys from EC shared points and encrypts:
   - $m_{0,i} = U_i$
   - $m_{1,i} = U_i + x$
4. Client decrypts only $m_{c_i,i}$.

After all rounds:

$$
V = \sum_{i=0}^{255} m_{c_i,i} \cdot 2^i \pmod n
$$

$$
U = -\sum_{i=0}^{255} U_i \cdot 2^i \pmod n
$$

and both parties verify:

$$
U + V \stackrel{?}{=} x \cdot y \pmod n
$$

---

## Project architecture

### Server (`server/`)

- `src/main.cpp` — creates random server share `x`, starts TCP server on port `12345`
- `src/server.cpp` — protocol orchestration, message exchange, final verification
- `src/ot_session.cpp` — OT round state, encrypted pair generation, additive share computation
- `src/crypto_utils.cpp` — secp256k1 operations, hashing, AES wrappers, scalar math
- `src/proto_utils.cpp` — protobuf-compatible framing and message encode/decode

### Client (`client/`)

- `src/index.ts` — end-to-end protocol execution and verification
- `src/client.ts` — framed TCP socket helper
- `src/ot_session.ts` — choice-bit logic, decrypt path, additive share accumulation
- `src/crypto_utils.ts` — secp256k1, AES, scalar arithmetic utilities
- `src/proto_utils.ts` — protobufjs message encoding/decoding helpers

### Shared schema (`proto/`)

- `proto/cot.proto` — message schema and payload definitions

---

## Message transport and wire format

- Envelope type: `CotMessage`
- Discriminator field: `message_type`
- Payload: `oneof payload`
- TCP framing:
  1. 4-byte big-endian length prefix
  2. protobuf-encoded message bytes

---

## Cryptographic building blocks used in code

- Curve: `secp256k1`
- Shared secret: x-coordinate of EC point multiplication
- KDF: `SHA-256`
- Symmetric encryption: `AES-256-CBC` (IV prepended in ciphertext blob)
- Scalar arithmetic: modulo secp256k1 order $n$

---

## Prerequisites

### Common

- Git
- Internet access during first CMake configure (to fetch `trezor-crypto`)

### Server (C++)

- CMake `>= 3.16`
- C++17 compiler (MSVC is expected on Windows)
- Boost headers (`>= 1.70`)

Top-level `CMakeLists.txt` sets:

- `BOOST_ROOT = C:/boost_1_82_0`

If your Boost path differs, override `BOOST_ROOT` during configure.

### Client (TypeScript)

- Node.js `>= 20`
- npm

---

## Build and run (Windows)

Use two terminals.

### 1) Build C++ server

From repository root:

1. Configure CMake (source `.` and build dir `build`)
2. Build target `cot_server` in your preferred configuration (Debug/Release)

Expected executable (Visual Studio multi-config):

- `build/server/Release/cot_server.exe`

### 2) Build TypeScript client

From `client/`:

1. Install dependencies (`npm install`)
2. Compile (`npm run build`)

Expected output:

- `client/dist/index.js`

### 3) Start protocol

- Terminal A: run `cot_server.exe`
- Terminal B (in `client/`): run `npm start` (or `npm run dev`)

Expected logs include:

- both sides print their multiplicative shares
- progress every 64 rounds
- verification section
- `Result      : PASS ✓` when successful

---

## Development workflow

- Keep protocol message compatibility between:
  - `proto/cot.proto`
  - `server/src/proto_utils.cpp`
  - `client/src/proto_utils.ts`
- If changing round logic, update both:
  - `server/src/ot_session.cpp`
  - `client/src/ot_session.ts`
- Rebuild both server and client after protocol changes.

---

## Troubleshooting

- **Boost not found during configure**
  - set `BOOST_ROOT` to your local Boost installation path.
- **Port 12345 already in use**
  - stop the previous process, or change host/port on both sides.
- **Client cannot load protobuf schema**
  - verify `proto/cot.proto` exists at expected runtime path relative to client build output.
- **Verification fails (`FAIL ✗`)**
  - clean and rebuild both sides to avoid stale mixed binaries.

---

## Open-source project files

For maintainers and contributors, see:

- `CONTRIBUTING.md` for contribution workflow
- `CODE_OF_CONDUCT.md` for community standards
- `SECURITY.md` for vulnerability reporting
- `LICENSE` for Apache 2.0 licensing terms

---

## License

Licensed under the Apache License 2.0. See `LICENSE`.
