# Cypherock COT (C++ Server + TypeScript Client)

This repository implements a **Correlated Oblivious Transfer (COT)** based 2-party multiplication flow over **secp256k1**:

- **Alice / Server**: C++ (`Boost.Asio` + `trezor-crypto`)
- **Bob / Client**: TypeScript (`Node.js` + `protobufjs`)

At a high level, the protocol computes additive shares $(U, V)$ such that:

$$
U + V \equiv x \cdot y \pmod n
$$

where:

- $x$ is the server's multiplicative share (random scalar)
- $y$ is the client's multiplicative share (random scalar)
- $n$ is the secp256k1 curve order

---

## What is implemented

### Core protocol pieces

1. **256 OT rounds** (one round per bit of the client scalar $y$).
2. Server sends round init with compressed point $A = aG$.
3. Client chooses selection bit $c_i = y_i$ and replies with point $B$:
   - if $c_i = 0$: $B = bG$
   - if $c_i = 1$: $B = bG + A$
4. Server derives two keys from EC shared points and encrypts:
   - $m_0 = U_i$
   - $m_1 = U_i + x$
5. Client decrypts exactly one message (according to $c_i$) to get $m_{c_i}$.
6. Client computes:

$$
V = \sum_{i=0}^{255} m_{c_i} \cdot 2^i \pmod n
$$

7. Server computes:

$$
U = -\sum_{i=0}^{255} U_i \cdot 2^i \pmod n
$$

8. Both sides exchange final shares and verify:

$$
U + V \stackrel{?}{=} x \cdot y \pmod n
$$

### Message format / transport

- Schema: `proto/cot.proto`
- Envelope: `CotMessage` with `message_type` + `oneof payload`
- Framing on TCP:
  - 4-byte big-endian length prefix
  - followed by protobuf-encoded bytes

### Crypto primitives in code

- Curve: `secp256k1`
- Shared secret derivation: X-coordinate from EC point multiplication
- Symmetric encryption: `AES-256-CBC` (with IV prepended)
- KDF: `SHA-256`
- Scalar ops: modulo secp256k1 order $n$

---

## Repository layout

- `server/` — C++ server implementation
  - `src/main.cpp` — entrypoint, generates server share `x`, starts TCP server on port `12345`
  - `src/server.cpp` — session loop, 256-round protocol orchestration, verification
  - `src/ot_session.cpp` — per-round OT state, message generation and final additive share
  - `src/crypto_utils.cpp` — secp256k1, AES, hash, scalar arithmetic wrappers over trezor-crypto
  - `src/proto_utils.cpp` — protobuf wire encode/decode compatible with client
- `client/` — TypeScript client implementation
  - `src/index.ts` — end-to-end protocol runner + verification
  - `src/client.ts` — framed TCP socket helper
  - `src/ot_session.ts` — client OT state machine and additive share computation
  - `src/crypto_utils.ts` — secp256k1 + AES + scalar arithmetic utilities
  - `src/proto_utils.ts` — protobufjs encode/decode and framing helpers
- `proto/cot.proto` — shared protocol schema

---

## Build prerequisites

### Common

- Git
- Internet access during initial CMake configure (to fetch `trezor-crypto`)

### Server (C++)

- CMake `>= 3.16`
- C++17 compiler (MSVC on Windows is expected)
- Boost headers (`>= 1.70`)

> Important: top-level `CMakeLists.txt` currently sets:
>
> `BOOST_ROOT = C:/boost_1_82_0`
>
> Keep Boost there, or override `BOOST_ROOT` while configuring.

### Client (TypeScript)

- Node.js `>= 20`
- npm

---

## Build instructions (Windows)

From repository root:

### 1) Configure and build the C++ server

Use your preferred generator (Visual Studio or Ninja). Example with VS generator:

1. Configure:
   - source dir: repo root
   - build dir: `build`
   - if Boost is not at `C:/boost_1_82_0`, pass your path as `BOOST_ROOT`
2. Build target: `cot_server` (Release or Debug)

Expected output binary (VS multi-config):

- `build/server/Release/cot_server.exe` (or `Debug/`)

### 2) Install and build the TypeScript client

Inside `client/`:

1. Install dependencies
2. Compile TypeScript

Build output:

- `client/dist/index.js`

---

## Run instructions

Use **two terminals**.

### Terminal A: start server

Run `cot_server.exe` from your chosen build configuration folder.

You should see logs like:

- server multiplicative share `x`
- listening on port `12345`
- round progress every 64 rounds
- final verification block

### Terminal B: start client

From `client/`, run the built JS entrypoint (or `npm run dev` for ts-node).

You should see logs like:

- client multiplicative share `y`
- connected to server
- round progress every 64 rounds
- final verification block

On success, both sides print:

- `Result      : PASS ✓`

---

## Notes and assumptions

- Transport is plain TCP on `127.0.0.1:12345` by default.
- Client loads `proto/cot.proto` at runtime via `protobufjs`; no code generation step is required for the client.
- Server uses a manual protobuf wire implementation in `server/src/proto_utils.cpp` compatible with the schema.
- This repo is currently focused on protocol correctness/testing, not hardened production deployment (no TLS/auth/session management).

---

## Quick troubleshooting

- **Boost not found** during CMake configure:
  - set/override `BOOST_ROOT` to your Boost installation path.
- **Port in use**:
  - stop existing process on `12345` or change server/client port together.
- **Proto load error on client**:
  - make sure `proto/cot.proto` exists at the expected relative path from `client/dist`.
- **Verification FAIL**:
  - ensure both binaries are from current source, no mixed stale builds.
