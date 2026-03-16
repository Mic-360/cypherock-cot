# Contributing to Cypherock COT

Thanks for your interest in contributing! 🎉

This project implements a COT-based 2-party multiplication protocol over secp256k1 across a C++ server and TypeScript client. We welcome improvements to protocol clarity, correctness, documentation, and developer tooling.

## Before you start

- Read `README.md` for architecture and run instructions.
- Check open issues to avoid duplicate work.
- For major changes (protocol/message format/refactors), open an issue first so we can align on design.

## Development setup

### Prerequisites

- Git
- CMake >= 3.16
- C++17 compiler (MSVC on Windows expected)
- Boost headers >= 1.70
- Node.js >= 20
- npm

### Build and run locally

1. Build server target `cot_server` via CMake.
2. In `client/`, run `npm install` and `npm run build`.
3. Start server, then run client (`npm start` or `npm run dev`).
4. Confirm protocol verification prints `PASS ✓` on both sides.

## Contribution workflow

1. Fork the repository.
2. Create a branch from `main` with a descriptive name:
   - `feat/<short-description>`
   - `fix/<short-description>`
   - `docs/<short-description>`
3. Keep commits focused and descriptive.
4. Rebase on latest `main` before opening a PR.
5. Open a pull request with:
   - clear summary,
   - rationale,
   - testing details,
   - and any protocol compatibility notes.

## Coding guidelines

### General

- Prefer small, reviewable changes.
- Avoid broad formatting-only diffs.
- Keep public behavior consistent unless change is intentional and documented.

### C++ (`server/`)

- Follow existing style and naming in `server/src`.
- Keep error messages actionable.
- Be explicit with bounds/size checks for protocol parsing.

### TypeScript (`client/`)

- Keep strict typing intact (`tsconfig` strict mode is enabled).
- Avoid implicit `any` and unchecked buffer assumptions.
- Keep protocol behavior aligned with server-side implementation.

## Protocol compatibility checklist

If your change touches message structures or round logic, verify all of:

- `proto/cot.proto`
- `server/src/proto_utils.cpp`
- `client/src/proto_utils.ts`
- `server/src/ot_session.cpp`
- `client/src/ot_session.ts`

Any one-sided change here will usually break runtime interop.

## Testing expectations

At minimum, contributors should:

- build the server,
- build the client,
- run an end-to-end protocol session,
- and confirm final verification is `PASS ✓`.

If you add new behavior, please include reproducible verification steps in your PR description.

## Documentation expectations

Update documentation when behavior changes:

- `README.md` for setup/run/protocol-visible changes,
- comments near protocol-sensitive code,
- this file when contribution process changes.

## Security and responsible disclosure

Please do **not** open public issues for security vulnerabilities.

Report them according to `SECURITY.md`.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0 (`LICENSE`).
