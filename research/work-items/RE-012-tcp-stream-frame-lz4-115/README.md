# RE-012: compose TCP frame reads with the size-prefixed LZ4 adapter

- Component: `transport`, task RE-012; maintainer acceptance issue [#3911](https://github.com/lalalune/hyperliquid-source/issues/3911).
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Scope: one independently authored offline Rust stream adapter joining the existing frame-policy and LZ4 libraries. No network or captured-process execution.
- Base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

## Target-grounded behavior used

The existing [frame-plan evidence](../RE-012-tcp-frame-plan-115/README.md) binds the complete five-byte header, big-endian u32 payload length, inclusive u64 length gate, exact `flag == 1` transform selection, completion-before-next-read branch, and requested read intervals capped at 4,000,000 bytes. It also identifies the captured reader's transform slot `0x64e7790` as targeting the size-prefixed LZ4 adapter at `0x477f8c0`.

The existing [LZ4 evidence](../RE-012-lz4-decode-115/README.md) covers that adapter's little-endian capacity prefix, capacity check, block decoding and normal-return error ordering. This change composes those two existing contracts; it adds no byte-window or reconstruction gate credit.

## New adapter contract

`src/node115-tcp-stream-frame-lz4` reads a frame from a caller-owned Rust `Read` implementation. `Limits::frame_payload` controls the outer header gate; `Limits::decoded_capacity` is passed to the existing LZ4 decoder. The two limits are separate because their equivalence in the native call path is not established by the retained evidence.

The adapter retries `Interrupted`, fills fragmented header and payload reads, and never requests a payload interval larger than the target-derived 4,000,000-byte cap. It does not drain an over-limit frame. A short header or payload leaves a partial frame consumed and reports `DiscardStream`. An LZ4 error occurs only after the entire announced outer payload has been read, so the returned `NextFrameBoundary` disposition means a caller can attempt the next frame. An I/O error before consuming any header byte reports `NoFrameBytesConsumed`; callers still decide whether that error is retryable.

These last read/error/disposition rules describe the new synchronous adapter and its API. The captured reader is an async state machine; this contribution does **not** claim its pending, cancellation, short-read, I/O error, allocation or cleanup behavior is equivalent. The adapter does not establish a socket handshake or a usable peer connection.

## Validation

The library has only path dependencies on the two existing project-authored crates; no external package or build hook is introduced. Tests use an in-memory `Read` implementation and synthetic frames only.

- `cargo +1.95.0 test --locked --offline --manifest-path src/node115-tcp-stream-frame-lz4/Cargo.toml`: 10 tests passed in debug and release.
- `cargo +1.95.0 fmt --check --manifest-path src/node115-tcp-stream-frame-lz4/Cargo.toml`: passed.
- Test cases cover fragmented header/payload reads, inclusive exact limit and rejected over-limit consumption, LZ4 composition with a following frame, decompression-error stream position, truncated payload and partial-I/O-error disposition, pre-header I/O failure, `Interrupted` retry, clean EOF versus empty frame, and the 4,000,000-byte request cap.

`make verify` passed after adding this packet and its manifest: signatures, 32 imported files and pinned repositories verified; packet manifests verified. `make catalogue-check` passed after regeneration. `make doctor` reports `analysis_ready: true` and `exact_rebuild_ready: false`; the latter remains a repository-wide open milestone, not a claim made by this bounded adapter. `make test` discovered 1,130 files; the run was stopped after 211 because unrelated packet-regeneration tests made it impractically long. It had reported errors in `test_bit9_f2_trace_static.py` and `test_curl_options_static.py`; both files passed when rerun independently with the same temporary GNU binutils 2.47 / pytest 8.4.1 / Capstone 5.0.7 environment. The full suite therefore has no completion result. No live networking, captured executable, signing, chain action, private key or paid dataset is used.
