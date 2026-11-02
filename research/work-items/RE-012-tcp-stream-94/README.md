# RE-012: asynchronous I/O for the node #94 frame format

- Component: `transport`; source base `e5c9b6436876b2a4a39daef813171f9879317699`.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim: independently authored framing I/O plus bounded static observations.
  No full transport, component gate, rebuilt-byte or network claim.
- Changed source: the existing `src/node94-tcp-frame/` component. No inferred
  can1357 implementation was read or copied for this change.
- Task selection checked PR #1606, which inventories `tcp_stream.rs` Locations and literals.
  This change uses different files and reconstructs I/O over the already
  qualified frame format; it does not claim that inventory or its ownership.

## Why this moves the node forward

The existing codec could encode/decode a complete in-memory frame but could not
consume or emit one over asynchronous I/O. The optional `stream` feature now
provides `stream::read_frame` and `stream::write_frame` over caller-owned Tokio
I/O. It handles fragmentation, short writes and suspension without losing or
repeating bytes, and consumes exactly one frame per read. This supplies a
usable framing layer for the later peer transport without pretending that peer
selection, handshake, timeouts, state synchronization or an executable exist.

The implementation preserves the previously established five-byte header,
inclusive size admission, flag-1 LZ4 rule and 4,000,000-byte chunk cap. Reads
chunk payload bytes; writes chunk the whole encoded frame. Raw reads transfer
ownership of their payload buffer instead of making a second full-frame copy.
The decoded LZ4 size is still checked before output allocation. There is no
flush or shutdown hidden in a successful write.

## New binary observations

`verify.py` reauthenticates the complete target, obtains FDE extents, and checks
21 specific instructions and their relative destinations. `records.json`
retains original bytes and coordinates. Addresses are linked ELF virtual
addresses, not file offsets or load addresses. GNU and LLVM listings retain
both entire FDEs (GNU `-d -M intel --insn-width=15`, LLVM `-d
--x86-asm-syntax=intel`, and explicit start/stop addresses from the table below);
nearest exported C++ names printed by the disassemblers are
not used as function names or ownership evidence.

| Selected extent | Observation |
| --- | --- |
| `0x2034eb0..0x203516e` (702 bytes) | Remaining-capacity loop reaches success only at zero; changed fill progress loops; unchanged progress constructs `early eof`; pending and error take separate branches |
| `0x2036460..0x20367c3` (867 bytes) | Empty remaining slice completes; successful writes advance pointer and subtract the count; a positive count loops; zero progress and an error leave the loop; pending preserves continuation state |

For reads, `0x2034f83` subtracts filled length, `0x2034f8c` reaches success at
zero, and `0x2034f9b` calls the poll helper at `0x4f7cf70`. The branches at
`0x2034fa2` and `0x2034fa7` distinguish pending and error. The comparison and
loop at `0x2034fc3..0x2034fc8` reach the nine-byte EOF literal only when a
successful poll made no progress. Its constructor loads `0x25` at
`0x2034fd4`; the call slot `0x576ee60` has a symbol-zero RELATIVE relocation
to `0x4edac60`.

For writes, `0x2036583` skips polling for an empty slice. The call at
`0x2036596` targets `0x4f7d1a0`; `0x203659f` handles pending and `0x20365a3`
handles error. The updates at `0x20365c9` and `0x20365d2` subtract the written
count and advance the pointer. `0x20365e6` loops on positive progress; otherwise
`0x20365e8` reaches the error path, using the packed constant
`0x1700000003` loaded at `0x203656e`.

These are observations of selected control flow and stored values, not a full
ABI recovery. The exact-version Rust source has `UnexpectedEof` at enum index
37 and `WriteZero` at index 23. The packed-error interpretation is source
correspondence; no independent complete `io::Error` ABI claim is made.

## Source and dependency correspondence

The accepted [frame reader](../transport-tcp-frame-read-94/README.md) packet
binds these exact-read paths to the frame readers and identifies Tokio 1.44.2
through target source Locations. Its companion
[writer packet](../transport-tcp-frame-write-94/README.md) establishes the
chunked writer and identifies the selected write poll. The
[codec packet](../RE-012-node94-tcp-frame-codec/README.md) supplies the remaining
format/LZ4 contract.

`source-evidence.json` pins the downloaded Tokio crate checksum, source-file
hashes, and the Rust 1.94.1 source revision. Tokio's `ReadExact` and `WriteAll`
implement the selected progress/EOF/pending behaviors. The new implementation
calls those existing licensed operations rather than recreating their internals.
The Tokio license remains its own MIT license; the new component code is MIT.

Only Tokio `io-util` is enabled, without the runtime, networking, macros or timer
features. The Cargo.lock was generated by Cargo for this real component. Its
`bytes` 1.12.1 and `pin-project-lite` 0.2.17 selections are build choices, not a
claim to recover the node's crate graph or exact features. Native macOS builds
do not establish Linux machine-code identity.

REA 6.8.0's direct `inspect_with_objdump` file-header call confirmed the same
artifact digest and ELF entry (`0x1343c80`), evidence
`ev_31db44ff39c4662fc317cebcdb288b91550914f1dcf4cd84f3beca81bf5c6f0f`.
Its public objdump contract supports symbol selection but not address windows;
local GNU/LLVM tools supplied the bounded instruction listings. No provider
registration, tooling infrastructure or captured executable was changed/run.

## Reproduce and controls

```sh
export PATH="$(brew --prefix binutils)/bin:$(brew --prefix llvm)/bin:$PATH"
make doctor verify
python3 research/work-items/RE-012-tcp-stream-94/verify.py
python3 -m unittest discover -s tests -p test_tcp_stream_evidence.py -v
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release
cargo clippy --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path src/node94-tcp-frame/Cargo.toml -- --check
```

The 16 stream tests use scripted I/O and independently specified wire fixtures:
all header/body truncations of a short frame, pending at each partial read/write,
all non-one flags, an independent LZ4 literal block, a maximum forged decoded
size, consecutive frames, inclusive admission, distinct header/payload chunk
boundaries, unchanged I/O errors, zero writes, and cancellation after progress.
They open no sockets. The original 53 offline tests remain in scope.

The five Python evidence tests mutate each selected instruction below the full
identity check, alter the EOF literal and relocation, and separately require
full artifact authentication. The four compiled source mutations in
`rust-negative-controls.json` remove admission, ignore compression, shorten
read chunks, and omit the transmitted header. Each compiles and then fails the
stream test suite. They are not implementation candidates or matching-byte
credit. Final validation outcomes are in `VALIDATION.md`.

## Limits and next step

The routines are explicitly not cancellation safe: cancellation/error can leave
part of a frame consumed or transmitted, so callers must discard the connection
unless they can restore the boundary. No reconnect/resume behavior is invented.

Timing remains incomplete. The prior packets expose reader 20/40-second and
writer 20/60-second values, but this change does not recover the complete
conditional timer lifecycle, cancellation effects, scheduling, logs or error
formatting. No timer is silently substituted. The poll helpers' deeper socket
behavior remains outside the selected loop evidence.

This source does not open a connection, choose an endpoint, encode a gossip
request, validate a peer, synchronize state, serve APIs, or build a node/Docker
image. No acceptance gate or byte-coverage percentage changes. The next bounded
question is to bind the caller's header-timing flag and per-chunk timer to the
recovered I/O, then integrate the independently reconstructed peer greeting and
message types once those are established.
