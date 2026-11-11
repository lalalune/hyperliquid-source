# RE-012: node 115 offline framed-stream composition

This partial contribution to #3911 composes the existing frame-plan and LZ4
reconstructions into `src/node115-frame-stream`, an owned one-frame incremental
adapter. It leaves the TCP component and the issue open.

Target: node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. The existing
`RE-012-tcp-frame-plan-115` and `RE-012-lz4-decode-115` packets provide the
header/chunk policy and decoder implementation; this contribution joins them
and adds selected evidence for the read/transform handoff.
Earlier node #94 work in #1245 and #1755 covers an offline frame codec and
asynchronous frame I/O respectively. Their broader older-version behavior is
related context; this packet binds the selected composition to node #115 and
provides a local synchronous fragment interface rather than an async runtime.

The retained windows show the five-byte read and partial-read handling,
inclusive admission gate, flag-1 transform selection, 4,000,000-byte chunk
limit, and post-read transform slot `0x64e7790 -> 0x477f8c0`. The selected
header and body read paths preserve pending state; ready success without
progress produces an early EOF error. The transform receives the wire payload
and the same maximum. The verifier authenticates 11 selected byte windows,
their enclosing FDEs and the transform relocation; it does not independently
prove the accompanying semantic interpretation or full function behavior.
Instruction text in `evidence.json` is a retained static interpretation, not
executed target code.

The new local API distinguishes an empty fragment from explicit EOF, reports
consumed input so a following frame remains with the caller, and makes each
reader terminal after success or failure. Terminal behavior is a local API
choice and does not establish native connection recovery. Initial wire-buffer
allocation failure is reported locally; the decoder retains its own allocation
and error policy. Network I/O, timeout and scheduler behavior, error ABI,
recovery and full runtime equivalence are outside this packet.

## Reproduce

With the repository artifact hydrated and Rust 1.95 already installed:

```sh
python3 research/work-items/RE-012-node115-frame-stream-115/verify.py --controls
cargo +1.95.0 test --locked --offline --manifest-path src/node115-frame-stream/Cargo.toml
```

The tests cover all two-fragment splits of representative raw and compressed
frames, empty feeds, explicit EOF, inclusive limits, decoder errors, unconsumed
next-frame bytes, and crossing the chunk boundary. No captured instructions are
executed or emulated.
