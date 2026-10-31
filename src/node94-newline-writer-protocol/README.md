# Node #94 byte-request and flag protocol

This independently authored `no_std` library implements only a qualified
callback protocol observed in node #94's 622-byte newline adapter at
`0x157d000..0x157d26e`. It makes no allocation, UTF-8/string conversion,
formatting or I/O itself. Every input byte is preserved, including NUL, CR and
invalid UTF-8. The callback receives nonempty LF-inclusive chunks followed by
a nonempty final tail when present.

For each chunk, the function samples the **current raw flag byte**. Any nonzero
value requests exactly four space bytes first. A nonzero callback byte returns
status 1 immediately. After successful indentation (or if none is needed),
the function stores whether the chunk ends in LF as 0/1 **before** the payload
callback. That callback's nonzero byte also stops with status 1. Otherwise the
next chunk samples the flag again, including arbitrary callback mutations.
All-success status is 0. Empty input and a terminal LF cause no empty payload
or extra indentation request.

The chosen API uses `core::cell::Cell<u8>` and a per-request normal `FnMut`
proxy. Either callback may set the Cell to any byte. An indentation-error
mutation persists without the helper store/payload; an indentation-success
mutation is overwritten by the PRE-payload 0/1 store. Payload mutations persist
on error and affect the next chunk on success. The proxy is invoked anew for
each request. If relating it to the native contract, it must represent cached
post-prologue D/V/B arguments and fresh method-entry selection per request;
a stable Rust closure does not prove a stable native writer identity.

This is **not the original ABI, vtable, nominal writer/formatter type or physical
rendering**. Safe references must remain valid even on empty input, a stronger
chosen domain than native raw empty-pointer states that need no flag/input/
method dereference. Callbacks must return normally; panic/unwind, faults,
concurrency and unsafe alias corruption are excluded. The original physical
frame/return/metadata and callback-preservation conditions remain explicit in
the [unchanged native proof](../../research/work-items/RE-005-diagnostic-field-trace-94/SCAN-AND-PRETTY-PROOF.md).
The parent's 390-byte formatter/helper remains supporting evidence, not an
implemented parent or a new source-equivalence claim. The `u8` result models
only the native low-byte 0/1 projection; higher native return bits are unknown.

## Actual standalone build

This is a real dependency-free Rust module under `src/`, built directly with
the existing authenticated research compiler **rustc 1.94.1**. That development
pin is not a recovered original node compiler. No Cargo workspace, dependency
lock, build script, allocator stub or original-byte transplantation is added.

```sh
/path/to/verified/rustc --edition=2021 --crate-name node94_newline_writer_protocol \
  --crate-type=rlib -D warnings -C overflow-checks=on -C opt-level=3 \
  src/node94-newline-writer-protocol/lib.rs -o /tmp/libnewline_protocol.rlib
/path/to/verified/rustc --edition=2021 --test -D warnings \
  -C overflow-checks=on src/node94-newline-writer-protocol/lib.rs \
  -o /tmp/newline-protocol-tests
/tmp/newline-protocol-tests --nocapture
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/owned-short python3 -B \
  tools/bincode_diagnostic_writer_rust.py --rustc /path/to/verified/1.94.1/rustc \
  --output /tmp/newline-protocol-build-new --controls
```

The runner admits one immutable node snapshot by full target digest. All ELF,
metadata, literal and certificate facts derive from that exact bytes object;
GNU sees only the unchanged producer's tiny copied raw spans. The independent
expectation generator enumerates LF indexes and a final nonempty end, then
applies the target-proved callback/flag transfer to given normal-callback
stimuli. It does not invoke Rust or copy `split_inclusive` to choose cuts.

A separately linked production library receives only raw byte inputs, initial
flags and indexed callback return/mutation stimuli. The harness records actual
request bytes, entry flags and supplied responses, never expectation-derived
indent/payload labels (a payload can itself equal four spaces). Missing indexed
actions use a normal default, so extra requests are visible rather than harness
panics. This is reviewed input-only data flow, not filesystem sandboxing.

`test_driver.rs` and `target-transcripts.tsv` serve the ordinary Rust test and
the separate std harness; neither is included in the no_std production rlib.
Real unoptimized/optimized builds, actual transcript comparisons, compiling
semantic mutants and own-library raw rebuild comparisons are recorded in the
[sibling Rust packet](../../research/work-items/RE-005-diagnostic-writer-rust-94/README.md).
They do not execute/emulate the captured node, establish original compiler/byte
identity, qualify physical memory accesses from Cell values, or complete a
component gate. All 19 original #1030 files and prior failures are preserved.
