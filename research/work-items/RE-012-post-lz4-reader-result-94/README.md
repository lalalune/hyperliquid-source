# RE-012: post-LZ4 reader result and cleanup requests (node/94)

This packet closes the selected post-call gap in
[transport-lz4-frame-94](../transport-lz4-frame-94/README.md): what reader
`0x2049950` does with the decompressor's result, how its immediate consumer
uses that result, and which buffer-cleanup requests each path makes.

| Selected ordinary path | Output to reader's result storage | Original-buffer cleanup request |
|---|---|---|
| Compression flag zero | Original capacity/pointer/length triple | None in this post-read path |
| Decompression result first word differs from T | Decoded capacity/pointer/length triple | Only if byte `C+0x49 != 0` **and** original capacity is nonzero |
| Decompression result first word equals T | T and the raw error payload; third word not established as active data | Only if original capacity is nonzero; no flag test |

Here `T = 0x8000000000000000`, C is the reader state pointer, and a cleanup
request is the observed call through `0x576e010` with pointer, capacity and
zero. It is **not** a claim that memory is physically freed or that the full
lifetime/allocator contract is recovered. All three ordinary paths clear
`C+0x49` and write `C+0x48 = 1`.

The concrete consumer at `0x204aeaf` distinguishes pending-shaped T+1,
error-shaped T and other result words. Its cleanup helper `0x1fcb690` returns
without any call for the completed reader state 1. On a value result, the
consumer passes the returned pointer/length to opaque `0x28bc630`, then
conditionally requests cleanup of that returned capacity. The opaque decoder's
format and source result type are not recovered here.

## Review and identity

- [PROOF.md](PROOF.md) gives the premises, branch/store relation, consumer,
  cleanup gates and separate LSDA observations.
- Component `transport`, task RE-012; node #94 target
  `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Research base: `d3af75257a396c85d20857f421c370ddb8cb40e5`; coordinates are
  linked ELF virtual addresses and half-open ranges.
- Prior credit: [PR #139](https://github.com/lalalune/hyperliquid-source/pull/139)
  owns header/admission/chunk facts; [PR #179](https://github.com/lalalune/hyperliquid-source/pull/179)
  owns the LZ4 wrapper; [PR #592](https://github.com/lalalune/hyperliquid-source/pull/592)
  owns the three counter-update prefix facts. Their bytes and shared timing
  helpers are dependency context, not new recovery credit. The
  [offline codec](../../../src/node94-tcp-frame/README.md) remains unchanged.
- Independently authored scripts/docs; no new can1357 source use or copied
  implementation. Claim status is byte observation plus conditional manual
  dataflow inference, with unresolved behavior stated below.

## Validation

Eight complete FDEs retain **10,506 bytes and 2,185 normalized instruction
rows**. GNU and LLVM agree on every selected byte and boundary after joining
only standalone LLVM LOCK prefix rows. [records.json](observed/records.json)
contains raw FDE/CIE/LSDA, relocations, fixed witnesses and export hashes;
[cfg.tsv](observed/cfg.tsv) contains structural basic blocks once (`-` means no
structural successor). Full GNU text remains readable; the complete LLVM text
is deterministically gzipped with both raw and stored SHA-256 values checked.

[validation.json](validation.json) records **79 corruption controls** and two
complete regenerated evidence trees, all passing. Normal and optimized Python
verification agree. [MANIFEST.sha256](MANIFEST.sha256) binds every packet file
other than itself. From this directory:

```sh
python3 -B verify.py
python3 -B -O verify.py
python3 -B collect.py --out /tmp/post-lz4-new-evidence
gzip -dc observed/reader.llvm.txt.gz
```

The output directory must be new. Host: Darwin 27.0.0 arm64, Python 3.14.3.
Defaults are GNU objdump `/opt/homebrew/opt/binutils/bin/objdump`
(2.47.20260726) and `/usr/bin/objdump` (Apple LLVM 21.0.0); pass `--gnu`/`--llvm`
to select tools. Exact-output regeneration includes tool version/formatting.
Every export uses an authenticated private read-only snapshot, checked before
and after the native tools. No captured code, emulator, instruction evaluator,
network behavior or project installer is run. No full-suite result is claimed.

## Scope and remaining work

Before: the prior packet left this reader's post-LZ4 result/disposal path open.
After: the selected branch, result stores, state changes, consumer and cleanup
request operands are connected to complete FDE/CFG evidence. This is partial
static research; no Rust implementation, compiled equivalence or component
acceptance gate is claimed or requested.

Valid async states, accessible disjoint storage, helper preservation and normal
returns are explicit premises. Header/read/timer/diagnostic behavior before the
selected path, complete decompressor fast paths, statistics concurrency,
allocator fallback, opaque decoder/error constructor, inactive result bytes,
unwind semantics and full ownership remain open. A useful next question is the
independently bounded contract of `0x28bc630`; it must not be inferred from this
consumer's argument shape.
