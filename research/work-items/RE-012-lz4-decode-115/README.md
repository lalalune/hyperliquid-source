# RE-012: node #115 size-prefixed LZ4 decode contract

- Component: **transport**, RE-012 / RE-005 integration boundary.
- Target: Linux x86-64 node #115,105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Research base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Scope: one complete adapter's logical-byte decoder contract and its literal
  sink helper; independently authored safe Rust implementation. No gate requested.

The active base contains no buildable size-prefixed LZ4 decoder. The selected
TCP reader's compressed path was already bound in [PR2076](https://github.com/lalalune/hyperliquid-source/pull/2076),
which explicitly leaves the transform body open. This packet follows that
real indirect call into the decoder; it does not re-credit the reader.
No overlapping LZ4-body task was present in the inspected open PR inventory.

The new [library](../../../src/node115-lz4-decode/README.md) accepts a four-byte
little-endian capacity plus a block. It implements literal and match extension
sequences, overlapping history, terminal literals, prefix-limit admission and
observed error-category precedence. The prefix is **capacity, not exact output
length**. A stream ending with a match still needs a terminal token. Those
are target observations, not extra wire-format restrictions invented here.

## Evidence and attribution

All addresses are linked ELF VAs, ranges half-open. FDE extents are verified
by the repository parser and GNU readelf; complete instruction partitions
agree between GNU2.45, LLVM23.1.4 and Capstone5.0.7.

| Body | Extent | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Size-prefixed adapter / inlined block decoder | `0x477f8c0..0x4780322` | 2,658 | 603 |
| Literal sink append helper | `0x477e5c0..0x477e6d4` | 276 | 74 |
| Total static context | two FDEs | 2,934 | 677 |

`evidence.json` retains42 exact instruction clauses, all132 direct branch
edges,25 callsites,33 unique selected relocation writers,19 source Locations,
complete FDE/CIE bytes and11 LSDA call-site rows. PT_LOAD mapping separately
cross-checks the section-based mapping. Full native exports are unmasked.
The supporting parsers remain unchanged and their hashes are recorded.
No native machine-code equality with compiled Rust is claimed.

Source Locations name `z_vendor/lz4_flex/src/block/decompress_safe.rs` and
`sink.rs`. This establishes embedded dependency attribution, not an exact
public crate version or proof of an unmodified fork. No public lz4_flex source
or unlicensed inferred source was copied. This safe scalar implementation is
independently authored from the captured instructions. Its value is recovering
the target integration contract; it earns no new dependency or first-party
compiled-byte credit. PR2050's broad dependency census is distinct context;
this packet does not duplicate its rebuild/byte-window claims.

The symbol-zero RELATIVE TCP slot `0x64e7790` binds to `0x477f8c0`.
External memcpy/memmove/memset symbols are resolved by actual dynamic symbols,
not guessed from slot names. Allocator, deallocator, error factories and panic
helpers are inventoried but left conditional. [PROOF.md](PROOF.md) states the
manual reduction, register/stack observations, copy invariants and premises.
Native Result/Vec ABI, formatted error payloads, spare-capacity contents,
allocation/unwind effects and full reader lifecycle are explicitly excluded.

## Implementation comparison

Before Rust existed, `corpus.py` froze158,486 input/expectation pairs; hashes
are in `frozen.json`. Of these,7,334 use separately constructed output bytes
or explicit boundary outcomes. Constructed matches expand a period without
calling the decoder oracle. The remaining expected results are the manually
instruction-derived Python specification, **not captured execution**.

There are11,156 successes,147,328 ordinary errors and2 extension-overflow
panic boundaries. The two overflow recipes each use16,843,010 continuation
bytes and test the actual checked u32 boundary without large output allocation.
The generated large inputs and raw outputs remain in ignored work/, not Git.

Rust1.95.0 debug, optimized and repeated optimized builds all match exactly:
475,458 observations over158,486 cases/build. Optimized library hashes match
when source and output paths are fixed. Ten separately compiled production
mutants exit normally and produce mismatches: prefix endian136,941;
equal-limit158,470; exact-size9,339; literal nibble58,824; match base7,725;
offset endian6,246; zero accepted1,120; wrong history bytes5,638;
extension termination2,032; extension wrapping2. These are Rust comparator
controls; they are not altered captured-program executions.

Forty-two individual native-clause corruptions are rejected below the full
capture hash, and two wrong-input identities are rejected at its public gate.
Those44 controls bind the evidence mechanically; they do not replace the
manual semantic proof or demonstrate the behavior of mutated target code.
No instruction emulator, captured executable, socket, signing, chain action,
private source or optional usage/trace upload is involved.

## Reproduce

From the repository root with the pinned binary materialized, Rust1.95.0,
Python3.14.5, Capstone5.0.7, GNU binutils2.45 and LLVM23.1.4 on PATH:

```sh
python3 -B research/work-items/RE-012-lz4-decode-115/collect.py work/lz4-static-fresh
python3 -B research/work-items/RE-012-lz4-decode-115/verify.py \
  --rustc /path/to/rustc-1.95.0 --out work/lz4-qualification-fresh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-lz4-decode/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-lz4-decode/Cargo.toml
make doctor verify catalogue-check reproduce
```

Use fresh output directories; the verifier refuses existing destinations.
`collect.py` regenerates full exports; `verify.py` regenerates them twice,
compares the committed packet, checks GNU readelf, recreates frozen cases,
compiles/runs all three correct builds and all ten mutated libraries, and
retains raw outputs plus results. `corpus.py`'s initial freeze entry point
refuses to freeze after Rust exists; verification uses its unchanged recipe.
Exact export text is qualified to the recorded native tool versions.

`results.json` records exact successful qualification and source/tool hashes.
`VALIDATION.md` records repository checks and their scope. No hosted CI,
container build, independent peer review or full-node run is claimed.

## Limits and next question

The safe library projects logical bytes and category decisions under normal
native memory/helper premises. It returns ExtensionOverflow for native panic
and a local Allocation error for reservation failure. It makes no ABI, timing,
SIMD/spare-capacity or exceptional-state equivalence claim. The full fast-copy
language and invalid-input behavior are justified by the manual reduction,
not established by native differential execution or finite corpus counts.

All92 component gates stay false; no byte-window registration is added.
Next: recover the inverse compression adapter and bind when the writer chooses
compressed vs uncompressed payloads, then join this decoder with the reader's
ordinary ownership/error continuation. That is separate from this PR.
