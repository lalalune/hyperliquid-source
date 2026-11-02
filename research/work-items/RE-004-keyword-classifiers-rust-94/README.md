# RE-004: three node94 keyword classifiers in Rust

This packet reconstructs one coherent classifier family from three
existing foundation packets. The complete leaves are
`[0x1437b90,0x1437be4)`, `[0x1e6d560,0x1e6d5a6)` and
`[0x25903d0,0x2590426)`: 240 bytes, 82 instructions, six literal keywords,
one two-byte output contract. They classify `until/required_matches`,
`vip/mm` and `input/gas_limit`. These three related reconstructions share
one component and one evidence packet.

The source preserves full-u64 length tests, skips unused input memory,
classifies before any overlapping output store, writes `[9, tag]` and
returns the full incoming output address in RAX. The safe image API
checks selected input/output spans before mutation; every refusal is
atomic. Refusals are new policy, distinct from original faults.
[PROOF.md](PROOF.md) establishes the full admitted domain, scalar/SIMD
comparison equivalence, alias order and explicit ABI limits.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Source: [`src/node94-keyword-classifiers`](../../../src/node94-keyword-classifiers).
The existing foundation packets, tools and tests remain unchanged. No
unlicensed inferred source was read or copied. This is a bounded RE-004
implementation result, not a completed foundation or whole-node gate.

## Static evidence

All six complete leaf/caller bodies have fresh GNU and LLVM exports and
matching Capstone boundaries. The three caller extents total 19,401 bytes
and 4,208 instructions. Exact FDE/CIE bytes, neighboring padding, one
confirmed direct call per leaf, E8/E9 candidate scans, all 80,300 RELA
records and the readonly 16-byte SIMD comparand are bound in `static.json`.
There are no helper calls or mutable constant dependencies. Indirect
entry paths and caller application semantics remain unproved.

Two old prose details are resolved directly against bytes: until's
PCMPEQB uses displacement −0x12330b6 to reach `0x204b10`; the vip caller's
actual endpoint difference is 6,525 bytes. Existing raw evidence is
preserved. `disassembly.json` records exact export commands, executable
hashes, versions and raw-output hashes. The target itself is only read
as data, never executed or emulated.

```sh
python3 -B research/work-items/RE-004-keyword-classifiers-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-keyword-classifiers-rust-94/verify_static.py
python3 -B research/work-items/RE-004-keyword-classifiers-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/keyword-classifiers-rust/fresh-replay
```

Use a fresh native output directory. The recipe pins the actual rustc
executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`,
version 1.94.1, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8 and aarch64-apple-darwin target. It builds a dependency-free
`no_std` library and a separate std input-only client directly, using
warnings denied, overflow checks enabled, one codegen unit, and the
explicit `/usr/bin/cc` linker. Exact invocations and actual tool hashes
are recorded, not inferred from a rustup selection string.

## Frozen oracle and observed results

Before the Rust directory existed, `oracle.py` fixed 12,443 inputs and
expectations from a full-length/base-256 dictionary and immutable
final-byte relation. `frozen.json` binds the target, oracle, static record
and compressed streams. The Rust uses selected slice comparisons and
actual ordered memory writes. No native output becomes expected data.

Both opt0 and opt3 match every complete 73-byte output record: 11,359
normal results, nine ImageRange refusals, 615 Input refusals and 460
Output refusals. Coverage includes all three tags for each selector,
10,240 single-position byte substitutions before shared-baseline
deduplication, overlap displacements at eight source alignments,
full-width length distinctions, exact final-byte boundaries and unused
invalid input addresses. Three additional unit tests pass per profile.
Malformed rows and oversized image lengths are rejected before output.
Four repeated rlib/client comparisons are byte-identical without masks.

Nineteen incorrect implementations were actually compiled and run at
both optimization levels (38 effective controls): each of six changed
literals, low32 length tests, each wrong output tag, omitted final byte,
case folding, early prefix store, late output admission, wrong RAX,
strict endpoint, reading unused input, wrong prefix and overwriting the
tag. Early output changes 392 admitted results; late admission changes
69 refused images. Comparator controls detect one changed row and a
missing row. `native-results.json` retains every count and first witness.

Static replays pass with regular and optimized Python, different hash
seeds and UTC/Kiritimati time zones, with equal recorded output. All 46
structural corruption controls reject. Local `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` pass. The three unchanged
legacy checker commands reproduce, and their focused tests pass 11+11+13
= 35 tests. Pinned rustfmt check passes. `checks.json` records all thirteen
commands and stream hashes. Doctor's existing `exact_rebuild_ready` gate
remains false. The shared full-suite run and hosted CI are not claimed
passed by this packet.

`native-raw-streams.json.gz` losslessly retains stdout/stderr of all
138 native recipe commands. `checks-raw-streams.json.gz` retains all local
check streams. The archives map labels to SHA-256 and those hashes to
base64 payloads. Every decoded payload and command-log binding is checked
against the original bytes. Native output streams are unmodified; call
metadata substitutes `<repo>`, `<rustc>` or `<home>` for local path prefixes
where applicable. Reproducible build artifacts stay under ignored `work/`.

Three development failures are retained in `development.json` and its
lossless archive: an incorrect handwritten static byte selector corrected
before freeze, nonunique mutation selectors corrected before compilation,
and Rust E0507 from moving a Range inside a match guard. The guard now
clones the two-usize range for indexing. Initial verifier/library sources,
exact compiler command and raw errors are preserved. No target or native
client ran in those failed attempts. The frozen oracle was unchanged;
the complete final matrix ran in a fresh directory after correction.

`overlap.json` records 119 open PRs, zero open issues, 100 recently merged
PRs and current main source with no competing classifier implementation.
The addresses were reserved before source authoring. Independent parent
source/proof review found no blocker. No imported pins, original evidence,
generated catalogue or acceptance gates change. Original compiled-byte
identity, arbitrary process-memory maps, ABI/fault behavior and whole-node
equivalence remain outside this contribution.
