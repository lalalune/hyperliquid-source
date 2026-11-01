# RE-004: signed byte/dword gate and its tail closure

Target node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`;
reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23` unchanged.
Bounded RE-004/foundation reconstruction; no component or progress gate advances.

`src/node94-byte-dword-gate-pair` reconstructs complete entries at 0x5172c70 and
0x5172c90 together: 63 bytes, 19 instructions. The first returns a nonzero flag
byte when a signed count is positive, otherwise a signed dword comparison.
The second checks a pointed qword against the sign-extended count, returning 1
on inequality or tail-entering the first function on equality. Full RAX/RDX
are preserved, including RDX's path-dependent sign versus zero extension.
The historical static packet left the second body unimplemented and unexplained.

PROOF.md derives all conditional accesses, exact widths and full-register
values. Missing unused flag/compared fields are admitted where the original
path does not read them. An immutable nonwrapping byte image supports arbitrary
read-role aliases and wrapped field formation. Numeric addresses are metadata,
never host pointers. None is a new safe refusal; original faults, concurrent
changes, MMIO, flags, CET and native calling convention are excluded.

## Evidence and qualification

All 63 leaf bytes / 19 boundaries and actual FDE/CIE records are bound with GNU,
Apple LLVM and Capstone. Four complete caller FDEs total 9,471 bytes and 1,889
instructions; all four E8 sites and the internal E9 tail are boundary-qualified.
All 80,300 RELAs are scanned; none names either entry or writes body/padding.
No RIP-relative data or opaque helper dependency remains inside the closure.
All 43 structural corruption controls are effective.

The first strict static comparison rejected three caller-only LLVM display
splits of LOCK ADD. That original verifier/diagnostic is preserved. Only exact
byte pairs at 0x503a84c, 0x503a9c4 and 0x50ecdb7 are joined; all other instruction
boundaries and every byte remain checked. The correction preceded Rust and
the static/oracle freeze. No leaf normalization or source change was involved.

An independent immutable-address-map oracle froze 24,730 cases before Rust
existed. All 98,920 comparisons matched across opt0/opt3 builds and repeats:
89,644 admitted projections and 9,276 API refusals. The signed comparison oracle
uses an unsigned order key rather than the source's i32 comparison; the tail
uses abstract sign extension/equality partitions, not instruction stepping.
The input-only client receives no expected outputs. Library memory preservation
follows from its immutable slice API and absence of unsafe code; native outputs
compare status and both full registers without masks.

All 24 compiled wrong implementations produce mismatches, including unsigned
substitution, low32 tail comparison, incorrect register extension, booleanized
flags, eager unused reads, wrong field widths/offsets and ignored image overflow.
Three units per optimization and malformed-input/comparator controls pass.
Same-option library/client/output hashes repeat exactly. No native build or
compiled-control failure occurred. All 190 stdout/stderr streams and commands
are retained losslessly in a content-addressed gzip archive (level1,mtime0).

Pinned compiler: rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, binary SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Flags bind aarch64-apple-darwin, edition2024, denied warnings, overflow checks,
one codegen unit, panic abort for value builds and the actual system linker.
Static tools are GNU 2.47.20260726, Apple LLVM 17 and Capstone 5.0.7.
Only independently authored native Rust ran. Original compiled-byte identity,
whole-caller/node behavior and original ABI remain unclaimed.

```sh
python3 -O -B research/work-items/RE-004-byte-dword-gate-pair-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-byte-dword-gate-pair-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/byte-dword-gate-pair-replay
```

Use a new output directory. Compiler location may differ; version/hash remain
checked. Source/compiler identities, exact commands, first mismatch witnesses
and raw archives are retained in this packet. Captured instructions are static
evidence locks, never executable transplantation.

## Shared baseline limits

The separate shared baseline attempted 971 files/15,462 tests/69 skips. Original
exit2 was solely three disk-full errors; all 20 affected tests passed isolated
retries. `shared-baseline-result.json` preserves that outcome and log hashes.
No successful full-sweep repeat, per-head full suite, skipped Linux run or
hosted CI success is claimed. Imports, pins and generated gates stay unchanged.

Doctor, verify, catalogue-check, reproduce, all 31 focused predecessor/FDE/GNU tests and rustfmt passed. The repository-checks archive preserves exact commands, outcomes and streams, with installed GNU binutils and rustup explicitly first on PATH.

## Independent review

A separate reviewer re-read the complete source/proof, derived all 24,730 expectations with signed-half partitions and explicit bit-filled sign extension, and independently parsed all 121,299 FDEs and 80,300 RELAs. Both leaf bodies, four full callers, actual E8 boundaries, the E9 tail and the three exact LLVM display joins were authenticated. The reviewer also reran all 43 structural controls. Witnesses distinguish 1,637 negative tail-mismatch sign extensions from 1,763 negative equality-path zero extensions and show admitted missing-unused-field paths. The parent replay reproduced the exact independent report.

The review script initially selected the wrong caller export for one display audit; its prior source and correction are retained separately in reviewer-script-fix.json. Target source, original expectations and frozen inputs were unchanged. No independent native replay or exhaustive input enumeration is implied.
