# RE-004: full byte-indexed OR family

This adds a safe `no_std` Rust value/field projection for three complete
node94 functions: `[0x15625e0,0x15625f5)`, `[0x1566100,0x1566115)` and
`[0x1568bb0,0x1568bc5)`. Each selects a measured u32 with the low input byte,
ORs that word into a field, and returns the selected word in full RAX.
The earlier foundation-flag-or packet characterized the first twenty
single-bit words; this contribution binds all 256 reachable dword indices
for each member and proves their full numeric and field relation. These
three related functions are kept in one contribution.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The reference gitlink stays
`999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred upstream source was
read or copied. OpenAI / Codex authored the work; the exact runtime model
identifier is not exposed. New implementation and prose are MIT.

## Measured boundary and complete relation

All 63 code bytes, fifteen instructions, three actual FDE/CIEs and separate
padding are bound. GNU, LLVM and Capstone agree on the complete functions.
There are no outgoing dependencies. The three readonly 1,024-byte read
windows overlap into 1,448 bytes/362 words. Those measured words are stored
once in Rust. They are reachable windows, not asserted source table extents
or evidence of actual caller index reachability.

[PROOF.md](PROOF.md) derives the exact member descriptors, zero-extended
RAX, load-biased RCX and wrapped field address. The old field becomes its
bitwise OR with the selected word; RAX remains that selected word. Every
u64 index, load bias and object address and every u32 old field is admitted
by the scalar projection. Original-memory correspondence requires the
bound stable readonly windows, a valid ordinary writable field, disjoint
code/table/control storage and valid return control. Numeric addresses
reported by this API are not dereferenced by Rust or promised as realizable
OS mappings. RET's RSP/control transition, flags and the original ABI are
outside the projection.

The twelve symbol-zero RELATIVE entry records and raw zero slots are
bound. All 80,300 RELA records are checked for conflicting writers,
including other-addend and partial overlaps. Full E8/E9 pattern scans
find no direct candidates; short/indirect transfers and slot consumers
remain outside that census. No function/type/field identity or flag meaning
is inferred from these observations.

## Independent expectations and qualification

Before Rust existed, the oracle, static facts and 98,880 input/expected
records were frozen. It selects bytes using positional base-256 arithmetic
and computes the union by summing occupied binary digits. Rust uses one
u32 table lookup and OR. The corpus covers every index of every member,
all old-field bit bases and complements, ignored upper index bits and
address-wrap boundaries. Its counts and exact fixture hashes are in
`frozen.json`; the oracle source hash is
`d7d00b7ecb77aaa9849042433c1f91c58e98e582144d2d303e9a2a478ecd6806`.

All 395,520 observations match across opt0/opt3 and repeat builds, with
identical same-opt rlib/client/output hashes. Nineteen actual compiled
mutants produce mismatches. Three unit tests pass in each optimization;
malformed framing, invalid member and changed/missing-output controls
reject as intended. Forty structural corruptions reject under optimized
Python. `native-streams.json.gz` losslessly retains all 160 exact native
command streams; every payload was checked against its original bytes
and SHA-256. Compiler, linker, source, command, build and output hashes
are in `native-result.json` and `native-commands.json`.

An independent reviewer manually parsed ELF segments and RELA, verified
all 362 source words and 768 window entries, and rederived every frozen
output using x+y-(x&y). The review includes source, proof and the explicit
RAX/RCX/control boundary. `verify_independent.py` preserves those checks
with only repository/output path adaptation; its replay reproduces all
98,880 tuples. The peer record retains both script hashes. A first passing
native run is retained locally; after the source comment and proof were
clarified to exclude RET/RSP, the complete native qualification was rerun
against the final source. Implementation and frozen expectations did not
change.

Sixteen focused predecessor tests, rustfmt, doctor, verify,
catalogue-check and reproduce pass. Exact streams are retained in
`repository-checks.json.gz`. A separate shared baseline reported 15,462
tests in 971 files with 69 skips and exited 2 from three disk-full errors.
All 20 affected tests passed isolated retries. This is not a clean original
sweep, a per-head full-suite result or qualification of skipped Linux tests.

## Reproduction

With the unchanged materialized target pins and rustc 1.94.1:

```sh
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
python3 -B -m unittest tests.test_foundation_flag_or -v
python3 -O research/work-items/RE-004-flag-or-family-rust-94/verify_static.py
python3 -O research/work-items/RE-004-flag-or-family-rust-94/verify_independent.py
python3 -O research/work-items/RE-004-flag-or-family-rust-94/verify_rust.py \
  --out work/flag-or-family-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
```

The actual compiler SHA-256 is
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`,
commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8. Observations
are on macOS arm64 with Python 3.14.3, Capstone 5.0.7 and GNU binutils
2.47.20260726. This does not qualify a different compiler or native x86
code generation. No captured code or emulator was run. Original byte
identity, whole-node equivalence, component gates and hosted CI success
are not claimed. Prior evidence, pins, catalogues and progress stay intact.
