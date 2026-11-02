# RE-004: strict three-digit parser with complete return/admission relation

This adds a safe `no_std` Rust reconstruction of complete node94
`[0x1683670,0x16836c5)`. The foundation-three-digit-ascii-parse packet
established the static rule; this contribution supplies the full-domain
RAX proof, a callable source component, independently frozen expectations
and native qualification. It preserves full64 length selection, leading
zero rejection and the requirement for all three bytes before digit
rejection. A missing required prefix is a distinct new safe refusal.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The reference gitlink stays
`999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred upstream source was
read or copied. OpenAI / Codex authored this work; the exact runtime model
identifier is not exposed. New source and prose are MIT.

## Result and evidence

For any length other than three, full RAX is zero with no input read.
For length three, exactly the 900 ASCII words `100` through `999` return
their numeric value. Every other readable triple returns zero. The safe
API admits arbitrary supplied slices and u64 lengths, requires a complete
three-byte prefix only on the length-three path, and ignores extra bytes.
The explicit native length differs from the supplied prefix length.

[PROOF.md](PROOF.md) derives all byte preimages, harmless tens truncation,
full-register zero extension and source bounds. Original correspondence
assumes stable ordinary readable data for required bytes and valid code
and return control. The API does not reconstruct native pointers, faults,
other registers, flags or the calling convention.

All 85 body bytes, thirty instructions, separate padding and actual FDE/CIE
are locked. GNU, LLVM and Capstone agree. The sole E8 candidate at
`0x1682606` is instruction-boundary qualified in the complete 1,301-byte,
318-instruction caller. E9 and naming relocation scans are empty; every
one of 80,300 RELA records is checked for body/padding overlaps. This is
not a complete indirect-reference census or a reconstruction of the caller.
All 27 structural corruptions reject under optimized Python.

## Independent expected values and validation

Before Rust existed, a finite dictionary of decimal strings for 100..999
provided expected values. It uses exact byte-word membership, independently
of the source's range predicates and weighted arithmetic. Frozen source
SHA-256 is
`045647e75a38e4ca099dd719d330a162541bd273be10259192684e601cd7188b`.
The 227,140 cases cover every value pair for each pair of byte positions,
all 900 accepted words, leading zeros, all prefix availabilities, high
length bits and every ignored fourth byte. They are not an exhaustive
run of all triples or lengths; the universal argument is in the proof.

All 908,560 observations match across opt0/opt3 and repeat builds, with
identical same-opt library/client/output hashes. Nineteen actual compiled
mutants produce mismatches, including premature rejection of an invalid
first byte, eager prefix checking on unused paths, low32/low8 length
checks, ignored digit predicates and truncated returns. Three unit tests
pass per optimization. Malformed input/descriptor and changed/missing
output controls pass. The lossless archive retains all 160 exact native
command streams, audited against their raw bytes and SHA-256 hashes.
It uses gzip level 1 with mtime 0; no failed native run preceded it.

Eight predecessor tests, rustfmt, doctor, verify, catalogue-check and
reproduce pass. Native source/build/output pins are in
`native-result.json`; exact commands are in `native-commands.json`.
Repository-check streams retain path normalization plus original hashes.

The separate shared baseline reported 15,462 tests in 971 files with
69 skips and exited 2 from three disk-full errors. All 20 affected tests
passed isolated retries. This is not a successful full-sweep rerun,
per-head full-suite result or qualification of skipped Linux cases.

## Reproduce

Use unchanged materialized pins and a new output directory:

```sh
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
python3 -B -m unittest tests.test_foundation_three_digit_ascii_parse -v
python3 -O research/work-items/RE-004-three-digit-parser-rust-94/verify_static.py
python3 -O research/work-items/RE-004-three-digit-parser-rust-94/verify_rust.py \
  --out work/three-digit-parser-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
```

The observed compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8, SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The host is macOS arm64 with Python 3.14.3, Capstone 5.0.7 and GNU binutils
2.47.20260726. No different compiler/host or original x86 code generation
is qualified. No captured executable or instruction emulator was run.
Original byte identity, source-level function identity, whole-node
equivalence, component gates and hosted CI success are not claimed.
Prior evidence, pins, catalogues and progress stay intact.
