# RE-004: node94 modulo-index lookup with closed signed-tail hash

The prior `foundation-modulo-index-byte-94` packet left the called hash helper
and Rust implementation unresolved. This contribution closes that call at the
wrapper's fixed seed and implements both functions in independent safe Rust.
The final 1–3 input bytes contribute signed values; treating them as unsigned
changes 56,333 frozen hash results. The wrapper then selects a table byte using
the unsigned u16 remainder plus the zero-extended low32 input index.

Target node94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23`. No inferred unlicensed source was
read or copied. New code/docs are independently authored under MIT; target
bytes/disassembly retain the artifact's rights. Existing source, evidence,
reference pins, catalogues and progress gates are unchanged.

## Complete static scope

| Role | ELF VA interval | Bytes | Instructions |
|---|---|---:|---:|
| Wrapper | `0x538c820..0x538c859` | 57 | 21 |
| Closed helper | `0x5422e70..0x5422ef5` | 133 | 42 |
| Incoming caller | `0x535be50..0x535c4ab` | 1,627 | 374 |

GNU, LLVM and Capstone agree on the full instruction bytes/boundaries. The
wrapper's only call at `0x538c83c` targets the fully bound helper; the helper
has no calls. All five helper branches and both returns are internal and
locked. FDE/CIE records, complete raw bodies and wrapper/helper padding (7/11
INT3 bytes) are retained. The whole-text E8 candidate scan finds the single
wrapper callsite `0x535bea9`, aligned in the full caller FDE. All 80,300 RELA
records are checked for protected-code writes and entry naming. Seventeen
structural corruption controls reject below the whole-file identity gate.
This does not constitute an indirect-xref census or reconstruct the full caller.

The hash uses factor 0xc6a4a793 and seed 397. Complete little-endian words pass
through wrapping add/multiply and XOR with a logical shift by 16. Remaining
bytes are individually sign extended, shifted by 0/8/16 and added modulo
2^32; only a nonempty tail receives the final multiplication and shift-by-24
fold. The wrapper divides the resulting u32 by a zero-extended word, discards
the quotient and returns a zero-extended selected byte. These are observations
from complete bytes; original names, types and application meaning are unknown.

## Domain and proof

The [proof](PROOF.md) covers every admitted length and byte value by induction
over complete words plus all four tail-length cases. It explicitly requires
`input_base + input_length + 4 <= u64::MAX` to cover lookahead pointer formation,
including empty input. A nonwrapping readable span alone would not establish the
unsigned pointer-loop comparisons near u64 wrap. Descriptor/divisor/table reads
must also be valid ordinary stable nonwrapping memory. Read-only aliases are
allowed; neither helper writes data. Original pointer ABI, faults, concurrent
mutation, code/control aliases, other helper seeds and caller purpose are excluded.

The library has no artificial input-length cap. The harness uses up to 256
input bytes and 512 table bytes. `ZeroDivisor` and `TableBounds` are new safe
refusals: they do not imitate native #DE or memory-fault behavior. Normal-return
correspondence requires a nonzero divisor and an accessible selected table byte.
No whole-node, compiled-byte identity or acceptance-gate claim is made.

## Independent expectations and actual native runs

Before any Rust source existed, `oracle.py` froze 79,056 records using integer
polynomial word sums, ring arithmetic and a separate signed-tail sum. It does
not decode or emulate instructions. All 65,536 two-byte tails are included,
every 0..256 input length appears, all byte values occur at each position in
three-byte tails with different prefixes, and boundary/seeded cases exercise
index high bits, divisor values and exact table endpoints.

Per build, 74,188 records have successful lookups, 1,150 have ZeroDivisor and
3,718 have TableBounds. The input-only client also emits the helper's full u32
hash, so modulo reduction or coincident table values cannot hide wrong hashes.
The library/client build and run at opt0 and opt3, each repeated, produce zero
mismatches over 316,224 records. Within each optimization, library, executable
and stdout hashes repeat exactly. Three Rust unit tests pass per optimization;
partial input is rejected before output. No output normalization is applied.

All 15 separately compiled wrong sources exit normally and produce mismatches.
Thirteen have witnesses among successful lookup cases, including signed-tail
(53,792), omitted length mixing (74,112), big-endian complete words (4,585),
unconditional tail finalization (1,841), wrong index high bits (67,323), and
truncated divisor (69,017). Those counts are cases with the original successful
lookup whose full emitted observation changes; the observation includes hash,
status and byte, so a hash difference need not imply a changed selected byte.
Two controls concern only new refusal cases: signed index arithmetic changes
117 bounds-refusal results, and changing the zero-divisor error kind changes
1,150. They are not advertised as target normal-return witnesses.
`native/result.json` records these denominators, source/artifact hashes and
first counterexamples. Two comparator controls detect a changed row and a
missing byte. `native/streams.json.gz` losslessly retains all 132 actual
stdout/stderr streams with content hashes and deduplicated payloads.

Independent read-only review recomputed all 79,056 fixtures with a different
byte-lane/sign-debt formulation, rehashed the target and checked complete
bodies/FDE/CIE records. It requested the explicit lookahead premise now in the
proof; no Rust or frozen oracle change was needed. `peer-review.txt` binds the
reviewed source hash. Native verification ran with Python `-O`, and every
evidence guard uses explicit exceptions.

## Reproduction and limits

From repository root with pinned artifacts materialized:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-modulo-index-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-modulo-index-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-modulo-index-rust-94/verify_rust.py \
  --out work/modulo-index-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
python3 -B -m unittest tests.test_foundation_modulo_index_byte -v
rustfmt +1.94.1 --check --edition 2024 src/node94-modulo-index/*.rs
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-004-modulo-index-rust-94 && shasum -a256 -c MANIFEST.sha256)
```

`--out` must be fresh. The qualified host is macOS ARM64, Python 3.14.3,
rustc 1.94.1 commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8;
actual compiler SHA-256 is
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The direct-rustc rlib/client build has no external dependencies or lockfile.
GNU binutils 2.47.20260726, Apple LLVM 17 and Capstone 5.0.7 provide static
checks. Exact version/byte pins intentionally require the recorded toolchain;
other-host qualification must be labeled separately. Source/compiler/linker
hashes, flags and commands are retained. All 26 focused legacy tests, rustfmt, doctor, verify, catalogue-check and
reproduce passed. Their results are archived in `repository-checks.json.gz` with path-only redaction.

The parent's shared full legacy sweep remains separate and unfinished; neither
it nor hosted CI is claimed as passing here. No captured code or instruction
emulator was run. This resolves the fixed-seed helper closure left by the prior
packet; other helper callers, ABI and full component recovery remain open.
