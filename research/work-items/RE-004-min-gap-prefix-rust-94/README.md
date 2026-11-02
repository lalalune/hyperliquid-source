# RE-004: full-u64 min-gap prefix equality

Component: `foundation`. Target: node #94, Linux x86-64 ELF,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
No inferred reference source was read or copied. New code and documentation
are independently authored under the repository's MIT license.

The prior `foundation-min-cap-gap-94` packet established the arithmetic
sketch but left Rust and the external comparison boundary unresolved.
This packet supplies a safe readonly image component for the complete
87-byte `[0x5430db0,0x5430e07)` helper, proves its full-u64 reduction,
and binds the real memcmp import. All coordinates are link-time VAs
unless explicitly labeled file offsets.

Observed bytes, FDE/CIE records and import metadata are retained in
`static.json` and the unedited GNU/LLVM listings. The name “prefix
equality” describes the proved value relation; it does not recover an
original source type or application purpose. The theorem explicitly
assumes a standard ABI-conforming, readonly, normally returning memcmp.
The captured libc body and runtime symbol resolution remain unmeasured.

## Reproduce

From the repository root, with the pinned artifact materialized:

```sh
python3 -B research/work-items/RE-004-min-gap-prefix-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-min-gap-prefix-rust-94/verify_static.py
python3 -B research/work-items/RE-004-min-gap-prefix-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/min-gap-prefix-rust/replay
python3 -m unittest discover -s tests -p test_foundation_min_cap_gap.py
python3 tools/foundation_min_cap_gap.py \
  --check research/work-items/foundation-min-cap-gap-94/evidence.json
make doctor
make verify
make catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-004-min-gap-prefix-rust-94/SHA256SUMS
```

Use a fresh native output directory. Actual rustc 1.94.1 is pinned by
SHA-256 `b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`
and commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, host/target
`aarch64-apple-darwin`, LLVM 21.1.8. The recipe uses edition 2021,
`-Dwarnings`, `codegen-units=1`, overflow checks on, opt0 and opt3,
explicit `/usr/bin/cc`, and a recorded path remap. Compiler/linker
versions and executable hashes are in `native-result.json`; every
actual build command is in `native-commands.json`. No dependency or
Cargo workspace is needed.

Static exports use GNU binutils 2.47.20260726, Apple LLVM objdump
17.0.0 and Capstone 5.0.7, with Python 3.14.3. `disassembly.json`
retains exact export commands, executable hashes, versions, stdout
hashes and empty stderr. `check-commands.json` records the completed
checks, including two Python hash-seed/timezone settings and `-O`.

## Evidence and implementation

The [proof](PROOF.md) covers all 30 leaf instructions, complete FDE,
adjacent FDEs/padding, 16-byte PLT stub, GOT resolver word, actual
JUMP_SLOT relocation, undefined FUNC symbol, version index/need chain
and libc DT_NEEDED record. All eight direct callers are confirmed in
their complete FDEs: 18,286 bytes and 3,745 decoded instructions.
Callers supply boundary context only. All 80,300 RELA records and a
full `.text` E8/E9 candidate census are checked; indirect entry paths
and caller application semantics are outside this claim.

The [Rust library](../../../src/node94-min-gap-prefix/lib.rs) accepts
actual immutable memory and returns full numeric RAX. It preserves
unsigned lengths, wrapped field addresses, the zero-minimum read
gate, arbitrary readonly aliases and complete prefix reads before
the final length decision. Invalid memory becomes an explicit new
safe refusal. The API has no arbitrary length cap or unsafe code.

`oracle.py`, `static.json`, input/output streams and `frozen.json`
were fixed before the Rust directory existed. The oracle uses
unbounded squared byte differences and the bounded signed modular-gap
predicate. Rust uses slice equality and the separately proved unsigned
ordering reduction. The separate input-only client consumes memory
descriptors, never expected values or a supplied memcmp return.

## Completed results

| Check | Observed result |
|---|---|
| Static binding and structural corruptions | 47/47 rejected; normal and Python `-O` identical |
| Frozen native cases | 69,063/69,063 exact per opt0 and opt3 |
| Repeated native cases | 69,063/69,063 exact per repeated profile |
| Raw repeated artifacts | 4/4 rlib/client pairs byte-equal, no normalization |
| Library unit tests | 3/3 per profile |
| Compiled wrong implementations | 21/21 per profile, 42 total detected |
| Client malformed inputs | partial records and oversized image rejected before output |
| Comparator controls | changed row detected; missing row rejected |
| Existing focused suite/checker | 15/15 tests and packet check passed |
| Repository checks | doctor, verify, catalogue-check, reproduce passed |

The corpus includes all 65,536 one-byte pairs, longer prefixes with
differences in each region and embedded NULs, signed/low-word/high-bit
length boundaries, field/payload aliases, exact endpoints and all four
safe errors. Normal results: 67,576; safe refusals: 1,487. The proof
covers the admitted domain beyond the finite corpus.

Native controls compile wrong min/width/order, zero paths, low32 gap,
equality, first/last-byte, NUL, pointer, omitted-byte and full-RAX
variants. Seventeen controls have admitted-value witnesses. The four
admission-only controls test early length rejection, eager zero-path
pointer reads, strict endpoints and saturating field addresses; they
are not counted as original-value counterexamples. Full mismatch
counts and first witnesses are retained in `native-result.json`.

`native-streams.json.gz` retains all 300 command streams from 150
commands in a deterministic, lossless base64 archive, deduplicated by
SHA-256. `check-streams.json.gz` similarly retains all 18 check streams.
Decode each payload, verify its hash, then resolve each stream label
through the `streams` map; command records bind labels, byte counts,
hashes and exit statuses. All bindings were verified after packaging.
No expected failure or raw comparison was discarded. The successful
native matrix required no source/control correction during execution.

`scope.json` records the live overlap check: 125 open PRs, zero open
issues, 100 recent merged PRs and current source, with no matching
claim. Broad remote inventories remain ignored local work records.

This is a host value reconstruction, not original compiled-byte
identity or a System V replacement. No captured code or emulator ran.
No full repository test-suite or hosted-CI success is claimed here;
the parent owns that separate validation. No progress gate, byte-window
registry, imported evidence or pin is changed. The remaining concrete
question is runtime memcmp implementation/resolution correspondence;
this packet establishes the explicit contract boundary without claiming
that missing runtime evidence.
