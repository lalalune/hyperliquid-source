# RE-004: node94 signed i128 to binary64 bits

This reconstructs the complete integer conversion leaf at ELF VA
`[0x565f4f0,0x565f598)` as independent safe Rust. It resolves its sign/magnitude,
normalization, guard/sticky rounding and zero behavior instead of assigning a
source identity from a nearby symbol. The full signed input domain maps to
nearest-even binary64, independent of MXCSR. Original ABI and compiled-byte
identity remain unestablished.

- Component: foundation; bounded RE-001 static qualification and RE-004 arithmetic.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`, unchanged.
  Its unlicensed inferred implementation was not read or copied.
- New library: [lib.rs](../../../src/node94-i128-f64/lib.rs).
- Full derivation: [PROOF.md](PROOF.md).

## Complete static evidence

The 168-byte body has 45 instructions, no call or branch, no explicit data
memory operand, and one terminal RET. Its SHA-256 is
`9ad0f5b92a2985f8e1bf622bc4bf0a395637cb73463db282a38913ac51ee9362`.
GNU and LLVM listings preserve every byte and agree on all boundaries; a
fresh Capstone decode agrees too. No bytes or operands are normalized.
The unique overlapping FDE is VA `0xfbda88`, CIE VA `0xce1518`; complete raw
records and the eight following padding bytes are checked separately.

The RELATIVE relocation at file offset 1,793,744 binds slot `0x576f7c0` to the
entry. All 80,300 RELA records are scanned for other entry naming and protected
writes. The leaf has no other explicit data dependency; immediate constants
are bound as part of its complete body.

A whole-text pattern scan finds no direct E8 candidate and seven RIP-relative
indirect CALL candidates through that slot. Each is confirmed as an instruction
start in a complete caller FDE decode:

| Caller FDE | Bytes / instructions | Call sites |
| --- | --- | --- |
| `0x145f530..0x145fce7` | 1,975 / 432 | `0x145f655` |
| `0x1f98cc0..0x1f99477` | 1,975 / 432 | `0x1f98de5` |
| `0x3cf7360..0x3cf7b17` | 1,975 / 432 | `0x3cf7485` |
| `0x4b00950..0x4b011b6` | 2,150 / 464 | `0x4b00b0e` |
| `0x4ead680..0x4ead933` | 691 / 170 | `0x4ead6d7` |
| `0x4f677a0..0x4f688a2` | 4,354 / 1,053 | `0x4f6798c`, `0x4f67efd` |

Caller hashes, raw FDE/CIE records and exact call bytes are in [static.json](static.json).
This is a bounded pattern inventory and linear decode, not a complete xref
census, caller control-flow proof or recovered caller purpose. The target
image remains the source for complete caller bytes; no copied executable
caller body is introduced into the implementation.

Seven in-memory corruptions test body rounding/sign, FDE extent, CIE encoding,
slot addend, padding and a caller displacement below full-target digest
admission. All are rejected. These are static checks, not executed mutants
of the captured binary.

## Behavior and independent expectations

The new API accepts an i128 and returns raw binary64 bits. The target's SUB/SBB
pair forms an unsigned magnitude even for the signed minimum. BSR-based
normalization and its compressed guard/sticky word implement nearest-even
rounding. Sign and exponent are assembled with integer operations. A rounding
carry increments the exponent, including positive `i128::MAX` rounding to
exactly `2^127`; negative `i128::MIN` already represents `-2^127` exactly.

For zero, BSR destinations are architecturally undefined. The proof shows that
shifting all-zero words, clearing R9 and conditionally replacing the exponent
base makes both arbitrary intermediate destinations irrelevant. The result
is positive zero. No unchanged-destination assumption or zero exclusion is
needed.

[oracle.py](oracle.py) was frozen before Rust. It binary-searches ordered
binary64 codes using exact rational comparisons, then chooses the nearest
candidate with even-code ties. It uses neither floating conversion nor the
Rust normalization/remainder algorithm. [frozen.json](frozen.json) binds its
source and decompressed input/output hashes. The 10,608 distinct raw inputs
include 5,297 positive, 5,310 negative and one zero; powers and neighbors across
all 128 bit positions, both signs at exact halfways and adjacent integers,
carry boundaries, signed endpoints and 4,096 deterministic varied inputs.

The full-domain proof and finite implementation checks have separate roles.
A 10,608-case corpus does not exhaust the `2^128` possible inputs.

## Actual new-Rust validation

The actual rustc 1.94.1 executable is SHA-256-pinned in the verifier, along with
its reported commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`. The `/usr/bin/cc`
linker is selected explicitly and its hash/version recorded. Host is macOS
arm64; Python 3.14.3, Capstone 5.0.7, GNU objdump 2.47.20260726 and Apple LLVM
objdump 17.0.0 supply the other tools. This identifies the research build,
not the original compiler.

Opt0 and opt3 each run twice, matching all 10,608 expectations: 42,432 native
comparisons, zero mismatches. Repeated rlib, client and output hashes agree
within each optimization. Both unit tests pass at each optimization. The
client receives only inputs, never expectations; incomplete input is rejected
before any output.

| Compiled wrong variant | Mismatches / 10,608 |
| --- | ---: |
| Halfways away from zero | 446 |
| Halfways toward zero | 444 |
| Ignore lower sticky bits | 1,912 |
| Lose sign | 5,310 |
| Clamp magnitude to u64 | 8,875 |
| Narrow retained significand to u32 | 9,647 |
| Wrong exponent bias | 10,607 |
| Discard rounding carry into exponent | 582 |

Two independent comparator controls detect one changed row and reject a
missing byte. All 90 command stdout/stderr streams are retained losslessly in
[streams.json.gz](streams.json.gz), using content-addressed base64 payloads.
Raw lengths and hashes, commands, source/fixture/compiler identities and first
mutant witnesses are in [result.json](result.json) and [commands.json](commands.json).

The first verifier attempt stopped because a deliberate clamp mutant used an
unsupported const `Ord::min`. Correct builds had already matched; the mutant
had not executed. Only that mutation was rewritten with an explicit condition,
then the complete verifier passed in a fresh directory. The original diagnostic
is retained in [validation-harness-correction.json](validation-harness-correction.json)
and is not counted as behavioral negative evidence.

A separate reviewer found no blocker after reading the complete assembly, proof,
oracle and Rust. The reviewer independently ran optimized-Python static checks
and regenerated all 10,608 frozen oracle rows byte-for-byte; the native matrix
above is the parent run, not an additional reviewer run.

Local `make doctor verify catalogue-check reproduce` passes. The parent task
runs one shared full repository sweep, which remains pending; no full-suite,
hosted-CI or target/Linux build success is claimed here. Existing import pins,
progress gates and selected byte windows are unchanged.

## Reproduce and limits

From the repository root with pinned inputs materialized:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-i128-f64-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-i128-f64-rust-94/verify_rust.py \
  --out work/i128-f64-review \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)"
rustfmt +1.94.1 --check src/node94-i128-f64/lib.rs src/node94-i128-f64/input_only_driver.rs
make doctor verify catalogue-check reproduce
```

The native verifier requires a new output directory and the recorded actual
compiler identity. No Cargo workspace, third-party package or build script is
needed. Original symbol/crate provenance, calling-convention integration,
register/flag preservation, caller meaning, runtime environment faults and
compiled target-byte identity remain unknown. No captured code or instruction
emulator ran. The next bounded question is how the confirmed callers produce
the two input words and consume the converted value.
