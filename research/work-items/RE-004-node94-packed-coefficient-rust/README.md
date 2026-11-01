# RE-004: normalization and all-count packed-coefficient closure

This packet reconstructs complete node #94 entries `[0x565ec20,0x565ecb2)`
and `[0x565ecc0,0x565ed4d)` in independently authored no_std Rust: 146+141
body bytes, one complete normalization-to-loop closure. It resolves shared
high-limb selection, preserved low 31 bits, masked double-word shifts, arbitrary
pair/count evolution, full packed 64 coefficient wrapping, and thirteen raw
register observations. No numeric input is excluded or presumed reduced.

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base source: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Component: bounded foundation arithmetic under RE-004. Addresses are original
ELF VAs. No original source symbol, mathematical operand meaning, neighboring
function, node-wide ABI/build or progress gate is claimed. Imports and pins
remain unchanged; no unlicensed inferred implementation was read or copied.

## Complete relation and universal acceleration

`PROOF.md` closes both entries and their tail edge. The normalizer selects the
highest jointly nonzero rank among limbs 3/2/1, uses its shared BSR-derived
SHLD count, and combines the shifted upper 33 bits with the original low 31.
If those upper ranks are zero, the BSR destination is undefined only
transiently: defined ZF and subsequent CMOVE replace that value before NEG,
SHLD or return observation. The resulting fallback is defined on all inputs.

The loop uses unsigned ordering and the saved old X parity to choose a swap/
subtraction, halves X, and evolves two biased coefficients modulo 2^64. For
every nonzero X, `bit_length(X)+bit_length(Y)` decreases by at least one,
so at most 128 such passes occur without an odd-Y or reduced-input assumption.
Once X=0, only one coefficient changes, as `K+(V-K)*2^r mod 2^64`.
This handles every low 32 count, including zero's 2^32 passes, while retaining
the coefficient from the *penultimate state* for the final R14 observation.
Final coefficient halves are zero-extended before 64-bit bias subtraction.

The direct entry writes eleven reported GP registers and preserves the
supplied R9/R11. The normalizer writes those two as well. Original memory
reads are assumed stable and successful; neither body writes memory. Pointer
faults, concurrency/volatile storage, flags, return control and the custom
machine ABI are excluded from the safe value projection. This closure is
distinct from fixed 30-step function `[0x565f2e0,0x565f390)` and does not
reclaim that prior implementation.

## Static closure and caller evidence

`static-lock.json` authenticates both complete bodies and their actual FDE/CIE
records, separately bounds 14/19 bytes of alignment context, and retains the
complete 2,155-byte caller `[0x565df20,0x565e78b)`. Fifteen incoming E8
candidates to the normalizer are confirmed at instruction boundaries there.
The only EB candidate into the loop is the normalizer's tail at 0x565ecae;
E9 scans are empty. Caller semantics and other callees remain context only.
The two-entry closure has no further callee, store or table/RIP-relative data
dependency. All 80,300 RELA records were scanned for naming addends and
body/padding overlap writers; none match. This is not a whole-program xref
census. Complete GNU disassembly, Capstone rows and selected GNU frame records
are retained without interpreting nearest-symbol annotations as source names.

## Frozen oracle, detected gap and explicit supplement

The original oracle SHA-256 is
`5b141232aeb0fa67fc07951cb7293c30afb715a9fbade3dc7c095cabc561bc82`.
It was frozen before Rust with 6,788 cases: 4,242 direct-entry and 2,546 normalized.
Python computes normalization through whole-integer prefix quotients and
composes unbounded integer 3x3 affine matrices for coefficient steps. Rust uses
word-level leading-bit selection and wrapping-u64 updates. The independent
algebraic proof connects them; neither executes captured instructions.

The first qualification's `wrong_lower_limb` mutant produced zero mismatches.
The original corpus lacked small high limbs at rank 2/3 combined with high bits
in the immediately preceding limb; random high limbs usually selected too
small a shift for those bits to survive the low 31 mask. This was a fixture
coverage failure, not a source change. Original oracle, freeze and Rust bytes
remain unchanged.

An explicitly **post-Rust** supplement adds 2,304 such boundary cases, generated
by the unchanged frozen oracle. `supplemental/SUPPLEMENT-FREEZE.json` records
its actual timing, Rust/source hashes and separate raw fixture hashes. It is
not represented as pre-Rust evidence. The final corpus has 9,092 cases: 4,242
direct-entry and 4,850 normalized. All 64 shift counts and all four selected
ranks are represented. The proof includes a concrete R9 witness where using
a0 instead of the preceding a1 loses bit 31 after a rank 2/shift 63 selection.

`observed/initial-control-failure.json.gz` retains original process stdout/
stderr and the first validator source. That validator kept native stdout in
memory until successful completion, so the unsuccessful run's native stdout
was no longer available. The archive therefore labels its recovery honestly:
a separate replay of the exact still-existing mutant binary returned the
unchanged original expectations, confirming zero mismatches. This replay is
not presented as original-run byte provenance. The packet validator now also
archives streams immediately when a compiled control is ineffective.

## Final native qualification and retention

Pinned installed rustc 1.94.1 built opt0/opt3 twice each, with overflow checks,
panic abort and warnings denied. All 9,092 final cases matched in each of four
builds: 36,368 case observations, with no API refusals. Same-option library,
client and stdout hashes repeated exactly. Sixteen compiled wrong variants
completed normally and all caused mismatches; `wrong_lower_limb` now has 588.
Other controls exercise count width/zero, parity/equality, packed carry/bias,
stable-tail absorption and final temporaries, sign extension, normalizer
rank/low-bit selection and zero-count shifts. All 56 structural controls were
rejected. A corrupted expected row produced exactly one mismatch; malformed
client input exited 2 without stdout.

`observed/results.json` and `selected-controls.json` retain counts and actual
counterexamples. `raw-streams.json.gz` losslessly stores 134 exact final command
stdout/stderr streams, with exact raw hashes, using base64 or XOR against the first
native stdout before compression. This is storage encoding, not result
normalization. The audit reconstructs every stream, checks hashes/exits,
recounts mismatches and validates the retained failure/replay evidence. The
very large GNU frame stdout is explicitly retained as selected original
CIE/FDE records only. Readable disassembly removes only line-ending whitespace;
exact GNU stdout remains in the archive.

## Reproduce and limits

From repository root with installed Python 3.14.3, Capstone 5.0.7, GNU binutils
2.47.20260726 and rustc 1.94.1:

```sh
python3 -O research/work-items/RE-004-node94-packed-coefficient-rust/validate.py \
  --output work/node94-packed-coefficient/recheck
python3 -O research/work-items/RE-004-node94-packed-coefficient-rust/verify_recorded.py
shasum -a 256 -c research/work-items/RE-004-node94-packed-coefficient-rust/MANIFEST.sha256
```

The validator authenticates static target bytes, regenerates and byte-compares
both separately frozen corpora, then builds/runs only new Rust. Exact compiler
identity, executable hash, platform, commands and outputs are retained. This
is macOS arm64 native qualification, not captured Linux code execution,
instruction emulation or target machine-code equivalence. No dependencies or
invented Cargo workspace/lockfile are introduced.

`make doctor verify catalogue-check reproduce`, 24 focused ELF/FDE/GNU tests,
rustfmt and archive/manifest checks passed; their output is retained separately. Shared baseline: 971 files/15,462 tests/69 skips; original
make exit2 was solely three disk-full errors, all 20 affected tests passed
isolated retries. That is not a fresh full-suite result on this head, skipped
Linux-native qualification or hosted CI success. No progress gate is advanced.
A remaining bounded question is how the retained caller constrains the pair
and consumes the decoded coefficients; this all-input relation assumes no answer.

Authorship: OpenAI / Codex client. The exact runtime model identifier is not
exposed and is not invented.
