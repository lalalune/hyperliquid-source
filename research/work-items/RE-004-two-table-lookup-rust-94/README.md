# RE-004: node94 two-table signed lookup in safe Rust

This reconstructs the complete leaf `[0x5560660,0x55606a8)` as an
independently authored safe `no_std` value component. The predecessor
`foundation-two-table-lookup-94` bound its 72-byte instruction rule but
explicitly left Rust, runtime table contents and valid index domains open.
The new API accepts the actual runtime byte image and load bias, preserves
all low32 gates/sign extensions and wrapping effective addresses, and
returns the full selected qword in RAX. It introduces explicit safe refusal
for a wrapping image description or an unavailable selected eight-byte load.
It does not invent a table length from the distance between linked bases.

- Task/component: RE-004 / foundation, a bounded independent value component.
- Target: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Branch base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` from refreshed
  origin/main. Input/submodule pins, catalogue and progress gates are unchanged.
- Scope: `src/node94-two-table-lookup` and this packet only.
- Authorship: OpenAI Codex; exact model identifier unavailable. New code/docs
  are MIT. No inferred reference implementation was read or copied.

## Exact behavior and closure

The first raw input's low32 value x selects the second path only when
x belongs to {3,4,5} and the second input's low32 value is 1. With y the
signed low32 third input, that path reads at
`(load_bias + 0x576db20 + 8*(x-3) + 24*y) mod 2^64`.
All other inputs read at
`(load_bias + 0x576d9e0 + 8*signed32(x) + 80*y) mod 2^64`.
The selected eight bytes form a little-endian u64; there is no returned
boolean, value narrowing or follow-up dereference.

[PROOF.md](PROOF.md) proves the full register-domain partition, sign extension,
index bounds, modulo address arithmetic, full RAX and slice admission. It
also distinguishes original normal-return assumptions from the new API.

`static.json` closes all 72 bytes/21 instructions, both branches/returns,
the internal five-byte NOP, FDE/CIE, following padding and next FDE. Full
GNU/LLVM exports and Capstone agree on instruction boundaries. The unique
raw E8 candidate `0x55c8554` is an instruction in the complete 1,747-byte,
460-instruction caller FDE `[0x55c84f0,0x55c8bc3)`. No E9 candidate or naming
relocation was found; this is not a full indirect-reference census.

Both RIP-derived bases are bound to their `.data.rel.ro`/PT_LOAD mappings.
Their first file qwords are zero but each has a RELATIVE relocation: the
runtime sample values are bias+`0x5585670` and bias+`0x55af100`, modulo 2^64.
These are two numeric samples, included in the frozen corpus, not inferred
logical tables. The complete 80,300-record RELA scan closes these two records
and excludes relocation overlap with the leaf and retained caller. Selected
runtime contents elsewhere are supplied by the image; no claim is made to
recover every possible selected byte as a constant from the captured file.
The leaf has no helper calls or external import dependency.

## Frozen expectations and native qualification

`oracle.py`, `static.json`, inputs and expected results were frozen and
hash-bound before the Rust directory existed. `frozen.json` records that
ordering and their hashes. The oracle uses literal gate membership,
unbounded affine byte arithmetic and an immutable numeric-address map;
the Rust uses wrapped subtraction, staged sign extension/index arithmetic
and checked slice ranges. The input-only client receives raw input records
and emits results, with no expected stream, oracle import or captured code.

The 12,929 cases include 10,554 admitted reads, 57 invalid image ranges and
2,318 unavailable selected qwords. Dense first/mode/row combinations exercise
both formulae and overlapping reachable image addresses; signed endpoints,
ignored upper halves, all 64 one-bit register positions, runtime-base and
effective-address wrapping, exact range boundaries, unaligned reads and
high-bit loaded values are covered. This is finite evidence supporting the
full-domain proof, not exhaustive execution of all possible registers.

Final pinned native qualification passed:

- Opt0 and opt3 each compare all 12,929 exact outputs, with zero mismatches;
  repeat runs bring the total to 51,716 full-output observations.
- All 54 compiled wrong-implementation runs are detected: 36 have cases
  where both versions return different admitted values; 18 produce only
  admission differences within these compact images. The latter include
  sign/width errors with enormous address differences, saturating address
  arithmetic and strict endpoint refusals. Actual counts and first witnesses
  are retained per run, including variants with both witness types.
- Three unit tests per profile; malformed/oversized input refusal controls;
  changed-row and missing-row comparator controls all pass.
- Four repeated artifacts (rlib and client per profile) are byte-identical,
  without normalization. Thirty-eight static corruption controls reject
  body, boundary, caller, data and relocation drift with Python `-O`.

`native-result.json` records source/compiler/linker hashes, complete compiler
version, host, inputs, counts and witnesses. `native-commands.json` records
all 186 invocations and hashes of their 372 exact stdout/stderr streams.
`native-streams.json.gz` retains every stream as hash-keyed base64 payloads,
losslessly deduplicated and verified (gzip level 1, mtime 0). The initial
successful qualification was followed only by formatting the verifier's
mutation table; the full final matrix was rerun and is the retained record.
No library, oracle or mutant behavior was changed between those two runs.

## Reproduce

Run from the repository root with the pinned inputs materialized:

```sh
python3 -O research/work-items/RE-004-two-table-lookup-rust-94/verify_static.py
python3 -O research/work-items/RE-004-two-table-lookup-rust-94/verify_rust.py \
  --rustc "$HOME/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc" \
  --out work/two-table-lookup-rust/replay
python3 tools/foundation_two_table_lookup.py \
  --check research/work-items/foundation-two-table-lookup-94/evidence.json
python3 -m unittest tests.test_foundation_two_table_lookup -v
make doctor
make verify
make catalogue-check
make reproduce
```

Use a fresh native output directory. Rustc is the actual 1.94.1
`aarch64-apple-darwin` executable, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The verifier uses edition 2021, explicit target, warnings denied,
codegen-units=1, overflow checks enabled, opt-level 0/3, `/usr/bin/cc`
and a recorded path remap. Native host output is not compared to captured
x86 instruction bytes. No Cargo dependency or speculative lockfile is needed.

The two GNU/LLVM disassemblies were generated directly from the target:

```sh
/opt/homebrew/opt/binutils/bin/objdump -d --insn-width=16 \
  --start-address=0x5560660 --stop-address=0x55606a8 artifacts/node/94/hl-node
/usr/bin/objdump -d --start-address=0x5560660 --stop-address=0x55606a8 \
  artifacts/node/94/hl-node
/opt/homebrew/opt/binutils/bin/objdump -d --insn-width=16 \
  --start-address=0x55c84f0 --stop-address=0x55c8bc3 artifacts/node/94/hl-node
/usr/bin/objdump -d --start-address=0x55c84f0 --stop-address=0x55c8bc3 \
  artifacts/node/94/hl-node
```

GNU binutils 2.47.20260726, Apple LLVM 17.0.0, Python 3.14.3 and
Capstone 5.0.7 were used. `checks-commands.json` and its lossless
`checks-streams.json.gz` preserve the local prerequisite/focused checks,
rustfmt and actual disassembler version output. `checks.json` reports their
completed results: doctor, verify, catalogue-check, reproduce, the predecessor
checker, all 12 focused legacy tests and rustfmt passed. `overlap.json` binds the fresh 149-open-PR, 100-recent-
merged-PR and zero-open-issue selection inventory and current-source check.

## Limits and shared baseline

This preserves the complete stated value relation under stable, ordinary,
valid runtime memory and actual load bias. It does not reproduce hardware
faults, MMIO, concurrent mutation, pointer provenance, flags, all volatile
registers, original stack/ABI control, source-library identity, original
compiler identity or original compiled-byte identity. Numeric test addresses
may describe impossible machine mappings; original correspondence is claimed
only for normally completing reads. All executed code was newly authored
Rust or static analysis tooling, never the captured executable or an emulator.

The separate parent baseline at source base `56c0ec67` attempted 971 files /
15,462 reported tests / 69 skips. Its original `make test` exited 2 solely
for three disk-full errors; all 20 tests in those affected files passed
isolated retry. There was no successful full-sweep rerun. This packet does
not claim a full suite on its own head, qualification of skipped Linux
checks or hosted success. It advances one bounded reconstruction; every
whole-component progress gate remains unchanged and incomplete.
