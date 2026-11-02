# RE-004: three-path pointer arithmetic return pair

Component: `foundation`. Target node #94 is the 91,774,280-byte Linux
x86-64 ELF with SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
No inferred reference implementation was read or copied. New code and
documentation are independently authored under the repository MIT license.

The predecessor `foundation-multi-path-pointer-arithmetic-triple-94`
packet established a static rule but left Rust unimplemented. This
contribution reconstructs the complete `[0x50fa260,0x50fa2b2)` leaf as
a safe readonly image API. It preserves full RAX/RDX, unsigned flag
classes, wrapped addresses and arithmetic, and the exact branch-dependent
field requirements. It also binds the actual relocated entry slot.
All addresses below are link-time ELF VAs unless labeled file offsets.

Observed instructions and metadata are in `static.json` and the complete
GNU/LLVM listings. “Pointer arithmetic return pair” describes the numeric
relation, without asserting that any returned value is a valid pointer
or identifying original source types. [PROOF.md](PROOF.md) covers the
complete u64 arithmetic and admitted-memory domain.

## Reproduce

From the repository root with the unchanged pinned artifact materialized:

```sh
python3 -B research/work-items/RE-004-pointer-arithmetic-pair-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-pointer-arithmetic-pair-rust-94/verify_static.py
python3 -B research/work-items/RE-004-pointer-arithmetic-pair-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/pointer-arithmetic-pair-rust/replay
python3 -m unittest discover -s tests -p test_foundation_multi_path_pointer_arithmetic_triple.py
python3 tools/foundation_multi_path_pointer_arithmetic_triple.py \
  --check research/work-items/foundation-multi-path-pointer-arithmetic-triple-94/evidence.json
make doctor
make verify
make catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-004-pointer-arithmetic-pair-rust-94/SHA256SUMS
```

Use a fresh native output directory. The actual rustc 1.94.1 executable
is pinned by SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`
and commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, with
`aarch64-apple-darwin` host/target and LLVM 21.1.8. The native recipe uses
edition 2021, warnings denied, one codegen unit, overflow checks on,
opt0/opt3, explicit `/usr/bin/cc` and a retained path remap. No Cargo
workspace, external dependency or captured execution is required.

Static exports use GNU binutils 2.47.20260726, Apple LLVM objdump 17.0.0,
Capstone 5.0.7 and Python 3.14.3. `disassembly.json` retains exact commands,
versions, tool hashes and raw output bindings. The static verifier also
runs under Python `-O` and different hash-seed/timezone settings.

## Evidence and implementation

The full 82-byte FDE has 20 instructions, two returns and no calls.
Both neighboring FDE/CIE records, fifteen leading INT3 bytes, fourteen
following INT3 bytes and all three internal branch targets are bound.
The backward jump is a join, not a loop. The complete E8/E9 scan finds
zero direct edge candidates. All 80,300 RELA records are checked, and
the single naming `R_X86_64_RELATIVE` record is bound to zero file bytes
at `0x575ad00`, its `.data.rel.ro` section and writable PT_LOAD. The
slot's larger table role and indirect callers remain unknown.

The [library](../../../src/node94-pointer-arithmetic-pair/lib.rs) returns
actual qwords from the chosen path. Primary byte 1 selects the stored
pair; all other bytes select the computed pair, with subtraction of eight
only when the secondary byte is zero. Neither result is dereferenced.
An invalid skipped field does not prevent an otherwise admitted path.
The new checked refusals are explicit API outcomes, not native faults.

The independently formulated oracle, static record and complete fixed
streams were frozen before the Rust directory existed. The oracle uses
one unbounded affine expression modulo 2^64 and positional byte weights;
Rust uses staged wrapping arithmetic and checked little-endian loads.
The separate native client receives only image bytes and descriptors.
Its output contains the status and both complete returned qwords.

The 76,421 cases include every one of the 65,536 flag-byte pairs,
cross-products of arithmetic boundaries, high-bit stored pairs, each
bit position, exact image endpoints, wrapped field addresses and
skipped unmapped fields. There are 75,341 normal results and 1,080 safe
refusals across all five errors. The proof covers the admitted domain
beyond this finite fixture set.

## Results and limits

| Check | Completed result |
|---|---|
| Native opt0/opt3 | 76,421/76,421 exact each |
| Repeated native executions | 76,421/76,421 exact each |
| Repeated raw artifacts | 4/4 rlib/client pairs byte-equal |
| Library units | 3/3 per profile |
| Compiled mutants | 21/21 per profile, 42 total detected |
| Client malformed records | partial and oversized records refused before output |
| Comparator controls | changed row detected; missing row rejected |
| Static structural controls | 28/28 rejected |

Seventeen mutants per profile have admitted-value counterexamples:
wrong primary/secondary classes, arithmetic direction/width/saturation,
field selection, full-word primary reads, stored-pair swapping/narrowing
and wrong RDX. Four per profile change safe admission only: saturating
the primary field address, eager secondary/stored reads and a strict
endpoint. Those four are not counted as original-value counterexamples.
The complete native qualification passed without correcting source or
control code during execution.

Exact native results, commands, first mutant witnesses and source/tool
bindings are retained in `native-result.json` and `native-commands.json`.
`native-streams.json.gz` is a deterministic lossless archive of command
stdout/stderr, deduplicated by SHA-256. Decode the base64 payload, verify
its content hash, then resolve labels through the `streams` map and
check command byte counts/hashes. `check-streams.json.gz` uses the same
format for the repository/focused checks. No comparison normalization
is applied to native output or repeated binaries.
All 300 native streams from 150 commands and all 18 check streams were
decoded and hash/length-bound after packaging; `packaging.json` records
that verification together with unchanged predecessor input hashes.

The local predecessor suite passed all eight tests, and its packet
checker reproduced exactly. Doctor, verify, catalogue-check, reproduce,
rustfmt and both static verifier configurations passed. All 28 structural
corruptions were rejected independently of the whole-file identity check.

`shared-baseline.json` is the coordinating worker's separate baseline
record, not a full-suite run on this contribution's head: 971 files,
15,462 reported tests and 69 skips. The original `make test` exited 2
solely for three disk-full errors; all 20 affected tests passed an
isolated retry after storage recovery. No successful repeat of the
entire sweep is claimed, and Linux-specific qualifications skipped on
macOS remain unqualified. Hosted checks are not claimed successful.

`scope.json` retains the initial and final overlap checks. The final
check found no matching address/topic among 135 open PRs, zero open
issues, 100 recent merged PRs or existing tracked source.

This is a host value reconstruction, not an original ABI or compiled-byte
match. No captured code or instruction emulator runs. Existing evidence,
pins, registries and progress gates stay unchanged. The remaining
concrete question is the relocated entry slot's caller/table role;
this packet binds the slot without claiming that missing provenance.
