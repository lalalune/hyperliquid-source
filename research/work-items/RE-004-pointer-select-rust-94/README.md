# RE-004: low32 pointer selector and both adjusting tail entries

This packet reconstructs one complete three-entry node #94 family in safe
Rust: the pointer selector `[0x552cac0,0x552cade)`, its add-0x18 tail wrapper
`[0x552b280,0x552b28d)`, and the add-0x2998 wrapper that enters it at
`[0x54cbd40,0x54cbd50)`. Together they contain 59 bytes / 13 instructions.
The historical `foundation-pointer-select-94` packet left Rust unimplemented
and scanned only E8 calls. The new full E9 closure revealed both related
wrappers; they are reconstructed in this single contribution.

Target: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Task/component: bounded RE-004 reconstruction, foundation. No source struct,
library identity, whole-node build or component gate completion is claimed.

Fresh inspection found no overlap in 217 open PRs, 100 recent merges, zero
open issues or current source. The direct body's exact bytes occur once in
`.text`. A bounded decoded-shape check across 8,484 complete 20–64-byte FDEs
found only this direct selector shape; this is not an exhaustive semantic
equivalence census. Both wrappers were checked separately for overlap before
expanding the same family. `scope.json` retains the inventory/source terms,
shape-check limits and wrapper-edge findings.

## Relation and API

`load(entry, image, base, object, selector)` reconstructs all three entry
adjustments, the full low32 equality test, and the final selected qword load.
The wrappers add 0x18, or 0x2998 then 0x18, modulo 2^64. The direct selector
chooses the adjusted object plus 0xe518 when low32(selector)=1, otherwise
plus 0xec10. It loads the qword at selected-base+0x78.

The returned structure includes full RAX (loaded value), full RDI (selected
base) and full incoming RSI (unchanged selector). Reading ESI for comparison
does not clear RSI's upper bits. The original candidate in RAX is completely
overwritten by the final qword. There are no opaque calls or partial-register
return assumptions.

Only the final chosen qword requires memory. Object/selected-base metadata
and the unused field need not be mapped. The stable numeric image must have
endpoint at most 2^64; field formation wraps before checking all eight bytes
within that ordinary interval. None is a new safe refusal, not an original
return or fault-order model. The slice is never mutated and numeric addresses
never become host pointers. The 2,048-byte fixture capacity is not an API cap.

[PROOF.md](PROOF.md) gives the full u64/byte-image argument and explicit
normal-return premises. The [library](../../../src/node94-pointer-select/lib.rs)
is independently authored `no_std` code with no dependencies and unsafe code
forbidden. No inferred implementation was copied; reference pin
`999556f6e0a474b8312db96ec3149e1c44e97c23` remains unchanged and its unlicensed
implementation was not read. New code/docs are MIT; captured bytes/disassembly
retain the artifact's original rights.

## Complete static and caller closure

GNU, LLVM and Capstone bind every selected member byte and logical instruction,
the complete FDE/CIE records, boundary context and padding. The six complete
external caller FDEs contain 5,339 bytes / 1,263 logical instructions. Their
eight E8 sites and both internal E9 links are checked at actual decoded
boundaries. All 80,300 RELAs are checked for entry naming and code/padding
writers. There are no static data/import dependencies in the selected family.
Caller algorithms, other helpers and globals are context only, not recovered.
The direct encoding scan is not a complete indirect xref census.

LLVM renders three caller LOCK prefixes as standalone F0 rows. Only those
exact prefixes at 0x551e926, 0x551e93b and 0x551e948 are joined to their
adjacent rows for logical-boundary comparison; every raw byte is retained and
matches GNU/Capstone. This is display grouping, not a compiled-byte mask.
Sixty-two unique-offset structural controls reject member instructions,
operands, FDE/CIE, padding, caller boundaries/edges, introduced references and
partial code writers. Shared CIE offsets are exercised once.

The initial strict LLVM-boundary failure and subsequent underclosed E9 scan
failure are retained in `initial-prefix-rendering/` and `initial-e9-closure/`,
including exact validator versions, exports and diagnostics. An oracle attempt
after the first static failure refused the missing static record and wrote no
frozen streams. The successful complete-family static record and oracle freeze
both preceded Rust creation. Brief disk exhaustion also blocked initial source
directory creation; it did not alter the frozen relation or produce a native
failure. Completed published outputs were reclaimed with hash/path journals.

## Independent expectations and native qualification

The pre-Rust oracle computes the final field address in one unbounded modular
expression, derives selected-base RDI backwards from it, and reads qwords with
positional-byte integer sums. It does not mirror the Rust staged additions or
checked slice helper, import Rust, interpret instructions or execute the target.
Its source, complete static record, frozen input/expected streams and hashes
are retained.

The 23,220 frozen cases give each entry 5,119 admissions and 2,621 refusals.
They include 3,915 admitted absent-unused-field cases, 5,073 with the selected
base itself unmapped, 7,206 preserving nonzero high32 selector bits, 3,381
alternative selections with such high bits, 2,310 final field-addition wraps,
1,155 exact-end reads and independent intermediate-wrapper carry witnesses.
Six global-overflow refusals keep the selected field individually present.

All four actual rustc builds, opt0/opt3 and repeats, match 92,880 output
records exactly in admission and full RAX/RDI/RSI. Three unit tests pass per
profile. All four repeated rlib/client artifact pairs are byte-identical with
no normalization. Partial input, invalid entry/image descriptor, changed output
and missing-record controls pass.

Thirty-nine mutant source variants first passed compiler metadata checks with
warnings denied, then were actually built/run at both levels. All 78 runs
are effective: 56 change admitted values and 62 change admission, with
overlap between these categories. They cover selector width/equality/sign, both candidate offsets,
field offset, complete output values/widths, both wrapper stages and carries,
byte order, zero-object/result refusals, eager unused reads, selected-base
mapping and image/exact-end guards. This qualifies actual native wrong code,
not just comparator corruption or a Python model.

No native or mutation-preflight failure occurred. Exact command streams are
checkpointed before assertions in content-addressed gzip files, then retained
in one lossless level-1/mtime-zero archive with label/hash/base64 bindings.
`native-result.json`, `native-audit.json`, command records and preflight source
archive provide actual source/compiler/output/witness bindings.
All 260 native commands and their 520 streams are retained in the 4,669,747-byte
`native-streams.json.gz`, SHA-256
`dc8773a961a9240605250ba8cdd40cee84d27c1364d2f097a18ca111bc39f226`.
The preflight archive includes 78 streams and all 39 mutated sources.
`archive-audit.json` checks raw command/output/source/freeze/repeated-artifact
bindings; `qualification.json` also audits both initial static-failure archives.

## Build and repository checks

The pinned actual compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, host/target
`aarch64-apple-darwin`, LLVM 21.1.8, file SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The recipe uses edition 2021, warnings denied, one codegen unit, overflow
checks enabled, opt-level 0 or 3 and `/usr/bin/cc`. Actual linker identity,
all flags, source/tool hashes and command streams are retained. These are
new host value-component builds, not original Linux x86-64 compiled bytes.

From the repository root, with Python 3.14.3, Capstone 5.0.7, GNU binutils
2.47.20260726 and Apple LLVM objdump 17:

```sh
python3 -O research/work-items/RE-004-pointer-select-rust-94/verify_static.py
python3 -O research/work-items/RE-004-pointer-select-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/pointer-select-replay
python3 tools/foundation_pointer_select.py \
  --check research/work-items/foundation-pointer-select-94/evidence.json
python3 -m unittest tests.test_foundation_pointer_select \
  tests.test_fde_extents_cie_aug_encoding tests.test_gnu_binutils_tools -v
make doctor
make verify
make catalogue-check
make reproduce
```

The legacy checker, 15 focused tests, rustfmt and all four make commands passed.
`checks.json`, exact command records and the lossless 18-stream check archive
retain those results separately from the pre-Rust static failures.

The separate parent baseline at this source base attempted 971 files / 15,462
reported tests / 69 skips. Its original make test exited 2 solely for three
disk-full files, whose 20 affected tests passed isolated retry. No successful
full-sweep rerun, per-head full suite, skipped Linux qualification or hosted-CI
success is claimed. No captured executable/emulator, live node, chain,
credentials, imported-pin change or gate update was involved.
Authorship: OpenAI / Codex client; exact model identifier unavailable.
