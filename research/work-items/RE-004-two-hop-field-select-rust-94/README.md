# RE-004: conditional two-hop read with exact memory admission

This packet independently reconstructs the complete node #94 leaf
`[0x5361710,0x5361738)` in safe Rust. It preserves full RAX/RDX, all u64
field-address arithmetic, the full-width zero test and accessibility of only
the selected terminal field. The previous `foundation-two-hop-field-select-94`
packet established static evidence and left Rust unimplemented. This work adds
a closed byte-image contract and actual native qualification; it does not
recover a source struct/type or advance whole-component gates.

Target: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Task/component: bounded RE-004 reconstruction, foundation. Fresh source and
live inspection found no overlapping implementation in 209 open PRs, 100 recent
merged PRs and zero open issues; `scope.json` binds the inventories. Nearby
bodies are only boundary context, not a claimed closed sibling family.

## Recovered relation and explicit domain

For little-endian qwords q and arithmetic modulo `2^64`, the leaf reads
`P=q(O+8)` and `Q=q(P+0x1e0)`. It returns full RDX=P and full RAX from
`q(P+0x178)` when Q=0, otherwise from `q(Q+8)`. It writes no data and calls
no helper. Other original general registers are not modified by its body;
stack/control/flags effects and the native ABI are outside the value API.

`load(&[u8], base, object)` models stable ordinary bytes in one nonwrapping
numeric interval, allowing endpoint exactly `2^64`. Each reached qword must
fit; the unused terminal need not be mapped. Numeric field addresses wrap
before checking that span and never become host pointers. None is a new safe
refusal for an invalid image/reached span, not an original return or fault
order. Unaligned and overlapping read roles are supported. The 512-byte host
fixture is not a public API size cap.

Zero O or P is not tested by the target. Such values are admitted when the
actually reached fields exist in the image. This narrows the historical
packet's blanket “null P would fault” statement: page mapping is an additional
runtime premise, not a zero guard in these instructions. The API does not
promise that arbitrary raw numeric addresses are canonical hardware mappings.

See [PROOF.md](PROOF.md) for the complete branch, register and memory-domain
argument, and [the library](../../../src/node94-two-hop-field-select/lib.rs)
for the independently authored `no_std` implementation with unsafe code
forbidden. There is no inferred-source copying, fake workspace or dependency
lock. Reference pin `999556f6e0a474b8312db96ec3149e1c44e97c23` is unchanged;
its unlicensed implementation was not read or copied. New code/docs are MIT;
captured bytes/disassembly retain the artifact's original rights.

## Static and frozen evidence

GNU, LLVM and Capstone agree on the complete 40-byte/ten-instruction body,
including both returns and the unreachable seven-byte internal NOP. Complete
FDE/CIE records, neighboring extents and eleven preceding INT3 bytes are bound.
The next FDE starts exactly at `0x5361738`, so no external padding is appended.

Both E8 sites, `0x5380fb7` and `0x538265a`, are boundary-confirmed in their
complete callers, totaling 3,030 bytes and 630 instructions. Full caller
code/FDE/CIE records are retained solely as call-boundary context, without
claiming their other helpers, algorithms or exception machinery. The complete
`.text` E8/E9 encoding scan finds those two E8 candidates and no E9 candidate.
All 80,300 RELAs are checked for entry naming and overlapping code writers.
The leaf has neither an import nor static-data dependency. Thirty-six static
corruption controls reject changed instructions/operands, internal NOP, FDE/CIE,
boundaries, caller edges, introduced entry references and partial code writers.

Before the Rust source directory existed, `oracle.py` formed every valid
qword interval using positional-byte integer sums, then composed the field
relation over that immutable dictionary. This is independent of the Rust
checked-slice helper. The frozen source/static/input/output hashes and actual
compressed input/expected streams are retained; no instruction interpretation
or target execution generated them.

The 10,464 pre-Rust cases include:

- 2,553 admitted fallback and 3,696 admitted indirect results; 4,215 refusals.
- 1,545 admitted fallback cases with absent unused indirect fields, and 336
  admitted indirect cases with absent unused fallback fields.
- 76 admitted zero-P, 388 admitted zero-object and 190 admitted nonzero-Q
  cases whose low32 bits are zero.
- 1,306 wrapped selected addresses, arbitrary result bits, role overlaps,
  unaligned/exact-end spans and two overflowing-image witnesses whose reached
  spans individually fit.

## Actual qualification and retained disk failure

The input-only host client receives just the image descriptor and bytes. It
does not read expected outputs, the oracle or captured instructions. Actual
qualification in the fresh `native-final` directory passed all 10,464 cases
at opt0/opt3 and a repeated build of each: 41,856 exact output records. All
admission statuses and full RAX/RDX values match. Three unit tests pass per
profile; both rlib/client repeat pairs per profile are byte-identical without
normalization. Partial-input/descriptor and changed-output/missing-row controls
also pass.

All 29 wrong source variants were first compiled for metadata with warnings
denied, then actually built and run at both optimization levels. All 58 runs
are effective: 26 change admitted values and 50 change admission, with overlap
between these categories. Controls cover each field offset/addition, pointer
width/sign/zero handling, branch choice, RAX/RDX width and provenance, byte
order, eager unused reads, whole-image/exact-end admission and all-ones results.
These are actual native mutations, not comparator-only or Python substitutes.

The final 198 command records bind 396 exact stdout/stderr streams, retained
losslessly in `native-streams.json.gz` (768,498 bytes, SHA-256
`c7a0292c4df3683e5117fe2e0511c7cf81ea3e8490344dea94e4e8f56ac9f472`).
Per-stream content-addressed gzip checkpoints precede each assertion; final
consolidation uses gzip level 1 and mtime 0. Every stream hash/length/command,
checkpoint, frozen expected output, source, preflight mutation and repeated
artifact was audited. The preflight archive retains all mutant sources and
58 raw streams. `native-audit.json` and `archive-audit.json` record the checks.

The first attempt coincided with shared disk exhaustion. Its outer native
process exited 120 with empty stdout/stderr; 18 successful command records
and 36 stream entries survived, ending after a successful mutant client build.
There is no retained exception text establishing the precise native failure
point and no recorded nonzero child command or value mismatch. The separate
repository-check recorder explicitly raised Errno28 while updating its command
file, after its first retained command. Neither partial attempt qualifies a
complete matrix or check set.

`initial-disk-full/` preserves every surviving initial metadata/source/stream
file, including exact gzip checkpoint bytes, the checks traceback and recorder,
and a hash/size manifest of compiler artifacts retained in ignored work. No
failed artifact was pruned. Space was recovered from completed published
outputs only, with hashes and deletion journals. The successful runs used
fresh output directories; source, oracle, static freeze and expectations were
unchanged. The final archive audit verifies those source bindings.

The legacy checker, 17 focused tests, rustfmt and all four make commands below
passed in the fresh check run. `checks.json`, its command records and exact
18-stream archive retain the final results separately from the failed recorder.

## Build recipe and reproduction

The exact native compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, host/target
`aarch64-apple-darwin`, LLVM 21.1.8. Its file SHA-256 is
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The recipe uses edition 2021, warnings denied, one codegen unit, overflow
checks enabled, opt0/opt3 and `/usr/bin/cc`. The verifier binds source files,
actual compiler/linker identity, flags, inputs and raw command outputs.

From the repository root, with Python 3.14.3, Capstone 5.0.7, GNU binutils
2.47.20260726 and Apple LLVM objdump 17:

```sh
python3 -O research/work-items/RE-004-two-hop-field-select-rust-94/verify_static.py
python3 -O research/work-items/RE-004-two-hop-field-select-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/two-hop-field-select-replay
python3 tools/foundation_two_hop_field_select.py \
  --check research/work-items/foundation-two-hop-field-select-94/evidence.json
python3 -m unittest tests.test_foundation_two_hop_field_select \
  tests.test_fde_extents_cie_aug_encoding tests.test_gnu_binutils_tools -v
make doctor
make verify
make catalogue-check
make reproduce
```

These are new ARM64 host builds of a safe value component, not recovered Linux
x86-64 compiled bytes or a full node. No captured executable, emulator, live
node, chain, credential, imported-pin change or gate update is involved.
Caller behavior beyond the retained call boundary remains unknown. A separate
parent baseline attempted 971 files / 15,462 reported tests / 69 skips at the
same source base; its original make test exited 2 solely for three disk-full
files, whose 20 affected tests passed isolated retry. No successful full-sweep
rerun, per-head full suite, skipped Linux qualification or hosted-CI success
is claimed. Authorship: OpenAI / Codex client; exact model identifier unavailable.
