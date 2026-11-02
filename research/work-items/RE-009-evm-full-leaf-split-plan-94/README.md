# RE-009: node94 full-leaf split pivot and destination plan

For an eleven-entry leaf and insertion position 0 through 11, the selected
native decision chooses old pivot 4, 5 or 6 and selects either the old node
or the new node for the incoming pair. Positions 5 and 6 have separate central
arms. This packet resolves that local planning decision and the corresponding
local index. It does not establish successful map insertion or global order.

- Component: RE-009 / storage and snapshots.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, freshly revalidated.
- Primary unwind extent: `0x1ab3d20..0x1ab4a43`, exclusive end; FDE
  `0x1016d98`, CIE `0xfbdc2c`, LSDA pointer `0x967024`.
- Independently authored static research. No inferred reference source was
  copied. No Rust implementation or acceptance gate is claimed.
- Status: observed instructions and operand fields; a bounded mathematical
  plan for a valid eleven-entry input; unresolved allocation, byte-move and
  propagation behavior. The source type and the label “leaf” remain inferred
  from the zero-height handle and data layout.

## Ownership and scope

[PR #1426](https://github.com/lalalune/hyperliquid-source/pull/1426), checked at
`53c124a68c6607c5114a8d93acdb09919bc84025`, resolves the local key comparator
at `0x28546c0` and explicitly leaves the call to `0x1ab3d20` unresolved. Its
call site is credited context here. This new work starts inside that callee
and does not change the key-order packet or the preserved overlapping row
packet. #1379 and #1384 cover compact and JSON rows; neither selects this FDE.

Exact-address searches and a current-main search found no other claim for
this helper. The broad search returned closed #1280 (consensus admission),
whose full body/diff contains no helper or call-site hit. Open #1418 concerns
the lattice JSON value writer at other addresses. #1410 and #1417 are also
separate checkpoint codec/scanner work. These are intake observations, not
an ownership guarantee; recheck current heads before submission.
The final refresh inspected the bodies of all 84 returned open PRs, through
#1436. The only insertion-helper address hit was #1426's explicit unresolved
gap. Upstream main remained `56c0ec67`.

`PLAN.json` froze the twelve cases and nine native mutations before the model
was written. `evidence.json` retains the complete 3,363-byte primary body and
its hash, file offset, indexed FDE/CIE bytes, LSDA pointer, three selected
primary windows (452 bytes), twelve selected native control transfers, and
134 bytes of credited caller context. These are retained/selected evidence
counts, not reconstructed or matched bytes or a component denominator.
`selected.asm` retains the four bounded GNU disassembly exports with line-end
whitespace removed; every exported raw byte is checked against the target.
An FDE does not alone prove original function boundaries or exclude cold parts.

## Native observations

All coordinates are linked ELF virtual addresses. The caller at `0x2854803`
stores a zero qword in its handle's middle word, then copies that handle and
passes its address in RSI at `0x285484c`. The direct call at `0x2854859`
resolves to `0x1ab3d20`. This proves the selected call edge and zero word;
valid tree structure and source-level height semantics are premises.

| Native sites | Observed decision or data transfer |
| --- | --- |
| `0x1ab3d37..0x1ab3d45` | Loads the node's 16-bit word at `+0x2ca`; unsigned `>=11` selects the split path. The code does not establish that this word can never exceed 11 |
| `0x1ab3d77..0x1ab3da9` | Loads index from handle+16, compares with 5, then preserves CMP flags through MOVs to JAE. Index below 5 selects pivot 4, flag 0, unchanged local index |
| `0x1ab3e5f..0x1ab3e86` | JE reuses the first comparison's equality flag: index 5 selects pivot equal to index and flag 0. Index 6 selects pivot 5, flag 1 and local index 0 |
| `0x1ab3e86..0x1ab3e97` | Remaining selected indices choose pivot 6, flag 1 and local index `index-7` using 64-bit arithmetic |
| `0x1ab3ea0..0x1ab3ecb` | Passes `0x2d0` to indirect slot `0x576dfd8`; a null result takes a separate branch. Allocation behavior is not closed |
| `0x1ab3ed0..0x1ab3ee9` | Computes `old_count + ~pivot`, which is `old_count-pivot-1` in the valid domain, and stores its low word at new-node+`0x2ca` |
| `0x1ab3eec..0x1ab3f2d` | Scales pivot by 32 and gathers two 16-byte halves from each of the old node's key and associated-value areas; value area starts at `+0x160` |
| `0x1ab3f5b`, `0x1ab3f73`, `0x1ab3f79` | Two indirect calls through `0x576dfe0` precede storing pivot as the old node's count; their byte-moving contract and effects remain unresolved |
| `0x1ab3fbb..0x1ab3fd8` | Flag zero selects the old node through CMOVE; nonzero retains the new node. The paired conditional selection also chooses the associated handle word |

The following table is the mathematical plan for **exactly eleven old
entries**, with one incoming pair inserted into the selected child. Child
sizes in the last column are predictions from that plan, not observed
post-insertion counts from a running target.

| Input position | Old pivot | Destination | Local position | Predicted left/right sizes |
| --- | --- | --- | --- | --- |
| 0..4 | 4 | old / left | input position | 5 / 6 |
| 5 | 5 | old / left | 5 | 6 / 5 |
| 6 | 5 | new / right | 0 | 5 / 6 |
| 7..11 | 6 | new / right | input position minus 7 | 6 / 5 |

For each case, removing the selected old pivot, inserting the incoming item
at the selected local index and reassembling left/pivot/right equals an
independent whole-list insertion. This establishes the plan's index geometry.
It does not prove that the unresolved calls perform those moves or that the
later propagation paths complete successfully. It also does not prove the
source entries are globally sorted. The verifier restricts its model to this
domain without claiming the target rejects other inputs.

## Reproduce and verification

Run from the repository root with Python 3.12.14 and the repository's shared
ELF/unwind parsers. GNU objdump 2.44 generated the selected listing. The
verifier and tests perform static reads and bounded mathematical operations;
they invoke no captured code, emulator, network or subprocess.

```sh
python3 -I -B research/work-items/RE-009-evm-full-leaf-split-plan-94/verify.py
python3 -I -B -m unittest discover -s tests -p test_evm_full_leaf_split_plan94.py -v
python3 -O -B -m unittest discover -s tests -p test_evm_full_leaf_split_plan94.py -v
python3 -I -B research/work-items/RE-009-evm-full-leaf-split-plan-94/verify.py --out /tmp/re009-leaf-plan-first
cmp /tmp/re009-leaf-plan-first/evidence.json research/work-items/RE-009-evm-full-leaf-split-plan-94/evidence.json
(cd research/work-items/RE-009-evm-full-leaf-split-plan-94 && sha256sum -c MANIFEST.sha256)
make doctor verify catalogue-check reproduce
```

Local materialization compared provenance manifests, authenticated every
copied artifact/import and checked all seven Git pins against the fresh
superproject before copying. In this clone, `make verify` uses standard LFS
filters only for that invocation, as documented by #1426; no persistent Git
configuration or checker changed. LLVM 19.1.7 is available through the existing
explicit path `/workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump`.

The ten focused tests cover all twelve frozen native cases, independent list
splicing, nine predeclared native mutations, additional preserved-flag/width/
branch controls, a separate full-file identity boundary, invalid model inputs,
disassembly omission/corruption, and ambiguous/NOBITS/out-of-input ranges.
One initial test chose input 4 as a counterexample to changing cut 5 to 4;
that input has the same plan under both choices, so the assertion failed.
The witness was corrected to input 5, without changing the frozen native
cases. The altered ADD's 64-bit wrapping is explicit in the model.

Final observed results: the ten focused tests pass normally and under `-O`
(exit 0 each); the packet verifier passes normally and under `-O` (exit 0
each); all five scoped manifest entries pass. Exports with effective Python
hash seeds 94 and 115 and time zones UTC and Pacific/Honolulu compare byte for
byte with each other and committed evidence (exit 0). Those export commands
use `python3 -B`, so Python accepts the declared `PYTHONHASHSEED` values.
`make doctor verify`, `make catalogue-check` and `make reproduce` each exit 0,
with three artifact signatures, 38 imported files and all seven source pins
verified. Actual environment logs are `/tmp/re009-leaf-plan-preflight.log`,
`/tmp/re009-leaf-plan-catalogue.log` and `/tmp/re009-leaf-plan-reproduce.log`.
A repository-wide `make test` result for this separate branch is not claimed.
Captured-execution opt-ins remain unset. Hosted CI, containers and Rust
reconstruction were not tested or implemented. Source/compiled comparison
and normalization masks remain unmeasured.

## Remaining question

Resolve the two byte-moving calls and the subsequent selected local insertion
path before claiming actual leaf splitting. Parent propagation, root growth,
allocation failure, LSDA/unwind paths, full insertion behavior, global order,
nominal types and production snapshot compatibility remain open. No progress
or acceptance gate changes.
