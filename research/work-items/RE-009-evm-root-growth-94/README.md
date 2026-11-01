# RE-009: node94 selected leaf-to-root growth metadata

The selected null-parent branch constructs a new one-entry root, connects the
old and new child through two edges, updates both children's parent/index
fields, and writes the new map root and height. Its return copies the saved
selected-child handle. This is a conditional native metadata contract; the
allocator, prepared-pair provenance and full insertion remain open.

- Component: RE-009 / storage and snapshots.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Fresh source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Selected complete windows: `0x1ab40d6..0x1ab40e6` and
  `0x1ab45df..0x1ab4705`, exclusive ends, 310 bytes total.
- Owner FDE: `0x1ab3d20..0x1ab4a43`, authenticated by full body hash
  `93d07eae728e5ddaadc820741e5508fffe77bf2a74f50ec73d3bd448b3124d15`.
- Status: exact native instructions, widths, operands and selected CFG;
  independent synthetic final-layout relation under the premises below.
  No target execution, Rust reconstruction or acceptance gate is claimed.

## Overlap and the rejected byte-move question

The initial requested slot `0x576dfe0` has one `R_X86_64_GLOB_DAT` row,
symbol index 6, zero addend, `memcpy@GLIBC_2.14`. It has no node-defined
callee FDE for the dynamically supplied implementation. Main already proves
this import identity in `RE-001-hourly-rotation-abi-94` and related packets.
This packet credits that observation and pivots to the next unresolved root
propagation branch. It does not claim new memcpy semantics or a particular
runtime DSO implementation.

[PR #1426](https://github.com/lalalune/hyperliquid-source/pull/1426), head
`53c124a68c6607c5114a8d93acdb09919bc84025`, covers the comparator/caller.
[PR #1438](https://github.com/lalalune/hyperliquid-source/pull/1438), head
`d4506b351f2e948a384384d4e73cdecef3c9fa10`, covers the split pivot/destination
plan and explicitly leaves root growth open. Its retained owner body is
credited; none of those 3,363 owner bytes are counted as newly reconstructed
or matched code here. This packet interprets the separate selected branch.

The intake inspected 86 open PR bodies through #1438 and current main for the
selected addresses. No other root-growth claim was found. Search indexing
can lag; recheck current bodies/heads before publication. The prior branches
and preserved row packet are unchanged.
The final paginated REST intake inspected 102 open PR bodies and found no
selected root-growth address/word claim. #1426/#1438 remained at the heads
above, and upstream main remained `56c0ec67`.

## Premises and native CFG

The selected edge at `0x1ab40e0` tests the leaf's parent pointer and jumps to
`0x1ab45df` when it is null. The current leaf is assumed to be the stable map
root. The map root is nonnull and its saved height is zero. The allocator
returns a fresh, valid, disjoint `0x330`-byte object and preserves SysV callee-
saved registers, stack state and unrelated live memory on ordinary return.
The two children and the prepared 32-byte key/value stack buffers already
exist and are valid, stable and nonaliased with the outputs. There is no
concurrent mutation or address wrap. These are explicit premises, not
properties established for the allocator or earlier byte-moving calls.

The selected normal CFG takes `0x1ab40e0 -> 0x1ab45df`, then falls through
the nonnull-root check `0x1ab45f3`, allocation-result check `0x1ab460e`, INC
overflow check `0x1ab4638`, saved-level check `0x1ab465b` and capacity check
`0x1ab466d`, returning at `0x1ab4704`. All branch opcodes/destinations and the
allocation call are extracted from authenticated bytes. Other incoming
propagation routes, including entry after `0x1ab45df`, are outside this claim.

The allocator call at `0x1ab4605` resolves through `0x576dfd8`. Its unique
`R_X86_64_RELATIVE` row has addend `0x54c06b0`, whose indexed FDE is
`0x54c06b0..0x54c0772`. These records identify the callee; its implementation
and memory-effect contract are unclosed.

After the call, the new node is held in R15. Native stores initialize its
parent to zero and its 16-bit count to zero. No further call occurs on this
selected normal route. Under disjointness, the intervening stores into the
old child and map cannot change the new count. The count read at `0x1ab4661`
therefore reads zero, the unsigned `<11` guard succeeds, and ECX becomes 1.
The resulting zero slot offset selects the first pair and the two child
edges. The initial XOR at `0x1ab45df` and the preserved saved zero height
establish the selected level comparison. This closes the local normal CFG
under the premises without closing any fault path.

## Actual selected stores

| Object | Native sites | Final field and width |
| --- | --- | --- |
| New root | `0x1ab4617`, `0x1ab4622`, `0x1ab4676` | Parent `+0x2c0`: u64 zero; count `+0x2ca`: u16 initially zero, finally one |
| New root | `0x1ab462b`, `0x1ab46b7` | `+0x2d0`: old-child pointer; `+0x2d8`: new-child pointer, each u64 |
| Old child | `0x1ab463e`, `0x1ab4646` | Parent `+0x2c0`: new root, u64; index `+0x2c8`: zero, u16 |
| New child | `0x1ab46bf`, `0x1ab46c6` | Parent `+0x2c0`: new root, u64; index `+0x2c8`: one, u16 |
| Map handle | `0x1ab4651`, `0x1ab4654` | Root `+0`: new root; height `+8`: one, each u64 |
| New root | `0x1ab468d`, `0x1ab4693`, `0x1ab46a5`, `0x1ab46ae` | Two 16-byte prepared key halves at `+0/+16`, and value halves at `+0x160/+0x170` |
| Result | `0x1ab46e5`, `0x1ab46e8`, `0x1ab46ec` | Saved selected-child pointer, saved selected height, saved local index at `+0/+8/+16`, each u64 |

The selected instructions do not write either child's count, the map word at
`+16`, the new root's index field at `+0x2c8`, or the other unused bytes.
This preservation statement requires the nonaliasing/noninterference
premises. No particular values for fresh-allocation padding are inferred.
The height INC has an explicit zero-result exit; unsigned maximum would
wrap to zero. Its failure behavior and the saved-level mismatch route are
retained as uncharacterized exits, with no security or runtime fault claim.

## Evidence and reproduce

`PLAN.json` froze the exact fields, premises and nine native mutations before
the model was written. `evidence.json` retains full selected bytes, decoded
operands/widths, normal CFG, owner FDE/CIE records and full-body hash,
allocator FDE metadata and raw RELA/symbol/version bindings. `selected.asm`
retains both complete GNU 2.44 exports with line-end whitespace removed.
Every raw exported byte is rechecked. FDEs describe unwind ranges and do not
alone prove original function boundaries or exception-path completeness.

```sh
python3 -I -B research/work-items/RE-009-evm-root-growth-94/verify.py
python3 -I -B -m unittest discover -s tests -p test_evm_root_growth94.py -v
python3 -O -B -m unittest discover -s tests -p test_evm_root_growth94.py -v
python3 -B research/work-items/RE-009-evm-root-growth-94/verify.py --out /tmp/re009-root-first
(cd research/work-items/RE-009-evm-root-growth-94 && sha256sum -c MANIFEST.sha256)
make doctor verify catalogue-check reproduce
```

The static verifier uses Python 3.12.14 and the existing ELF/unwind parsers.
It invokes no subprocess, emulator or captured instruction evaluator. Local
materialization authenticated copied artifacts/imports and all seven pinned
source checkouts against the fresh base. Standard LFS filters are supplied
only to the verification invocation, as documented in #1426; persistent Git
settings and checkers are unchanged.

The independent model applies the final-field relation to disjoint synthetic
buffers. Whole-buffer checks cover both selected children, every prepared
byte position and sentinel bytes outside written fields. Native mutations
change edges, count/index/parent destinations, allocation size, overflow
predicate and value offset; selected mutations produce different full-buffer
layouts. Other controls check relocation type/symbol/addend, exact field
widths, image identity, alias/entry assumptions and missing/corrupt exports.
These supplement the binary CFG/operand evidence; they are not target-run
fixtures or proof that earlier copies and allocation satisfy their contracts.

Final observed checks: 10 focused tests pass normally and under `-O` (exit 0
each), including an independent coordinator rerun. Two exports with effective
Python hash seeds 94/115 and time zones UTC/Pacific-Honolulu match each other
and committed evidence (exit 0). `make doctor verify`, `make catalogue-check`
and `make reproduce` each exit 0; all three targets/signatures, 38 imported
files and seven source pins verify. The packet verifier and five-entry
manifest pass (exit 0). Actual environment logs are
`/tmp/re009-root-growth-preflight.log`, `/tmp/re009-root-growth-catalogue.log`
and `/tmp/re009-root-growth-reproduce.log`. No repository-wide `make test`
result for this branch, hosted CI or container success is claimed. No captured
execution occurred. Independent Rust, compiled comparison,
normalization masks, allocator/fault/unwind closure, prepared-buffer provenance,
non-leaf propagation, complete insertion and global ordering remain open.
All full RE-009 acceptance gates remain unfinished; no progress files change.
The next question is to establish the preceding selected byte-transfer and
child-insertion contracts before composing them with this root-growth result.
