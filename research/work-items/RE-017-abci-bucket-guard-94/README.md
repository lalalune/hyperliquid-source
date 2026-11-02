# RE-017: loaded begin-block guard, two decoder paths and materializer handoff

The selected JSON and MessagePack paths assemble the loaded `begin_block_logic_guard` as the same two-word `(bucket_millis, last_bucket)` value and place it at the input offset from which the materializer copies it to the previously identified begin-block state, enabling that particular field's reload behavior to be reconstructed.

- Component ID: `abci`, RE-017; bounded state-loader result question.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; no reference implementation is copied.
- Claim status: the selected FDEs, instruction bytes, literal data, decoded direct transfers and displacements are observations. Field roles and links between separately reached objects are conditional inferences. Runtime scheduling, input acceptance in unexamined children and object identity are unresolved.
- Scope included and excluded: six previously unowned decoder FDEs, the selected new call and result-copy windows in previously studied parents, and one helper handoff window. The original state-loader GOT and call sites, parent functions, numeric helpers, block driver, hash builder, node #115 and visor are not newly owned. This is one field's selected paths, not a complete ABCI implementation.

## Reproduce

Run from the repository root with CPython 3.12 or a compatible Python 3 and the captured node #94 file:

```sh
python3 tools/abci_bucket_guard94.py --out research/work-items/RE-017-abci-bucket-guard-94
python3 -m unittest tests.test_abci_bucket_guard94
(cd research/work-items/RE-017-abci-bucket-guard-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_bucket_guard94.py --out work/re017-guard-a
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_bucket_guard94.py --out work/re017-guard-b
diff -r work/re017-guard-a work/re017-guard-b
```

The two comparison directories must initially be empty. Development used Linux x86-64, CPython 3.12.3 and GNU objdump 2.42 for human inspection only. The generator uses the standard library and `tools/elf_index.py` and `tools/fde_extents.py`; it checks the complete artifact SHA-256 before creating output, requires an unambiguous allocated file-backed range and excludes SHT_NOBITS. It invokes no external program, does not parse disassembler output, and does not execute the target. `functions.tsv`, `extents.tsv`, `windows.tsv`, `calls.tsv`, `branches.tsv`, `offsets.tsv`, `immediates.tsv`, `literals.tsv`, `references.tsv`, `selector-table.tsv`, `marker-table.tsv`, `key-comparisons.tsv` and `summary.json` are generated. The manifest covers these files and this README.

## Evidence

Addresses are link-time virtual addresses; tables also give file offsets. Ends are exclusive. `functions.tsv` verifies each selected FDE against the unwind index and gives its CIE, FDE, LSDA where present and full-body SHA-256; `extents.tsv` contains all selected raw bytes. FDE extents are unwind descriptions, not proof of all function boundaries. `windows.tsv` and `calls.tsv` distinguish selected functions from `prior-function-context`; the counts are curated selections, not an exhaustive control-flow census. No byte mask is applied.

### Connection to existing work

[RE-017 state link](../RE-017-abci-state-link-94/README.md) establishes the `state.rs` Location-bearing loader and [RE-019](../RE-019-rmp-json-loader-94/README.md) identifies its `.rmp` and JSON arms. The supplied open-PR snapshot's JSON Exchange-field study, #1369, identifies `begin_block_logic_guard` as one arm of the already studied JSON parent; its original duplicate and missing-field sites are not regenerated here. The separate cancellation-root study, #1856, supplies the MessagePack outer-reader boundary. These are prior context, not a claim that both outer paths have been re-derived here.

The earlier [CStaking wire study](../staking-cstaking-state-wire-94/README.md) already describes the generic BucketGuard field order and nonzero-width rule. The new question is which distinct child visitors load the **begin-block** instance in the two Exchange paths, how their local failures and results propagate, and where that result is copied. The prior [round-clock study](../staking-round-clock-94/README.md) describes begin-block use at state `+0x38f8`; open #1701 associates that same offset with a selected state-root job input. Neither prior result proves runtime identity with this particular load.

### Selected functions

| Selected FDE start | Role in the inspected paths | FDE end |
| --- | --- | --- |
| `0x325dd60` | JSON wrapper passing `BucketGuard`, length 11, field count 2 | `0x325dda5` |
| `0x3143ec0` | JSON object/sequence guard visitor | `0x3144696` |
| `0x30339a0` | JSON second sequence-value step | `0x3033ad0` |
| `0x2a9c3a0` | MessagePack guard visitor | `0x2a9da87` |
| `0x2aae4c0` | MessagePack two-name classifier | `0x2aae580` |
| `0x2a65dc0` | MessagePack width marker adapter | `0x2a65e50` |

### JSON field and result

On the selected prior-parent path, the new call at `0x2fe71c5` reaches the wrapper; its returned first word is staged at `rsp+0x88` and its second at `rsp+0x5f0`. A zero first word branches away at `0x2fe71dd`. On the selected result-copy path, `0x2ff3e9d` stores the first word at `[r14+0x1dd8]` and `0x2ff3eac` stores the second at `[r14+0x1de0]`. The role of `r14` as the relevant result object follows the prior parent analysis and requires its register and stack continuity to hold on the path considered.

The wrapper calls `0x3143ec0`, supplying the literal `BucketGuard` and two fields. On the object path, its length and overlapping qword comparisons identify `last_bucket` and `bucket_millis`; `references.tsv` resolves their RIP-relative operands and retains the compared bytes. The `last_bucket` arm calls `0x2fe4650`, sets a distinct presence slot, and checks it before a second occurrence. The width arm calls `0x3094280` and uses the stored nonzero word as its duplicate and completion sentinel. At object completion, a clear last-presence bit branches to the `last_bucket` diagnostic; a zero width branches to the `bucket_millis` diagnostic. An unknown-key arm calls an external helper and branches on its result; its full behavior is not interpreted here.

On the selected sequence path the first child `0x30480a0` reaches `0x2fe4650` at the separately marked context site `0x3048198`; the second child `0x30339a0` reaches `0x3094280`. Thus those selected first and second value paths use the same respective children as the named fields. Missing first and missing or zero second select diagnostic construction with indices 0 and 1. Selected success stores the width at result `+0` and the last value at `+8`. The presence test is separate from the last value; it does not by itself prove which numeric values the external child accepts.

### MessagePack field, formats and failures

The selected parent site `0x2aba720` calls `0x2a9c3a0` with `BucketGuard`; a non-9 child tag branches away at `0x2aba72f`. On tag 9 it stages the two result words at `rsp+0x510`; the selected continuation also stages the first at `rsp+0x2b0`. The missing and duplicate branches pass the 23-byte literal `begin_block_logic_guard` to diagnostics. On the selected result path `0x2ab8a62` copies the staged 16 bytes to `[r13+0x1dd8]`. The code windows establish those operations; continuity through intervening blocks and the identity of `r13` with the loader result require the stated path and alias assumptions.

For the ordinary `BucketGuard` name, the `_ExtStruct` special-name test takes its other arm. If the input state byte is 1, the single selected entry in `selector-table.tsv` reaches the fresh-marker reader. The fixed-map and fixed-array marker ranges feed their respective map and array arms. The separate bounded `0xc0..0xdf` table has 32 signed entries in `marker-table.tsv`; the upper and lower comparisons and table reference are checked from instruction bytes. On this fresh-marker path:

| Marker | Table target | Observed length path |
| --- | --- | --- |
| `0xdc` | `0x2a9c6fe` | two-byte big-endian array count |
| `0xdd` | `0x2a9c66d` | four-byte big-endian array count |
| `0xde` | `0x2a9c69a` | two-byte big-endian map count |
| `0xdf` | `0x2a9c640` | four-byte big-endian map count |

The four insufficient-length branches reach `0x2a9c77e`, whose selected stores advance by the remaining bytes, clear the remaining count and construct tag 1. These table targets enter after the shared fresh-marker setup; they are not standalone callable function entries. Other table entries and the special-name path are recorded as bytes but their complete semantics are not claimed.

The fixed-array arm tests depth, handles zero and one element by distinct indexed diagnostic calls, calls the last-value child then the width adapter, and branches on each child tag. After two successful child results, count two reaches the 16-byte result assembly; a larger remaining count enters a tag-4 construction. The diagnostic helper is a boundary and can itself return different tags, so an indexed diagnostic call alone is not a proof of unconditional rejection.

The selected map-key classifier checks all 11 bytes of `last_bucket` and all 13 of `bucket_millis`, returning local selectors 0 and 1; another name returns selector 2. `key-comparisons.tsv` contains every compare byte and its checked branch. Selector 0 reaches the last-value child and a separate presence slot; selector 1 reaches the width adapter and a width-value slot. Duplicate branches go to the corresponding named diagnostic. At map completion, missing last takes the `last_bucket` diagnostic before the zero-width check takes the `bucket_millis` diagnostic. Selector 2 reaches a separate helper and its return is checked; no complete unknown-key acceptance rule is claimed. The width adapter's downstream numeric helper, its established slot and its other numeric forms are prior boundaries. Open #1643 studies integer routes through that helper; this packet does not republish its relocation or claim all numeric conversions.

### Copy into the materializer and use boundary

In the materializer's selected windows, the argument moves save input `rsi` in `rbx` and output `rdi` in `r14`. `0x3752044` reads 16 bytes at `[rbx+0x1dd8]`, and `0x375204b` stages them at `[rsp+0xb0]`. `0x3752875` reloads those bytes and `0x375287d` writes them to `[r14+0x38f8]`. The intervening code and calls are not completely modelled; the copy conclusion assumes the saved input, output and staging memory are preserved and do not alias an intervening write.

The round-clock packet reports that its previously studied begin-block routine reads the width at state `+0x38f8`, compares its computed bucket with the last word at `+0x3900`, and updates the latter on the greater arm. The root-groups packet #1701 reports a capture at `+0x38f8`. **Conditional inference:** if the materializer receives the object produced by either selected parent path, and its output is the same object used by those later consumers without an intervening conflicting write, this loaded pair is their guard input. No actual scheduling, object identity, final serialized hash, or whole-block transition is established by these matching offsets.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No target execution, captured fixture, compiled comparison, normalization masks, helper or relocation closure, final state-root comparison, or whole-ELF equivalence has been measured. The small key comparison routine in the tests is a static model of the pinned classifier, not execution of the node.

The focused suite passed 27 tests with zero skips. Controls cover a damaged artifact hash before output creation, invalid/unmapped/NOBITS/ambiguous ranges, FDE-index and body corruption, selected instruction windows, all 21 direct-call displacements, all 51 conditional branch opcodes and displacements, all 24 key bytes and their exits, changed name lengths and RIP references, all 32 jump-table entries, an out-of-FDE jump target, the selected state-table entry, and length-truncation instructions. File-backed byte edits use a private copy-on-write mapping.

## Results and limitations

`summary.json` records 6 selected FDEs containing 8,578 bytes, 47 selected windows, 21 selected direct calls, 51 selected conditional branches, 7 displacement and 5 immediate observations, 8 literal records, 16 RIP-relative references, 24 classifier comparisons, 1 selected state-table entry and 32 bounded marker-table entries. These are selection counts, not coverage percentages. No ABCI progress gate is requested; the component remains 0/4.

Unresolved: the full parent control-flow and aliases between copy windows, external numeric and error helpers, all nonselected JSON and MessagePack forms, writer side effects, scheduling and ownership between loader, materializer, block driver and root builder, and the rest of begin/action/end-block behavior. Next question: can a previously unowned ownership-transfer path establish that the materializer output reaches a specific begin-block invocation without an intervening write to these two words?
