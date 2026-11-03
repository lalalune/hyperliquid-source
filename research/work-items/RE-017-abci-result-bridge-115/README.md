# RE-017: Connect the ABCI projected result to its delivered rows

For selected normal-return branches of node #115, the previously separated projection and fingerprint-input records can be reconstructed as an indexed 64-byte aggregate whose 8-byte key is removed to deliver a 56-byte identifier-and-vector row.

- Component ID: `abci` (RE-017, related to RE-009 state/snapshot validation).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; navigation reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed clue, not copied source or evidence of #115 semantics.
- Claim status: static observations and conditional inferences below; unresolved dependencies remain explicit. Names in the tables are descriptive hypotheses, not recovered symbols.
- Scope included and excluded: selected loader-result continuation, aggregate insertion and collection, plus specific conversion, allocation and cleanup branches. Existing caller, projector, accumulator, collector, wrapper, worker and fingerprint sites are context, not newly owned claims. Full ABCI begin/action/end processing, state mutation and root equivalence are excluded and remain open.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and the #115 artifact present. The extractor uses the repository ELF and FDE parsers and the Python standard library; it does not invoke binutils or execute the artifact. The selected output is fully determined by the verified input and fixed, instruction-aligned windows. Neither environment-specific paths nor timestamps are emitted.

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_abci_result_bridge115
python3 tools/abci_result_bridge115.py --out <tmp-dir>/first
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_result_bridge115.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/first research/work-items/RE-017-abci-result-bridge-115
(cd research/work-items/RE-017-abci-result-bridge-115 && sha256sum -c MANIFEST.sha256)
```

`<tmp-dir>` denotes a reviewer-chosen temporary directory. Optionally, when the separately obtained #94 artifact is available, this command additionally checks that old artifact's own digest, source-location record, relocation, caller/target FDE extents and old caller/target byte patterns. Its output remains the same #115 evidence; the old input is never substituted for the target.

```sh
python3 tools/abci_result_bridge115.py --historical-node references/can1357-hl/bin/hl-node-mainnet-new --out <tmp-dir>/historical-check
```

GNU objdump 2.42 was used only to inspect instructions by hand; it is not an input to any generated evidence or test. `MANIFEST.sha256` records output file hashes. `functions.tsv` retains raw bytes and hashes for each selected FDE interval; `windows.tsv`, `transfers.tsv`, `operands.tsv`, `drop-table.tsv` and `unwind*.tsv` retain the selected observations. `facts.json` records input digest and derived constants; `pivot-cases.tsv` and `transition-cases.tsv` are explicitly synthetic branch models derived from verified operands, not executions.

## Evidence

All addresses below are #115 ELF virtual addresses unless identified otherwise. `functions.tsv` includes file offsets, unwind-index entries, CIE/FDE/LSDA addresses and exclusive ends. Starts are checked against `.eh_frame_hdr` and the referenced FDE; the FDE spans are unwind ranges, not a claim that they establish every machine-code function boundary in the binary. Only file-backed sections are mapped; `SHT_NOBITS` is excluded. The extractor verifies the full artifact digest before generating any output. It captures complete bytes for the 14 selected FDE intervals and 94 named inspection windows; it does not purport to decode every instruction in those intervals. The 134 transfer records are selected, instruction-aligned patterns, not all calls or branches in these bodies. Relocation/data/helper closure and whole-binary coverage are not claimed.

### Loader context and historical control

The #115 location record at VA `0x64767a8` (file offset `0x64747a8`) has a relocated pointer to the 20-byte suffix `l1/src/abci/state.rs`, line 123, column 37. Context bytes at `0x3c1352f` address that location; `0x3c1353b` compares a returned word with 1. Open #115 proposals #2047, #2107 and #2243 trace the loader handoff, expanded-owner callback and block-result continuation. They are pending work; we use their documented connections as conditions, not as a new ownership claim or proof of runtime scheduling. The index and result statements below are only for the pinned continuation and branches.

The older RE-017 clue is independently bound to #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`: location `0x56dfbf8`, line 107, column 37; old caller `0x32725d0`, call `0x3272785` via slot `0x57755a8`, and target `0x3273810` comparing against 2 at `0x3273871`. The optional old-artifact check validates those #94 coordinates and the #115 extraction validates its own Location and instructions separately. It does not equate the old and new function layouts or prove equal behavior.

### Previously mapped entry and state writes, rechecked as context

| Context step | Pinned #115 observation and limit |
| --- | --- |
| Loader `0x3c12800` | After a comparison at `0x3c128d4`, the equality branch writes the request word to state `+0x10`, saturating-increments `+0x18`, and clears `+0x10e8` at `0x3c12904`. This packet checks those instructions but does not reclaim the loader or its existing indirect call. |
| Owner and worker | Pending #2047 and #2243 describe constructor/callback handoffs into the owner consumed by worker `0x5a6e1e0`. Identity of a live runtime allocation, scheduler selection and absence of alias writes are assumptions, not established by these context windows. |
| Begin `0x5483f50` | Context `0x5483fd3` saturating-increments state `+0x28`, clears state `+0` and stores an argument in three state slots. The selected block-entry-to-begin relation comes from pending #2107. |
| Guarded item `0x560dbb0` | Context `0x560dbcc` saturating-increments state `+0x16b0` before helper calls; when the later 16-bit tag equals `0x1a2`, `0x560dc2b` saturating-increments `+0x16b8`. The alternate tag bypasses the second counter. The existing predicate and helper calls are not newly owned, and intervening writes remain possible. |
| End selection | Pending #2107 identifies an end selector and root-input captures on a selected branch. Complete end behavior and full root equivalence are not established here. The result branch continues below. |

These are contextual observations in previously proposed functions, not newly selected FDEs. They anchor a possible loader-to-state-update-to-result route subject to all of the cited proposals' separate assumptions; the new contribution begins at the result-container helpers.

### Row flow on the selected branch

| Stage (existing context) | Observation / interpretation boundary |
| --- | --- |
| Engine `0x5a06600` | `0x5a0692e` initializes an index, `0x5a06984` advances it, and `0x5a06993` tests a high-bit sentinel and diverts out of the examined loop before `0x5a06a1a` writes the index alongside 32 copied bytes. The index advances after a completed non-sentinel iteration. Later handling of the diverted item is unresolved, and the statement assumes index arithmetic does not wrap. |
| Projector `0x5961310`; zipper `0x5b30c10` | Pinned operands show 72-byte input and 64-byte projected row strides, then a 40-byte record paired with a 24-byte triple in a 64-byte joined record. The triple is used as capacity, pointer and count on the traced branch. |
| Accumulator `0x4dd0010` | Ring and tree branches use the leading 8-byte key and preserve the remaining 56 bytes. Threshold and copy observations are in the branch tables below. |
| Collector `0x5b785d0` | Ring fetch `0x5b78628` and tree fetch `0x5b78674` stage key and payload separately; selected output stores at `0x5b7892b` emit the payload. A sentinel capacity takes a separate cleanup/empty-result branch. |
| Wrapper `0x4fcb590`, worker `0x5a6e1e0`, serializer `0x531e200` | On the selected return path the engine output triple is forwarded, saved, and passed to the previously identified fingerprint routine. Serializer context reads nested pointer/count at row offsets `0x28`/`0x30`. This is a byte-layout connection, not a claim about the fingerprint value. |

Inferred selected aggregate layout, in bytes: `key[0..8] | identifier[8..40] | capacity[40..48] | pointer[48..56] | count[56..64]`. The collector's corresponding value is `identifier[0..32] | capacity[32..40] | pointer[40..48] | count[48..56]`. Here “identifier” is a descriptive 32-byte field, not a proved state root or authenticated hash. This layout and ordering inference depends on the prior loader-to-block pointer chain, selected non-sentinel branches, unmodified intermediate values, correct helper bindings and normal returns. There is no execution trace establishing that a particular live block follows the chain.

### Newly examined functions and branches

| New FDE start | Descriptive role | Selected evidence |
| --- | --- | --- |
| `0x57ea380`, `0x5812d50` | Ring insertion and circular movement | `index > count` reaches diagnostic call and `ud2` if that call returns. After a capacity check, the shorter-side comparison selects prefix or suffix movement; 64 bytes are copied into the selected slot. The growth helper remains unresolved. |
| `0x515f660`, `0x5b759a0` | Ring-to-tree conversion and ring drain | The drain copies occupied circular segments. Empty/singleton streams bypass sorting; lengths 2–20 call the short sorter, lengths at least 21 use an indirect sorter whose implementation and stability are unresolved. For a well-formed ring drained at the 64-entry conversion trigger, this is the indirect-sort branch; the short sorter is a separate helper branch. |
| `0x53ef8f0`, `0x4d5f920` | Short sorting and adjacent-key reduction | Pinned comparison/move windows show ordered 64-byte records. For an equal-key run, the reducer cleans the previous payload and emits the last row in the sorted run. Without proving long-sort stability this is not necessarily the last row in original input order. |
| `0x4d016b0`, `0x51ef230`, `0x4c71540` | Bulk build, insert and split | Allocation immediates are 720 bytes for a leaf and 816 for an internal node. The examined node stores a count at `+0x2ca`, 8-byte key slots at `+8`, and 56-byte values at `+0x60` with capacity 11. Empty insertion and the selected full-node split pivots are pinned; deeper recursion is not exhaustively proved. |
| `0x51e62a0`, `0x5b98a90` | Tree iteration and tree-to-ring conversion | Iterator bounds and invalid-state branches precede node access. Flattening moves selected key/value pairs to 64-byte entries and cleans the old representation. Reachability of the down-conversion during this loader continuation remains open. |
| `0x52545b0`, `0x59d35b0`, `0x5b232a0` | Tree, joined-row and nested-value cleanup | `drop-table.tsv` decodes 13 signed table entries for tags 0–12 from file-backed ELF bytes; a separate tag-15 route is pinned. Exact source enum names and all ownership/alias guarantees remain unknown. |

The context accumulator tests the representation and count before any lookup. If its leading word is the high-bit sentinel and count is below 32, it selects tree-to-ring conversion. On the ring representation, a nonzero lookup result together with count at least 64 selects ring-to-tree conversion; a zero lookup result or a count below 64 does not take that conversion branch. Thus counts 32–63 alone do not fix the representation. `transition-cases.tsv` enumerates boundary models; the lookup result is described as nonzero rather than asserting unproved semantic names for every helper return.

For the observed full-node split decision, `pivot-cases.tsv` models index 0–4 using pivot 4 on the left, index 5 using pivot 5 on the left, index 6 using pivot 5 on the right at local index 0, and indices 7–11 using pivot 6 on the right at local index `index - 7`. These rows derive from the pinned immediate operands and branch encodings; they are testable models of one decision, not runtime samples.

### Failure and unwind boundaries

The selected allocation sites include null-result branches, capacity and multiplication limits; selected ring and iterator guards reach diagnostic calls and/or `ud2`. `unwind.tsv` preserves 86 parsed LSDA call-site rows across selected FDEs; `unwind-links.tsv` records 41 selected calls: 35 match a call-site range, 4 have no listed matching range, and 2 belong to an FDE without LSDA. The parser accepts the encodings observed here and preserves landing-pad/action values but does not reconstruct action chains. A missing row is not a proof that no cleanup or unwind exists. The packet does not infer rollback, absence of side effects, or a successful response for any failure branch.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker flags, two-build comparison, normalized masks, function equivalence, indirect target closure, data/vtable closure and whole-ELF comparison: not yet implemented/measured. The generated records are target-grounded static inputs for a future independently authored implementation, not recovered Rust source or proof of runtime equivalence. No node or visor was executed, and no node networking, keys or chain action was used. Public repository metadata and PR contents were consulted read-only for overlap review.

## Results and limitations

The packet checks 14 selected FDE starts and exclusive ends, 12 context FDEs, 58 selected and 36 context windows, 134 selected transfers, 27 decoded operands, 13 cleanup-table entries, 86 LSDA rows and 41 call records, including 35 LSDA matches. These are selected-record counts, not coverage denominators for the component or binary. The focused suite has 24 passing tests with no skips, including target-hash rejection, mutated windows and instruction patterns, invalid FDE/relocation/range controls, `SHT_NOBITS`, table corruption and the threshold/pivot boundary models. Two independent generations with differing hash seed and timezone must match byte-for-byte; the supplied manifest binds the checked-in evidence.

The selected dataflow is conditional, and the entry and endpoint are context supported by earlier #115 work. State-root provenance, all action variants, long-sort behavior, full tree recursion, helper identity/closure, scheduler/alias effects and the fingerprint algorithm remain open. No component progress gate is requested. Next question: resolve the indirect long sorter and its equal-key ordering, then establish whether duplicate keys or tree-to-ring conversion can actually occur along this loader-driven path.
