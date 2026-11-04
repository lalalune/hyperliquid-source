# RE-017: loader-fed item preparation and ordered block handoff

A conditional node #115 path carries the loader-fed expanded-state cell into item preprocessing, writes a verified three-copy key representation, and groups prepared rows in an order different from the order of its predicate tests; an independent reconstruction can therefore preserve both the state input and the selected ordering before the block handler runs.

- Component ID: `abci`; RE-017's state and root handoff also supports RE-009.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed navigation reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference code was copied. The retired #94 packet is available in the parent of the source commit.
- Claim status: ELF bytes, selected FDE ranges, relocations, fixed instruction operands, direct transfers, and LSDA rows are observations. Pointer continuity, chosen inputs, stable bucket ordering and the connection to earlier state and root work are conditional inferences. Runtime reachability and source-level type names remain unresolved.
- Scope included and excluded: one selected non-splitting outer/inner item route, selected precheck alternatives and failure edges, a four-group merge, and the conditional handoff to the previously investigated block handler. Previous loader, engine, allocation, guard, classifier, item-handler and root bodies are context rather than newly owned functions. The process entrypoint, every item and parallel scheduling branch, all state-root inputs, full block behavior and all component gates are excluded.

## Reproduce

From the repository root with the authenticated target and repository ELF/FDE readers present, use fresh writable output directories. Replace `<tmp-dir>` and `<python-only-path>` with suitable values for the environment:

```sh
python3 tools/abci_item_prep115.py --out research/work-items/RE-017-abci-item-prep-115
PATH="<python-only-path>" PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_abci_item_prep115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PATH="<python-only-path>" PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_item_prep115.py --out "<tmp-dir>/first"
PATH="<python-only-path>" PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_item_prep115.py --out "<tmp-dir>/second"
diff -r "<tmp-dir>/first" "<tmp-dir>/second"
diff -r -x README.md -x MANIFEST.sha256 "<tmp-dir>/first" research/work-items/RE-017-abci-item-prep-115
(cd research/work-items/RE-017-abci-item-prep-115 && sha256sum -c MANIFEST.sha256)
```

Generation and focused tests used Python 3.12.3 on Linux x86-64. GNU objdump 2.42 was used only for bounded human inspection; neither the extractor nor the tests invoke external programs or parse its text. The extractor authenticates the complete #115 input before writing, uses `tools/elf_index.py` and `tools/fde_extents.py` for sections, unwind headers, CIE/FDE and ULEB parsing, excludes fileless NOBITS mappings, and emits 13 deterministic evidence files. Inputs and outputs are static; the node and visor were not executed, and no network, keys, chain data or runtime state were used. `MANIFEST.sha256` covers this README and the generated files.

## Evidence

All code and data coordinates below are linked ELF virtual addresses before load bias. The generated tables provide file offsets and raw bytes. `functions.tsv` records complete, unmasked bytes and SHA-256 for each of 14 selected FDE ranges; `windows.tsv` separates 18 context windows from new ranges. `fields.tsv` and `patterns.tsv` pin the selected instruction operands and register transfers, while `transfers.tsv` decodes only its listed instruction-aligned calls, branches and RIP references. `unwind.tsv` and `unwind-calls.tsv` retain selected LSDA call-site ranges and landing coordinates, not the full language-level exception actions. An FDE is an unwind range, not proof of a complete function boundary or a census.

### Entry and state-cell identity

Earlier #115 proposals `RE-017-abci-loader-handoff-115`, `RE-017-abci-greeting-115`, `RE-017-abci-compact-root-115`, `RE-017-abci-block-root-115`, and `RE-017-abci-expanded-result-115` describe selected loader, owner, begin, action, end and root boundaries. The present packet does not claim their functions or existing call sites. The old link's #115 Location is independently checked at `0x64767a8`, `state.rs:123:37`, with a comparison against 1. The newly selected mapper's separate Location is `0x64aa260`, `state.rs:340:21`, referenced at `0x5618a3b` on its length-mismatch arm.

On the selected existing engine continuation, `0x5a06727` forms cell `P = context + 0x450`; the engine saves and later reloads that cell before passing it to the existing collector. The collector puts `P` at its input descriptor `+0x18`. Its existing reserve call copies the 32-byte descriptor into the boundary driver `0x5b5bac0`. This packet checks the latter's contextual call at `0x5b5bb6e`, which passes the address of a saved pointer to that descriptor field to the new outer collector. The mapper at `0x5618990` dereferences the saved pointer twice and places `P` at offset `+0x28` in its local descriptor. The new append and dispatch functions copy that field, pass an address to it through their descriptors, and the new worker at `0x5b361cc` dereferences the holder and then `P` before supplying the resulting state pointer to `0x5921480`. `fields.tsv`, `patterns.tsv` and `joins.json` check these offsets, the two stack argument positions and the relevant register moves.

Thus, assuming the selected calls return normally, the intended branch is taken, the ABI and copy bindings hold, and no intervening helper or alias changes the saved cell, the precheck receives the same state-pointer value loaded from `context + 0x450`. Previous loader/owner packets provide the separate conditional connection from the Location-linked loader to this context. Neither this arithmetic nor matching offsets prove runtime scheduling, allocation identity, or alias stability.

### Selected functions and data flow

The following compact map joins the newly selected bodies with prior-context
boundaries. The first arrow is the conditional loader-to-owner inference from
the earlier packets; the return arrows summarize normal control and object
forwarding, not direct calls between the named return endpoints:

```text
Location-linked loader 0x3c13520 --[prior conditional owner handoff]--> engine 0x5a06600
  -> collector 0x54864a0 -> reserve 0x564bab0 -> driver 0x5b5bac0
  -> outer 0x5b3a2d0 -> mapper 0x5618990 -> append 0x564b740
  -> driver 0x5b5c2d0 -> dispatcher 0x57c3a60 -> worker 0x5b35f80
  -> precheck 0x5921480 -> [return prepared rows to collector]
  -> prior continuation 0x59618e0 -> [prior guarded dispatch] -> guard 0x5868030
  -> prior classifier 0x548c8e0 -> merge 0x5b6ee00 -> [return ordered rows]
  -> prior projector 0x5b324b0 -> item loop 0x5865d80 -> handler 0x54851a0
  -> [prior conditional state updates and root child]
```

| Selected FDE start | Observed role on this route |
| --- | --- |
| `0x5b3a2d0` | Outer 32-byte-row collector; maps an entry through `0x5618990`, stores a returned 32-byte object, checks capacity, and has separate direct, split, sentinel and cleanup arms. |
| `0x5618990` | Checks that parent `+0x10` equals input `+0x18`, carries the state cell into a temporary descriptor, and calls `0x564b740`; inequality reaches the `state.rs:340:21` diagnostic. |
| `0x564b740` | Forms a destination using `0x90`-byte stride; calls `0x5b5c2d0`, verifies the returned count, and has growth, underflow, bounds and count-mismatch branches. |
| `0x5b5c2d0` → `0x57c3a60` | Checks the nested input bounds and forwards the worker arguments; selected cleanup and unwind branches are recorded. |
| `0x5b35f80` | Pairs a `0x168`-stride parent input with a `0x70`-stride action input, calls the precheck for tag `0x1a2`, and emits `0x90`-byte rows. Tag `0x1a3` exits the selected loop before that row's store. |
| `0x5921480` | Dispatches the special parent tag `0xba` to `0x4d915c0` and the other arm to `0x4d909b0`; selected returned tags, key copies, map and scan conditions are below. |
| `0x4d909b0`, `0x4d915c0`, `0x4d90d40` | Common, special and value-dispatch checks; selected table entries and the `0x2711` comparison are retained without assigning source-level enum names. |
| `0x4554610`, `0x4716b00`, `0x55ffa50` | Selected 20-byte key search, membership and separate scan used by precheck. The search uses `memcmp`-named relocation and `0x38`-byte entries; membership has empty, singleton and multi-entry arms. |
| `0x5b6ee00` | Joins four classified streams in the order below, checks an allocation-count bound, copies `0x90` bytes per row, and returns a three-word descriptor. |

For the directly examined case of one outer item and one nested item, each worker's half-count check selects its direct arm. Other counts can take split or direct paths depending on additional values; those scheduling paths are not closed here. In a prepared `0x90`-byte row, selected stores place the parent pointer at `+0`, index at `+0x10`, and 16-bit result tag at `+0x20`. The nested result payload begins at `+0x22`. On the successful key branch described next, the first key begins at row `+0x23`; the existing consumer separately reads 16 bytes at `+0x23` and four at `+0x33`. The two offsets are independently joined to the precheck's output offsets `+3` and `+0x13` in `joins.json`.

### One concrete key-preparation branch

Let `K` be the 20 bytes supplied to the precheck and `S = 0x8000000000000000`. The following is a conditional static path, not a captured fixture:

1. The action tag is `0x1a2`, the parent dword at `+0x10` is `0x86`, and the common selector helper returns byte 2. The selector computes index 1 and the relative table entry at `0x914eac` targets `0x4d90a7a`, which returns tag `0x1a2` and the supplied 20 bytes. `tables.tsv` retains four selected entries; values beyond the recorded selector cases are not established.
2. State `+0x4b88` differs from `S` and the qword at `+0x4ba0` is zero. The selected search takes its empty path and returns a low-bit value of 1, so the precheck bypasses its membership lookup. State `+0x398` differs from `S` and `+0x3b0` is zero; the selected scan returns zero.
3. State byte `+0x170a` is 3 and parent byte `+0x150` is zero. The engine's selected earlier mode test checks the same offset and value, subject to the cell/alias assumptions. The precheck writes tag `0x1a2`, flag zero at `+2`, and copies `K` at result offsets `+3`, `+0x17`, and `+0x2b`. These are three separate stores of the same bytes on this particular arm; no claim is made about the rest of the result buffer.
4. The worker places that result in the `0x90`-byte row. The existing classifier places parent tag `0x86` in group A. Under the selected normal copy and merge path, the existing consumer receives the row; on its nonzero gate the already mapped `0x54851a0` receives the row's `+0x20` result object and state cell. Prior `RE-017-abci-expanded-result-115` describes the handler's selected saturating counter/keyed-word updates and the conditional connection to a root child. Those earlier writes and root visitors are contextual dependencies, not new ownership claims here.

For a further **prior-context** handler branch, assume the state qword at `+0x14e8` is 1 and the 20-byte value at offset `+0x48` of the object pointed to by state `+0x14e0` equals `K`. The existing singleton comparison reaches `0x548542b`, where the handler loads and stores state `+0x16b0` using unsigned saturating increment. After two existing indirect helpers, if the second returns tag `0x1a2`, it likewise increments `+0x16b8`. The input key and state-slot handoffs remain conditional as above, and helper side effects are unresolved. These handler instructions are included as context, not claimed as new findings; the counter offsets, selected bytes and saturation boundary model can be independently checked.

The model tests reject every changed prerequisite by returning an unresolved result. They do not imply that this combination is reachable in a running node. Equality of input and output keys also depends on the normal return and selected table entry of the common helper.

### Group order and observable failure boundaries

`buckets.tsv` derives the descriptor offsets and selected merge-loop destinations from pinned fields and decoded branch bytes. A parent tag equal to `0x86` takes A before either predicate. For other tags the first predicate is tested before the second, but a true first predicate assigns C, while a false first predicate and true second predicate assign B. Both false assign D. The existing classifier appends complete `0x90`-byte rows to the corresponding buffers; it initializes the merge mode to 1. On the selected normal path `0x5b6ee00` copies A, B, C, D in that order, preserving each source buffer's traversal order. Thus input order can change across B and C even though C's predicate was tested first. The predicate slots and `memmove` relocation are recorded as contextual dynamic bindings; their runtime implementations and side effects are not established.

| Condition | Selected byte-backed continuation |
| --- | --- |
| Parent length and nested input length differ | `0x56189be` reaches the `state.rs:340:21` diagnostic and `ud2` if its indirect call returns. |
| Inner tag equals `0x1a3` | The worker exits the selected loop before emitting that row. With a single expected row and a zero returned count, `0x564b81d` takes the separate count-mismatch diagnostic; reachability of such an input remains unknown. |
| Parent tag is `0xba` and the selected nested dword also equals `0xba` | The special helper writes result tag `0x121`. A selected unequal 20-byte comparison writes `0x12b`; a separate lookup-miss arm writes `0x123`. |
| A selected precheck key-search hit is in bounds but the following membership lookup returns null | The precheck writes tag `0x124`. A nonzero selected scan result writes `0x81`. |
| Parent optional byte is nonzero and the selected helper returns byte 2 | The precheck writes tag `0x15`. Other helper results and alternate branches require their own conditions. |
| Selected value-dispatch arms compare a qword against `0x2711` | A value at least that threshold reaches a return with tag `0x158`; the table's other entries and helper effects remain separate. |
| Merge count exceeds `0xe38e38e38e38e3` | The selected bound reaches an allocation-failure call and `ud2` if it returns. The bound equals `(2^63 - 1) // 0x90`; a null allocation and later growth each have distinct recorded edges. |

The 20-byte comparisons include 16 byte comparisons and a separate four-byte comparison. The focused synthetic oracle flips all 20 positions; it is not a target execution. The LSDA links identify table coverage and landing addresses only; they do not prove that a particular failure unwinds, that cleanup finishes, or that prior state mutations roll back.

### Historical #94 clue

The retired `RE-017-abci-state-link-94` record is bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. It records caller `0x32725d0`, callee `0x3273810`, Location `0x56dfbf8` at `state.rs:107:37`, and a comparison against 2. That historical binary is not an input to this packet, and its record was not re-executed. The separately authenticated #115 bytes instead show Location `0x64767a8` at `state.rs:123:37` and comparison 1, as well as this packet's independent `state.rs:340:21` reference. This is a release-specific cross-check, not an equivalence claim or transfer of #94 addresses, layouts, tags or behavior.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker settings, two-build comparison, raw and normalized implementation comparisons, masks, helper/call-target closure, relocation/vtable closure and whole-ELF equivalence: **not yet measured**. The captured FDE bytes are evidence only and are not transplanted into an implementation. The selected static traces and synthetic models make no runtime execution claim.

## Results and limitations

The focused suite passed 47 tests with zero skips. Controls cover wrong and changed hashes, every selected FDE body, every pinned operand and register-transfer pattern, every listed transfer displacement, duplicate/mismatched/overlapping FDE records, missing or ambiguous and NOBITS mappings, relocations, LSDA bounds, all 20 positions of a key comparison, selector boundaries, changed pointer/offset joins, merge-count boundaries and bucket-order counterexamples. The synthetic selected-success and bucket models are conditional on the pinned static branch interpretation; they do not execute the node.

`summary.json` reports 14 selected FDEs, 111 pinned operand fields, 28 pinned data-flow patterns, 58 windows including 20 prior-context windows, 134 transfers including 20 context transfers, 2 Locations, 7 boundary relocations, 25 selected jump-table entries, 4 buckets, 78 LSDA rows and 38 selected call-to-unwind links. These are selections rather than coverage denominators. The selected starts and FDE addresses also matched the supplied digest-bound unwind index. No progress gate is requested. The full begin/action/end-block scope, runtime aliases and scheduling, unselected precheck and parallel arms, dynamic predicate/copy implementations, complete cleanup, final state-root value, snapshot compatibility, Rust reconstruction and whole-ELF equivalence remain open. Next question: establish which actual action inputs and callback schedules reach the selected key branch, and whether later helpers preserve the resulting keyed state until the root child is serialized.
