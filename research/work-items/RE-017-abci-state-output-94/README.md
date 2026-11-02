# RE-017: node 94 loaded-state order export

A state.rs:86 loader result reaches a conditional temporary-map export whose MessagePack-shaped and JSON-shaped writers consume the same tagged record layout and independently name the same 16 order fields, giving a reconstruction a concrete output boundary and field offsets.

- Component ID: `abci` / RE-017, bounded to the state-loader result's order-export path.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed reference `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation is copied.
- Claim status: the listed byte operands, FDE ranges, calls and conditional branches are observations. Order, map and format names are functional inferences from the observed fields, storage and previously established writer markers. Runtime reachability, source types and complete serialization are unresolved.
- Scope included and excluded: 22 previously unowned FDE extents and the selected path, field and failure witnesses. The earlier `0x22ae8a0` loader caller, `0x28c66b0` processor and `0x28cb9f0` sink are boundary context, not newly claimed functions; the earlier loader GOT and call site are not re-owned. The previous state.rs:107 loader and this state.rs:86 loader share an earlier identified callee, but identity or dataflow between their results is not established. Node #115, visor, other branches and full block application are excluded.

## Reproduce

Run from the repository root with Python 3.12 or newer and its standard library. The tested environment was Linux x86-64, CPython 3.12.3. The generator authenticates the full input SHA-256 before parsing, imports `tools/elf_index.py` and `tools/fde_extents.py`, rejects SHT_NOBITS and ambiguous file mappings, and decodes only fixed byte patterns. It neither executes the target nor invokes external programs. Human review additionally used GNU objdump 2.42 on bounded addresses; that text is not an input to generated records.

```sh
python3 tools/abci_state_output94.py --out research/work-items/RE-017-abci-state-output-94
python3 -m unittest -v tests.test_abci_state_output94
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_state_output94.py --out work/abci-state-output-a
PYTHONHASHSEED=271 TZ=Pacific/Honolulu python3 tools/abci_state_output94.py --out work/abci-state-output-b
diff -r work/abci-state-output-a work/abci-state-output-b
(cd research/work-items/RE-017-abci-state-output-94 && sha256sum -c MANIFEST.sha256)
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The generator emits `functions.tsv`, `extents.tsv`, `windows.tsv`, `edges.tsv`, `branches.tsv`, `fields.tsv`, `field-layout.tsv`, `text-fields.tsv` and `summary.json`. `extents.tsv` retains original bytes; `windows.tsv` distinguishes boundary context from new extents. The manifest also hashes this README. No normalized bytes or external disassembly are generated.

## Evidence

All code and data addresses are ELF link-time virtual addresses. File offsets, FDE/CIE coordinates and raw bytes are in the generated tables. The selected FDE records are reconciled with the unwind header and each complete extent is hash-pinned; an FDE range alone does not prove a complete source-function boundary. The tables contain selected sites and branches, not a whole-binary call census or proof of dynamic reachability.

### Input, temporary map and branch selection

Prior [RE-020](../RE-020-path-field-thunk-94/README.md) binds the path-field call at `0x22aec0f` to the state.rs:86 loader thunk. The new boundary window immediately following that existing call shows `rdx = rsp + 0x1f0` and `r9d = 0`; the prior [state inventory](../abci-state-inventory-94/README.md) records the following transfer to `0x28c66b0`. The processor keeps this pointer in `r12`. On the no-height arm and when the first argument's low byte is not 2, it reads a base at input `+0x5c0`, a count at `+0x5c8`, and computes an end using stride `0x2f0`; the subsequent loop advances by the same stride. On a selected continuation, an unsigned 64-bit word at `[r13+0x30]` is multiplied by `10000`; overflow branches to `0x28c6d25`. If the product fits, adding the current `rdi` value branches on carry to `0x28c6d34`. The largest word whose product fits is `1844674407370955`; the addition also requires the addend not to exceed the remaining unsigned range. These bounds describe the checked register operations, not proven reachable inputs. The intervening traversal and its helpers are only partially covered, so the field's source-level type and the path's actual invocation remain unknown.

On the selected traversal, the low bit of the second argument chooses whether to call record converter `0x2519180`. The processor supplies the first argument's byte as the converter's flag. The resulting value or the alternate sentinel form is passed to the temporary ordered-map updater `0x2862490`. A matching key takes the replacement path: a prior `0x48`-byte value is copied to the output and the new value occupies its slot. An empty root takes the allocation and insertion path; a nonempty unmatched search calls another helper before the count increment if that helper returns normally. This is a temporary export map, not a demonstrated mutation of the node's live consensus state.

After the selected loop, the map and path-like byte span go to boundary sink `0x28cb9f0`. On the no-height arm, a nine-byte span equal to `/dev/null` jumps directly to the return path. Otherwise a predicate chooses between the following paths. The prior [bridge state JSON packet](../bridge-state-json-94/README.md) associates the same predicate slot with a case-insensitive `rmp` extension test. If that earlier slot binding applies here, its nonzero arm identifies that extension; this packet does not re-own the relocation or independently revalidate path handling. Final file helpers remain outside this packet:

| Predicate result | Newly traced route | Bounded observation |
| --- | --- | --- |
| Nonzero | `0x25dd540` -> `0x2566730` -> `0x1e37f00` | Collect entry pointers, then use the binary writer. |
| Zero | `0x25e7da0` -> `0x2566730` -> `0x290ea20` | Collect the same form of entry pointers, then use the text writer. |

The collector uses `0x10` bytes per entry and stores a key pointer and a value pointer. Its empty and allocation-failure choices are recorded separately. The binary sink initializes a control word to bytes `00 04 00 01` and the following byte to zero; thus the passed serializer initially has byte `+0xb = 1` and `+0xc = 0` on that arm. Intervening helper effects on those bytes are not fully closed; later claims that depend on them are conditional on their values at the relevant writer. Existing [RE-009](../RE-009-evm-state-wire-94/README.md) identifies the called map, array and string marker helpers as MessagePack-shaped; this packet does not re-own those helpers. The text path stores bracket, brace, quote, comma/newline and colon/space bytes, but escaping and all scalar encodings remain helper boundaries.

### Record and container representations

The converter advances input by `0xc0` and output by `0xc8`, storing an eight-byte tag followed by a `0xc0`-byte payload. These rules apply only when the converter is reached:

| Flag byte | Tag | Bytes copied into the temporary payload before the output copy |
| --- | --- | --- |
| Zero | 1 | `0xa8` bytes from input offset `+0x18`; the other `0x18` stored payload bytes are not established by that copy. |
| Nonzero | 0 | `0xc0` bytes from the input start. |

On successful binary serialization when byte `+0xc` is still zero and the collected entry count fits 32 bits, the initialized wrapper takes the selected sentinel path and each outer entry uses a two-element key/value sequence. The larger-count wrapper path remains unclosed. `0x28c7b10` tests the value's first word. The sentinel `0x8000000000000000` takes the direct `SideMap` route. Otherwise, with serializer byte `+0xb = 1`, it writes the names `book_orders` and `untriggered_orders` in that order; the first points to two side lists and the second to another list. The text writer separately has the same sentinel split and the same two key references. These are conditional normal paths, not a claim that a particular input selects either variant.

The binary list writer tests a **four-byte** tag against 1: equality calls order writer `0x23367a0` on record `+8`, while the other branch writes a pair whose order element starts at `+0x20`. The text list writer tests a **one-byte** tag against 0: nonzero calls text order writer `0x2336310` on record `+8`, while zero takes its pair path. The selected converter produces only tags 0 and 1, for which those decisions agree. As a synthetic corruption control, tag 2 selects different branches; no claim is made that the selected producer emits it. The first pair element passes 20 input bytes and a 42-byte destination bound to a formatting helper; the exact formatted representation is unresolved.

### Named order fields

On successful named binary output, `0x23367a0` requests a 16-entry map. The independent text writer references the same literal bytes in the same sequence. `children` is named in a separate adapter in each route. Offsets below are the observed loads or address calculations relative to the order pointer; they do not establish the complete original Rust types or padding. The exact instruction and name references are in `field-layout.tsv`, `fields.tsv` and `text-fields.tsv`.

| Order | Field | Observed order offsets |
| --- | --- | --- |
| 1 | `coin` | `+0x8`, `+0x10` |
| 2 | `side` | `+0x90` |
| 3 | `limitPx` | `+0x60` |
| 4 | `sz` | `+0x68` |
| 5 | `oid` | `+0x70` |
| 6 | `timestamp` | `+0x78` |
| 7 | `triggerCondition` | `+0x20`, `+0x28` |
| 8 | `isTrigger` | `+0x91` |
| 9 | `triggerPx` | `+0x80` |
| 10 | `children` | address `+0x30` |
| 11 | `isPositionTpsl` | `+0x92` |
| 12 | `reduceOnly` | `+0x93` |
| 13 | `orderType` | `+0x50`, `+0x58` |
| 14 | `origSz` | `+0x88` |
| 15 | `tif` | address `+0xa5` |
| 16 | `cloid` | address `+0x94` |

In the binary writer, the low bit of the byte at `+0x90` selects the one-byte literal `B` for zero and `A` for one. The children adapters reach separate list writers using `0xa8` element stride and call their respective order writers recursively. Successful traversal is conditional on each preceding helper succeeding; the table is not a claim about bytes after a failed write.

### Failure and boundary decisions

| Condition | Observed branch or consequence |
| --- | --- |
| Checked source multiplication or subsequent addition overflows | `0x28c6810` -> `0x28c6d25` or `0x28c681c` -> `0x28c6d34`, respectively; both reach failure calls followed by `ud2` if those calls return. |
| Converter allocation is null | `0x25191de` -> `0x25192f7`, allocation-failure route. |
| New map-node allocation is null | `0x286271a` -> `0x2862819`, failure call and `ud2`. |
| Map-node count is at least 11 at its checked site | `0x2862784` -> `0x286282b`, diagnostic route; a newly allocated node was initialized to zero earlier. |
| Binary header, entry, field or child helper reports the checked non-success result | Selected checks branch to their error-copy/cleanup paths; the sink branches at `0x28cbb80` to `0x28cbf0a`. |
| Text child or order helper returns nonzero | Selected checks return the nonzero value through list/entry adapters; the sink branches at `0x28cbe06` to `0x28cbf4e`. |
| Text depth counter is all ones or selected internal writer state is invalid | The pinned conditional branches reach the corresponding failure/diagnostic helpers. |

The sink's subsequent diagnostics, I/O outcomes, unwinding behavior and propagation to its caller are not fully closed. A failed write may already have changed the temporary output buffer. The exact 131 selected conditional branches, including fallthroughs and targets, are in `branches.tsv`.

## Implementation and comparison

Not yet implemented. No independent Rust component, Cargo build, behavioral execution, captured-node execution, raw binary comparison or normalized comparison is claimed. No bytes are masked. The tests exercise parsing and synthetic comparison controls, not the node. Helper internals, indirect call targets, relocation and vtable/data closure, complete CFG reachability and whole-ELF equivalence are not established.

## Results and limitations

The generated packet records 22 selected FDE extents, 39 owned and 20 boundary windows, 34 selected direct transfers, 131 conditional branches, two independently named 16-field sequences, 19 order-operand rows, eight label references and seven selected text literal stores. These counts describe only this packet's selected sites; they are not total function coverage or a matched-window denominator. Nineteen focused tests pass with zero skips, including 262 individual branch mutations, 68 transfer mutations, arithmetic boundary cases, corrupt target hash, altered FDE range, altered selected and boundary bytes, changed field name and operand, bad call and branch encodings, reordered text fields, SHT_NOBITS, ambiguous and out-of-range mappings, and the synthetic tag controls. Two outputs regenerated with different hash seeds and time zones compare byte-for-byte.

The first ABCI component task still requires begin/action/end-block paths and state-root inputs. This packet does not complete that task or request a progress gate; the component remains 0/4. Next question: bind the state.rs:86 result's producer and the processor's unexamined traversal to the actual state-root inputs, while separately validating the sink predicate binding and final I/O behavior.
