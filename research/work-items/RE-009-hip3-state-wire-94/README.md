# RE-009: nested four-field state codec

Node #94's nested state codec writes four ordered fields and its MessagePack-shaped reader accepts shorter positional forms with defaults for the last two, allowing a reconstruction to preserve those compatibility choices and duplicate-key failures.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead.
- Claim status: observation for the byte windows, FDE records, named fields, selected branches and calls; inference for the codec and type interpretation; unresolved for complete field semantics and runtime snapshot compatibility.
- Scope included and excluded: selected nested reader, classifier and writers; selected JSON-shaped reader; no full ABCI state, complete input grammar, runtime I/O, other versions, target execution or Rust equivalence.

## Reproduce

From the repository root, using Python 3 and the standard library plus the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/hip3_state_wire94.py --out <tmp-dir>
cmp <tmp-dir>/evidence.json research/work-items/RE-009-hip3-state-wire-94/evidence.json
python3 -m unittest tests.test_hip3_state_wire94
```

The collector authenticates the input before parsing. It reads ELF sections and actual `.eh_frame` records using the shared parsers, rejects NOBITS mappings and ambiguous ranges, checks each selected body hash, and extracts names, selected direct-call displacements and signed tables from bytes. It invokes no external program. GNU objdump 2.42 was used only for manual inspection. Addresses below are unrelocated ELF virtual addresses; FDE ends are exclusive. FDEs alone do not prove complete source functions or cold-part closure. No operand masks are used.

## Evidence

`evidence.json` retains five FDE-described extents and body hashes, selected byte windows, field-name sites, the classifier length table, the reader's five-way dispatch, selected direct calls and the relocated diagnostic. The selected MessagePack-shaped reader is `0x1a4a5c0..0x1a4bb02`, its key classifier is `0x16ccf80..0x16cd0e6`, and the writer is `0x233e900..0x233eb9d`. A JSON-shaped reader `0x1ccc5f0..0x1cccff7` and writer `0x233e730..0x233e8f3` expose corresponding named-field operations. The previously studied outer state-wrapper reader calls its nested exchange decoder; within that decoder the contextual call at `0x1a5b948` targets this packet's reader. The parent is context only, and is not remapped here. This does not establish that all snapshot entry paths use both formats.

The reader's short-sequence error passes a descriptor through the relocation at `0x5685e58` to the 51-byte diagnostic `struct Hip3BackstopLiquidatorParams with 4 elements`. The type name is an inference from this diagnostic, not a recovered source declaration. The writer field arguments, in order, are:

| Classifier tag | Name | Selected writer input |
| --- | --- | --- |
| 0 | `m` | byte at input `+0x20`, selecting one of three one-byte strings |
| 1 | `half_life` | option-like tag at `+0`, value at `+0x8` when tag is 1 |
| 2 | `max_slippage` | floating-point load at `+0x10` |
| 3 | `max_n_depositors` | word at `+0x18` |

The classifier compares exact lengths and bytes, producing tag 4 for other keys; its length table has recognized destinations at lengths 1, 9, 12 and 16. The map dispatch table sends tags 0 through 3 to distinct presence checks. A second occurrence of each recognized field goes to a duplicate-field diagnostic carrying that field name. The tag-4 route invokes a child helper; its full treatment of unknown values is not established. Child errors, truncation and nesting-depth failures have separate paths and are not treated as successful parses.

On the positional route the zero- and one-element cases reach the short-sequence diagnostic. After two successful child reads the reader can use a zero floating-point default and the integer `1000` for the remaining values; a third successful child replaces the floating-point default and a fourth replaces the integer default. A larger count reaches an extra-element error path. These are conditional on preceding child success, not claims that arbitrary values of those lengths are valid. The map completion path separately tests presence slots before selecting zero and `1000` defaults; the complete value grammar and the meanings of its other option-like representations remain open.

The writer selects the four-entry map helper for mode byte `+0xb` equal to 1 and the four-entry array helper for 0. In the former mode it emits the four names in table order, and in both modes it emits corresponding values. It returns early on selected helper failures. The option-like half-life value takes a direct `0xc0` write on the non-1 tag arm; the tag-1 arm calls a scalar writer. Mode values other than 0 and 1 are not characterized. The JSON-shaped reader compares the same name bytes and has distinct duplicate-key branches; the JSON-shaped writer names the same fields in the same order. Exact JSON formatting and all nested value grammars are outside this packet.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No binary comparison, execution, fixture, compiled identity, call-target closure or on-disk compatibility test is claimed. The eight focused unittest methods include wrong target digest, an altered classifier with a recomputed digest, an altered field literal with a recomputed digest, an out-of-range dispatch target, an invalid call opcode and an unmapped address. These controls validate the collector's bounded observations, not target behavior.

## Results and limitations

Five selected FDEs, four named fields, a 16-entry length table, a five-entry tag table and 17 selected direct calls are recorded. Two regenerations with different hash seeds and time zones were byte-identical; eight focused tests passed. Artifact verification and catalogue consistency passed. No full-component progress gate is requested. The called scalar readers, all malformed marker cases, unknown-value helper, actual state snapshot mode and cross-release compatibility remain unresolved. Next question: resolve the `m` variant and half-life child readers and connect this nested value to a complete, separately authorized offline fixture.
