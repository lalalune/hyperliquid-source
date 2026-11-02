# RE-009: ActionDelayer snapshot field and compatibility decisions

The node #94 state reader requires six ActionDelayer map fields but defaults the missing mode and scale, and its `status_guard` is read with the type name `BucketGuard`; this enables a reconstruction to preserve older state inputs without modeling that guard as the boolean suggested by the unlicensed reference.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only to select a question and compare labels.
- Claim status: static observation for selected instructions, addresses, strings, branch targets and literal bits; inferences for state type names and the compatibility interpretation; unresolved for nested payloads and full snapshot files.
- Scope included and excluded: the selected MessagePack-shaped state writer and mode writer, one MessagePack-shaped reader, its two key matchers, named-field helpers, and selected positional length decisions. Excluded are the inner queue and map encodings, the `BucketGuard` reader body, unknown-value helper behavior, JSON, unselected sequence-reader behavior, actual snapshot entry points, other releases, runtime execution and filesystem effects.

## Reproduce

Run from the repository root with Python 3.12.3 or a compatible Python 3, using the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/delayer_snapshot94.py --out work/delayer-check-a
python3 tools/delayer_snapshot94.py --out work/delayer-check-b
diff -r work/delayer-check-a work/delayer-check-b
cmp work/delayer-check-a/codec.json research/work-items/RE-009-delayer-snapshot-94/codec.json
cmp work/delayer-check-a/fields.tsv research/work-items/RE-009-delayer-snapshot-94/fields.tsv
python3 -m unittest tests.test_delayer_snapshot94
(cd research/work-items/RE-009-delayer-snapshot-94 && sha256sum -c MANIFEST.sha256)
```

The generator authenticates the full target SHA-256 before ELF parsing; it reads only file-backed allocated sections, rejects `SHT_NOBITS`, and imports the shared section and CIE/FDE parsers. It extracts only fixed instruction forms and selected signed displacements. It invokes no external program; the target is read as data and is neither executed nor emulated. Evidence is independent of binutils output, time zone, hash seed and working directory. GNU objdump 2.42 was used only for human inspection of bounded windows. The manifest records the output and README hashes. No network, live state, chain data or keys are used.

## Evidence

All addresses below are unrelocated ELF link-time virtual addresses; `codec.json` also records file offsets, FDE record addresses, exclusive FDE ends, full selected-body hashes, raw compare/branch bytes and the signed table entries. FDE extents describe unwind ranges and alone do not establish all source-level function boundaries. The extraction is complete for the listed fixed compare chains and selected sites, not a linear decode of the whole reader or a coverage census.

### Outer writer and state layout

The writer `0x2311e90..0x2312134` calls one header helper with field count 8 when its context byte `+0xb` is nonzero and another with count 8 when it is zero. The existing [EVM state wire packet](../RE-009-evm-state-wire-94/README.md) identifies those shared helpers as map and array writers. For the supported context byte values 1 and 0, respectively, the selected writer emits names or positional values in this order. `fields.tsv` includes every key reference, child call, case and duplicate edge.

| Order/tag | Key | Source object offset | Reader case | Map-end missing decision |
| --- | --- | --- | --- | --- |
| 0 | `delayed_actions` | `+0x30` | `0x176a997` | missing-field diagnostic |
| 1 | `user_to_n_delayed_actions` | `+0x48` | `0x176ab8c` | missing-field diagnostic |
| 2 | `n_total_delayed_actions` | `+0x60` | `0x176aa91` | missing-field diagnostic |
| 3 | `max_n_delayed_actions` | `+0x68` | `0x176aae4` | missing-field diagnostic |
| 4 | `vty_trackers` | `+0x70` | `0x176aa12` | missing-field diagnostic |
| 5 | `status_guard` | `+0x20` | `0x176ac0b` | missing-field diagnostic |
| 6 | `delayer_mode` | `+0x00` | `0x176ac67` | default selected |
| 7 | `delay_scale` | `+0x88` | `0x176ab37` | default selected |

These are conditional on successful earlier parsing and child results. Each of the eight reader cases has a seen-state branch leading to its own key and the `duplicate field` template. After the map loop, the first six absence checks lead to the respective `missing field` template in table order; the final two take other paths. The ninth case invokes an unanalysed helper with argument 1, so the packet does not claim what happens for arbitrary unknown values.

The writer tests child or key results after each stage. Its selected header and field branches are recorded individually in `codec.json`; failures reach local result-copy paths before later fields. This is evidence about control transfer, not proof of allocator, I/O, or nested writer behavior. The existing [action-delay queue packet](../RE-004-action-delay-queue-94/README.md) independently connects this object to node state and describes queue operations, a different question from the codec decisions here.

### Positional length decisions

The same reader has a positional route. Conditional on each preceding child succeeding, counts 0 through 5 take the corresponding numbered length-error route before the missing element's child is called. The six checked child calls and their failure destinations are in `codec.json`. When the first six children succeed and there is no seventh element, the reader selects tag 1 with zero metadata for the mode. It then calls `0x16fde80..0x16fdefe` for the scale: the helper checks a remaining-count word, returns an absent indicator when it is zero, and otherwise calls its floating-point child. The caller uses 1.0 for the absent indicator and the child's value when present. A nonzero remaining count at the later completion check takes an error-construction path or a bounds-failure branch. Thus the evidence supports the six-element compatibility route and identifies the seven- and eight-element calls, conditional on child success; it does not establish a complete arbitrary sequence decoder or acceptance of corrupt elements.

### Default fields and nested guard

At map completion, an absent `delay_scale` selects the eight bytes at `0x20a730`, `00 00 00 00 00 00 f0 3f`, and stores them at the selected object result's `+0x88`: binary64 1.0. An absent `delayer_mode` selects tag 1 and clears two associated words before constructing the result. The mode writer `0x23d8e00..0x23d8ef9` checks for tag 1, supplies the eight-byte literal `PerAsset` and passes the payload at `+0x08` to a child; its other branch supplies `Enabled`. Interpreting the zero metadata as an empty payload is consistent with the earlier queue layout, but the child payload and invalid in-memory tags are not validated here.

The `status_guard` case passes the exact eleven bytes `BucketGuard` and their length to a child at `0x176ac39`. Inference: the persisted field is a nested guard value rather than the reference's boolean. The already documented [validator state wire packet](../staking-validator-state-wire-94/README.md) describes a separately encountered guard structure; this packet neither reanalyses that shared writer nor establishes every nested guard byte.

A human-read excerpt of the key default decisions (the generated records use ELF bytes, not this excerpt):

```text
1769cba: test BYTE PTR [rsp+0x3b0],0x1
1769cc4: movq xmm0,QWORD PTR [rip+... ]  # 0x20a730
1768c8c: cmp r13,0x2
1768c92: mov r13d,0x1
```

### Key matching and failure controls

The reader's key classifier calls `0x22ecd20` or `0x22ed250` on the selected string routes. The first uses 128 explicit byte-compare instructions plus a three-way first-byte selector. The second uses two overlapping-word cases, three overlapping SIMD cases, and three 12-byte word cases. Their length dispatches each cover the 15 lengths from 11 through 25. Both yield the same eight key/tag pairs in the table above; other tested lengths and substitutions yield tag 8. `codec.json` preserves all compare bytes and both sets of extracted constants, and verifies all selected mismatch and table edges. These are static predicates, not complete MessagePack input executions.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, native differential execution, whole-function equivalence, relocation normalization, call closure or external fixture was attempted. Normalization masks: none. The focused tests include wrong input identity, missing byte ranges and `SHT_NOBITS`, altered FDE-admitted instructions, both matcher tables and SIMD data, child-call and conditional-branch corruption, all six absence-branch corruptions, sequence length and optional-value branches, duplicate/missing literals, the mode branch and the scale constant. A synthetic predicate checks all 33,405 single-byte replacements of the eight extracted keys; these are negative controls for the static key rules, not target executions.

## Results and limitations

The generator records 8 selected FDE-described ranges, 8 fields, 6 missing-field checks, 8 duplicate-field paths, 6 positional prefix checks, 2 key matchers and 15 selected writer branches. Eighteen focused unittest methods pass. Two generator runs produce byte-identical `codec.json` and `fields.tsv` under differing hash seeds and time zones with a Python-only executable search path. The results bind only to the stated #94 digest and do not establish a full snapshot schema, on-disk compatibility, behavior of the nested maps or successful restoration of a real snapshot. No full-scope milestone gate is requested.

Next question: determine the `BucketGuard` and queued-action child representations along this reader's selected calls, then validate complete synthetic fixtures in an explicitly authorized offline harness.
