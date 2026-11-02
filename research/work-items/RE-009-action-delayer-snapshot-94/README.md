# RE-009: node #94 action-delayer state serialization and queue records

Node #94's action-delayer state codec supplies the missing-field defaults and duplicate handling for the outer state, and identifies the nested queue record and its two-word ID and broadcaster variants, allowing those snapshot-reader decisions to be reconstructed from the target.

- Component ID: RE-009, storage and state roots; action-delayer state serialization
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` / `999556f6e0a474b8312db96ec3149e1c44e97c23` (`references/can1357-hl`, unlicensed and used only as a lead)
- Claim status: static observations for the listed bytes, FDE extents, offsets and branches; interpretation of layouts and accepted formats is identified below; unresolved items remain open.
- Scope included and excluded: the MessagePack-oriented state writer/reader, the corresponding JSON name and default paths, the mode discriminator, and the delayed-actions queue down through its record, ID and broadcaster codec branches. The existing `RE-004-action-delay-queue-94` packet covers enqueue/release and already identifies the time-keyed tree; this packet addresses different codec functions. The application-state parent linkage is prior evidence in `RE-009-app-hash-builder-94`. Excluded are transition behavior, actual snapshot captures, complete action payload decoding, physical database layout, hash ownership and node #115.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3 and the connected node #94 artifact; the recorded checks used Python 3.12.3. The extractor authenticates the entire input before parsing. It uses only the Python standard library and the repository's shared ELF and FDE parsers; it does not invoke binutils or execute the node. `evidence.json`, `fields.tsv` and `record-fields.tsv` are the complete generated outputs. The manifest also covers this README.

```sh
python3 tools/action_delayer_snapshot94.py --out research/work-items/RE-009-action-delayer-snapshot-94
python3 -m unittest tests.test_action_delayer_snapshot94
(cd research/work-items/RE-009-action-delayer-snapshot-94 && sha256sum -c MANIFEST.sha256)
```

For a separate output use `python3 tools/action_delayer_snapshot94.py --out <tmp-dir>` and compare its three files with the corresponding packet files. The tool records each examined body's SHA-256 and ELF file offset in `evidence.json`; exclusive ends are FDE extents, not proven complete function boundaries. Every recorded pin is file-backed, and NOBITS sections are excluded.

## Evidence

Coordinates below are ELF virtual addresses; `evidence.json` gives matching file offsets and raw byte windows. Names in this section are observed field or variant text, except descriptive function labels, which are inferred. The generator checks the full input digest, 53 selected FDE ranges and body digests, direct call displacements, one uniquely resolved relative relocation, fixed instruction forms, RIP-relative data references and signed dispatch-table entries. It does not parse disassembler text. The ranges are a bounded path, not a node-wide census.

### Outer state and defaults

The field classifier at `0x22ecd20` feeds the reader at `0x1767dd0`; writer `0x2311e90` and the JSON writer at `0x48b23b0` use the same eight names. The table follows the writer's order, which is also the classifier's tag order. Offsets are relative to the in-memory action-delayer object, not wire offsets.

| Tag | Field | Object offset | MessagePack reader case | Missing in map |
| --- | --- | --- | --- | --- |
| 0 | `delayed_actions` | `0x30` | `0x176a997` | diagnostic |
| 1 | `user_to_n_delayed_actions` | `0x48` | `0x176ab8c` | diagnostic |
| 2 | `n_total_delayed_actions` | `0x60` | `0x176aa91` | diagnostic |
| 3 | `max_n_delayed_actions` | `0x68` | `0x176aae4` | diagnostic |
| 4 | `vty_trackers` | `0x70` | `0x176aa12` | diagnostic |
| 5 | `status_guard` | `0x20` | `0x176ac0b` | diagnostic |
| 6 | `delayer_mode` | `0x00` | `0x176ac67` | default below |
| 7 | `delay_scale` | `0x88` | `0x176ab37` | default below |

Each of the eight map cases checks a presence marker and branches to a field-specific duplicate diagnostic. Unknown names select a separate value-skipping call at `0x176ad09`. The corresponding JSON missing and duplicate name sites are recorded in `fields.tsv` and `evidence.json`. The sequence path has missing-element guards for the first six fields, a default route for the seventh and a default route for the eighth; extra elements reach the remainder error path at `0x17698c6`. Child-reader failures can still reject a sequence that has the right number of elements.

The map default path at `0x1768c8c` sets mode tag 1 and clears the tree root and length; its sequence counterpart begins at `0x17695d7`. The mode-name classifier and writer associate tag 1 with `PerAsset`, and tag 0 with `Enabled`. Thus the inferred missing mode is an empty `PerAsset` tree. Both state readers use the same binary64 literal at `0x20a730` (`000000000000f03f`) when scale is absent: 1.0. The mode map reader checks that the outer variant map has one entry; its `Enabled` map arm accepts the nil marker while `PerAsset` delegates its payload to another reader. The writer emits the unit name for `Enabled` and a one-entry variant map for `PerAsset`. These are local codec observations, not a claim about all serializer configurations.

The `PerAsset` payload writer tail-calls `0x25ecca0`; its reader delegates to `0x180e990`, which has map and sequence row paths at `0x2637d80` and `0x267e930`. The map path passes the labels `AssetWire` and `ActionDelayerStatus` to its key and value readers. Both paths insert into `0x2850ce0`, whose comparison uses an unsigned 32-bit key and whose value slot occupies eight bytes. An existing key causes the insertion helper to replace the prior value and return 1, leading both row readers to a `duplicate key` diagnostic. The sequence pair path checks for two elements and rejects a nonempty remainder.

The status writer `0x2313be0` branches on the value slot, and classifier `0x22ef330` independently maps its names to tags:

| Slot | Writer variant | Reader tag | Payload |
| --- | --- | --- | --- |
| zero | `On` | 0 | unit name |
| nonzero | `Alternating` | 1 | `seconds` field |

The alternating reader `0x19b3460` has missing-field and duplicate-field paths for `seconds`. Its number reader calls through slot `0x5770c68`; a unique symbol-free `R_X86_64_RELATIVE` relocation binds that slot to `0x2eb9f30` in this ELF. The raw 24-byte relocation record and its file offset are retained; the extractor rejects duplicate slots, other relocation types for the slot, and REL or RELR sections. The integer routes below are from that function's byte-indexed dispatch table and sign guards. They are local paths, conditional on successful reads of all encoded bytes.

| MessagePack integer form | Markers | Local numeric range reaching success |
| --- | --- | --- |
| positive fixint | `0x00` through `0x7f` | 1 through 127 |
| negative fixint | `0xe0` through `0xff` | none |
| unsigned 8/16/32/64 | `0xcc` through `0xcf` | 1 through the width's unsigned maximum |
| signed 8/16/32/64 | `0xd0` through `0xd3` | 1 through the width's signed maximum |

The inspected integer routes send zero and signed negative values to error construction, and short buffers to a truncation path. The extracted table also contains floating-point and non-integer branches, but their conversion behavior is unresolved. The single relocated slot is resolved independently of the other call-target and relocation closure gaps.

### Queue and record path

The outer writer's queue edge is `0x2311f3a` -> `0x25e5480` -> `0x25781a0` / `0x1e258b0` -> `0x1dee8d0`. In the inspected pair-writing branch, bytes at `0x1deeabd` write marker `0x92`. On read, the queue child `0x1778870` has map and sequence routes. The map row loop calls a key reader with the literal `Time`, then the value reader `0x19da140`, then tree insertion `0x284e5d0`. The sequence route goes through `0x2683490` and pair reader `0x1993520`; zero and one element branch to missing-element errors, and after the two value reads a count other than two takes the excess-length error at `0x1993c18`. Both routes check the insertion return sentinel and, for an existing key, reach a `duplicate key` diagnostic. The old value is replaced before that error is produced; no transaction rollback is asserted.

In the inspected tree insertion comparison, a 12-byte in-memory key is ordered by one signed 32-bit word and two unsigned 32-bit words. This is a description of the memory comparator, not a claim about the on-wire time format or units. The value sequence's loop at `0x24cf220` allocates and advances records in `0x148`-byte steps and calls `0x17b1000` for each value. This independently connects the codec to the existing runtime packet's time-keyed tree; it does not establish the content of every nested action.

The record reader's classifier at `0x22ed680` and writer at `0x2312900` independently match the following names. The table follows the emitted field order; the six duplicate branches and child-reader call sites are in `record-fields.tsv`.

| Tag | Record field | Record offset | Observed codec detail |
| --- | --- | --- | --- |
| 0 | `user` | `0x110` | writer passes 20 bytes to its formatting path |
| 1 | `action` | `0x10` | delegated payload codec |
| 2 | `id` | `0x100` | two nested fields below |
| 3 | `is_frontend` | `0x124` | byte passed to boolean writer |
| 4 | `expires_after` | `0x00` | tag plus payload at `0x08`; absence writes nil |
| 5 | `broadcaster` | `0x125` | tagged payload below |

The ID writer emits `height` then `tx_index`, reading the two eight-byte slots at `0x100` and `0x108`; reader `0x1885ef0` dispatches the same names through classifier `0x22edcb0`. Both ID field cases have distinct missing-field and duplicate-field diagnostics. Slot size does not establish every accepted integer encoding or range.

The record map reader uses missing-field diagnostics for `user`, `action`, `id`, `is_frontend` and `broadcaster`. The absent `expires_after` path instead turns the missing sentinel into a zero presence tag. The writer's tag test at `0x2312b79` takes its nil-writing helper when the tag is not 1; that helper writes MessagePack byte `0xc0`. All six named record cases have separate duplicate branches, including the optional expiry field.

The broadcaster writer reached from the record branches at `0x2207a83`; its names are independently checked by `0x21e7b30` and the reader at `0x168b630`:

| Tag | Name | Observed payload copied by reader |
| --- | --- | --- |
| 0 | `Evm` | 32 bytes |
| 1 | `Broadcaster` | 20 bytes |

These sizes describe decoded memory copies; the complete wire grammar and semantic ownership of the bytes have not been established. The inferred reference declares an address for `broadcaster` and a differently shaped `DelayedActionId`; its `action_id` and this binary's `id` may be different abstractions. Those declarations are not evidence for this target codec.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo build or binary-equivalence comparison was attempted. The two outer writer FDE bodies were compared byte-for-byte over 676 positions: 603 positions match and 73 differ in 22 contiguous ranges; both byte strings are retained for every differing range and no bytes were masked. This raw comparison is diagnostic only and does not establish semantic equivalence. Apart from the one resolved numeric-reader slot, relocation and call-target closure, helper closure, vtable/data closure and whole-ELF comparisons are not measured.

The focused unittest suite exercises classifier name changes, wrong branch displacements and offsets, two variant names, duplicate destinations, default literals, queue comparator boundaries, wrong key length, bad call opcodes, corrupt binary hash, truncated file ranges, unmapped/ambiguous addresses and NOBITS exclusion. These are checks of the extraction and a small predicate model, not execution of target code or a replacement for target snapshot fixtures.

## Results and limitations

The generated records cover 8 outer fields, 6 queue-record fields, 2 nested ID fields, 2 broadcaster variants and 2 per-asset status variants. The 53 digested FDE extents include helper entry points and selected raw windows; the packet does not claim to have analyzed every instruction in them. The byte windows and call targets support the local branches above, while other indirect calls and child payload semantics remain unresolved. No node, visor, chain data or external network was used. No milestone or full-scope progress gate is requested.

Next question: recover the nested `action` payload's serializer and matching reader, including its variant-specific failures, then compare these static expectations with authorized target-grounded snapshot fixtures.
