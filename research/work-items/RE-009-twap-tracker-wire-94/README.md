# RE-009: node 94 spot TWAP tracker wire path

Node #94 serializes `spot_twap_tracker` as a two-field value containing a sequence of three-field scheduled items and a user-indexed tree, so a reconstruction can preserve the observed field order, compact container markers, and reader failure decisions on this state serialization path.

- Component ID: storage and state roots, RE-009.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as an unlicensed lead.
- Claim status: static observations for the bytes, direct calls, relative branches, FDE records, counted literals and relocations; interpretations are identified below. No execution or equivalence claim.
- Scope included and excluded: the spot tracker field wrapper, the two-field writers, item sequence and item writers, outer user-tree rows, time-text formatting handoff, and one MessagePack-shaped reader's field and length decisions. The inner user-ID-to-state tree, full timestamp formatting, ordering construction, all serializers' helper internals, actual checkpoint fixtures and other releases are excluded.

## Reproduce

From the repository root, with Python 3.12 or newer and the authenticated node artifact in place:

```sh
python3 tools/artifacts.py verify
python3 tools/twap_tracker_wire94.py --out research/work-items/RE-009-twap-tracker-wire-94
python3 -m unittest tests.test_twap_tracker_wire94
(cd research/work-items/RE-009-twap-tracker-wire-94 && sha256sum -c MANIFEST.sha256)
python3 tools/twap_tracker_wire94.py --out <tmp-dir-one>
python3 tools/twap_tracker_wire94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

Use two distinct existing or new directory names in place of the placeholders. The generator reads the target, verifies its SHA-256 before analysis, and imports the repository ELF and FDE parsers. It reads section and relocation records with `struct`, excludes `SHT_NOBITS` from file mappings, and interprets selected fixed instruction byte patterns; it invokes no external program and does not execute the target. Development used CPython 3.12.3 on Linux x86-64. GNU objdump 2.42 was used only for human analysis, not in the generator or tests. `tracker-evidence.json` and `instruction-windows.tsv` are generated; the manifest hashes every file in this directory except itself. The tool resolves no input paths from the shell environment, and generated content has no timestamps or host paths.

## Evidence

All addresses below and in the output are ELF link-time virtual addresses; the TSV also records file offsets. End addresses are exclusive FDE-described extents, checked against `.eh_frame` and `.eh_frame_hdr`. An FDE is an unwind range, not by itself proof of an original source boundary. The JSON records the 24 selected ranges, their FDE addresses, full body hashes and sizes. The 297 selected byte windows include 100 independently decoded rel8/rel32 destinations; some windows intentionally cover only part of a subsequent instruction. They are bounded observations, not a complete instruction decode or call graph.

The existing [app-hash builder packet](../RE-009-app-hash-builder-94/README.md) identifies the low-lane row 14 capture at state offset `+0x34e0`; the relevance of that capture to this serializer remains an inference because the builder is outside this packet. The separate field wrapper `0x27b2a20` emits the counted name `spot_twap_tracker` when its writer flag is nonzero, checks the result, then tail-jumps to `0x26db260`. This gives an independent field-name link to the selected serializer. A separate JSON field wrapper `0x27b0e70` emits the same name and calls `0x26db590`. The previously mapped hash pipeline is context: this work does not claim it has recomputed a hash.

### Writers and memory views

| Layer | Observation and selected evidence |
| --- | --- |
| Tracker | `0x26db260` chooses a two-member setup, then sends `running_heap` from the input base to `0x1e2d480` and `user_to_id_to_state` from input `+0x18` to `0x25e7c00`. Names are emitted when the writer flag at `+0xb` is 1. Calls and each error exit are in the TSV. |
| Compact tracker | `0x26db390` computes `((flag xor 1) << 4) or 0x82`. For flags 0 and 1 this gives `0x92` and `0x82`: two-element array and two-entry map markers, respectively. Name markers `0xac` and `0xb3` precede the 12- and 19-byte field names in the named branch. |
| JSON writer | `0x26db590` begins an object and handles those same two counted names in order. It invokes the first value path and checks the returned status before preparing the second field. |
| Heap items | `0x1e2d480` walks elements at a `0x28` stride and calls `0x26d9190`; `0x1e21920` and `0x26d8eb0` are the compact counterparts. Each item writes `next_slice_time`, `user`, `twap_id` in that order, reading at item offsets `+0x8`, `+0x14`, and `+0x0`. The compact item computes `0x93` or `0x83` for flags 0 or 1, respectively. |
| Outer user tree | `0x25e7c00` collects 16-byte pointer pairs and calls `0x1e246e0`; its pair writer `0x1df5c70` emits a two-element marker in the observed direct branch, passes the first pointer to `0x1e0d0a0`, and then calls a nested tree writer. The compact counterpart uses `0x1e1eda0` and `0x1e053c0`. The key helper passes 20 input bytes and a 42-byte buffer to a relocated formatter slot; the full textual spelling is not established here. |
| Time field | `0x1dfca40` and `0x1dfcba0` call two relocated helpers on pointers separated by four bytes and write `T` between their results. Nonzero status from any of the three formatting steps branches to a diagnostic and `ud2`. The final formatted value is passed to a writer; calendar rules and the helper implementations remain open. |

`0x26db260` and `0x26db390` are separate writer monomorphs with matching field names and order; their local writer configurations are not assumed to have the same layout. The flag-to-marker table is established only for byte values 0 and 1. The row captures pointer pairs in traversal order, but this packet does not establish what order the underlying tree supplies.

### Reader decisions

`0x16f6830` calls classifier `0x26c0260` after its input checks. The classifier compares exact field lengths and bytes, returning the common tag 9 and the codes below. Its two 16-byte comparison constants overlap by 13 bytes; the tool reconstructs the 19-byte name from both and checks it against the writer literal. At map exhaustion the field reader returns code 3. The tool resolves all four signed relative jump-table entries at `0x342ff0` in `0x1906c20`.

| Code | Field or event | Dispatch | Observed decision |
| --- | --- | --- | --- |
| 0 | `running_heap` | `0x190712a` | If its presence sentinel is already set, go to the duplicate-field formatter; otherwise call `0x171e560`. |
| 1 | `user_to_id_to_state` | `0x1907099` | If the presence flag is already set, go to the duplicate-field formatter; otherwise call `0x183df50`. |
| 2 | any other byte string | `0x1907100` | Call `0x19682d0` with argument 1, then continue when its returned tag is 9. Its internal skip behavior is not analyzed. |
| 3 | exhausted field count | `0x1907193` | Check for the first field, then check the second; missing-field formatting uses the corresponding counted name. |

The first field reader `0x171e560` calls the item reader `0x19bdf90`, which in turn calls `0x26bfd80`. The item classifier returns tag 9 with codes 0, 1, 2, or 3 for `next_slice_time`, `user`, `twap_id`, or an unknown name, respectively. Its four-entry table at `0x37dc44` dispatches to `0x19bf850`, `0x19bf91b`, `0x19bf897`, and `0x19bf8e2`. Each known-field arm checks a separate presence indicator before reading its value; a repeated name branches to a counted duplicate-field construction for that same name. The item reader also contains separate missing-field constructions for all three names. The user arm sets a length of 20 for its input helper. The initial name comparisons, table offsets, and error strings are independently read and checked by the tool.

The duplicate and missing paths each use separately measured 12- or 19-byte field names and the respective counted diagnostic prefixes. Their full formatted output and the downstream error type are not reconstructed. In the positional sequence arm, `0x19074c5` routes count zero to a length-error path, `0x19074fb` tests for count one after the first element, and `0x19075fd` checks count two after the second. The field reader also checks remaining bytes by unsigned subtraction: borrow at `0x16f695c` goes to `0x16f6b5e`; zero remaining and zero length take the non-borrow path. These statements cover only those branches, not all malformed MessagePack cases.

### Inferences and unresolved points

- The direct compact bytes are consistent with MessagePack arrays, maps and strings. The item field names and the containing `spot_twap_tracker` label support interpreting the 40-byte item as a scheduled TWAP entry; this is not a source-type or runtime-behavior proof.
- The 20-byte first member of the user-tree pair is consistent with an address and the 42-byte output buffer with a prefixed hexadecimal rendering. The formatter body and its output are not inspected; no exact key bytes are claimed.
- The field named `next_slice_time` and the `T` separator suggest a date/time string, but the two formatting callees, ranges and timezone semantics remain unresolved.
- The `+0x34e0` capture belongs to the previously mapped low-lane builder. The reference label, wrapper and row capture together support the state-hash connection; exact encoded values, ordering and the resulting digest are not validated here.

## Implementation and comparison

Not yet implemented. No independent Rust build, target execution, binary comparison or normalization was performed. Relocation and helper closure is incomplete: the packet resolves the formatter slots it uses as evidence but does not audit their bodies, the nested map values, the job runner, complete state serialization or relocation equivalence. There are no masks or matched-window claims.

## Results and limitations

The generator checks 24 FDE-described ranges, 297 byte windows, 100 selected relative edges, seven counted writer literals, ten field-error constructions and three relocation slots. The focused test suite has 20 tests and no skips. It exercises all single-bit corruptions of all five known tracker and item field-name byte strings, length boundaries, the digest gate, selected opcode/branch/immediate changes, a damaged FDE length, a modified relocation type, and non-file-backed or out-of-range addresses. The name and length tests exercise a static model derived from the selected branches; they do not execute the node or establish the behavior of untraced parser helpers.

No progress gate is requested: two fields and their adjacent failure decisions do not cover RE-009's fixture schema, hash ownership or snapshot compatibility acceptance scope. Next question: recover the nested `user_to_id_to_state` tree's key/value wire forms and compare a small authorized, sanitized checkpoint fixture, including ordering and malformed inputs.
