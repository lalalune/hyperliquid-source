# RE-009: user-state snapshot field names and compatibility decisions

Node #94's user-state readers route both `asset_to_oi` and `asset_to_oi_szi` to the same field, reject a second occurrence across those names, and write the latter spelling, so a reconstruction can preserve this snapshot compatibility rule and the six-field writer order.

- Component ID: RE-009, storage and state roots; the selected nested user-state value.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead and not copied.
- Claim status: observations for selected instruction bytes, FDE extents, names, branch and call targets; inference for their interpretation as matching snapshot reader/writer paths. Cross-release compatibility and actual runtime behavior are unresolved.
- Scope included and excluded: two field classifiers and map readers, three writer forms, and four small name helpers. The field values' complete codecs, unknown-key helpers, all reader sequence paths, surrounding checkpoint orchestration, allocation and unwind closure, runtime behavior and other releases are excluded.

## Reproduce

From the repository root, with Python 3.12.3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/user_state_codec94.py --out <tmp-dir>
cmp <tmp-dir>/records.json research/work-items/RE-009-user-state-codec-94/records.json
cmp <tmp-dir>/fields.tsv research/work-items/RE-009-user-state-codec-94/fields.tsv
python3 -m unittest tests.test_user_state_codec94
(cd research/work-items/RE-009-user-state-codec-94 && sha256sum -c MANIFEST.sha256)
```

Replace `<tmp-dir>` with an existing or new directory outside the retained packet. The generator first validates the whole input SHA-256, imports `tools/elf_index.py` and `tools/fde_extents.py`, excludes NOBITS sections from file-backed address resolution, reads actual FDEs and checks unmasked SHA-256 for each selected body. It writes only `records.json` and `fields.tsv`. It invokes no external program and does not execute the binary. GNU objdump 2.42 was used for human inspection only; its output is not an input to the generator or tests. Addresses are linked ELF virtual addresses; file offsets and FDE addresses are in `records.json`. Ends are exclusive. An FDE extent is unwind metadata, not by itself a complete function-boundary or reachability proof.

## Evidence

### Field classification and map reading

The binary field classifier `0x2301330..0x230148b` and the JSON field classifier `0x2301490..0x23015eb` both dispatch on byte length. Each has a 32-entry signed-relative table for lengths 2 through 33; the corresponding targets have the same offsets in the two classifier bodies. Seven individual spellings lead to six tags, with all other selected lengths and failed content comparisons reaching tag 6:

| Tag | Recognized input key | Length | Input object offset in writer | JSON map absence |
| --- | --- | ---: | --- | --- |
| 0 | `user_to_state` | 13 | `+0x00` | missing-field path |
| 1 | `users_with_positions` | 20 | `+0x60` | missing-field path |
| 2 | `check_all_users_for_liquidatables` | 33 | `+0xa8` | missing-field path |
| 3 | `asset_to_oi`, `asset_to_oi_szi` | 11, 15 | `+0x78` | separate default path |
| 4 | `open_order_tracker` | 18 | `+0x30` | separate default path |
| 5 | `ar` | 2 | `+0x90` | separate default path |

Offsets describe the writer's in-memory input object, not offsets in an encoded file. The older-looking 11-byte spelling is reconstructed from the two overlapping immediate comparisons at `0x230139b`; the 15-byte spelling uses the analogous compares at `0x2301424`. Both return tag 3. The vector constants and the other immediate and data comparisons are checked separately. The tag 6 arm reaches a distinct helper path; its complete handling of unknown values is not established.

The binary reader `0x1a47aa0..0x1a4a5b8` calls the first classifier at `0x1a4996b`; the JSON reader `0x1d1fa20..0x1d22963` calls the second at `0x1d1fc84`. Each indexes a seven-entry relative dispatch table by the returned tag. For tag 3, the binary arm at `0x1a49c64` tests the same presence slot and its conditional branch at `0x1a49c6d` leads to the canonical `asset_to_oi_szi` duplicate diagnostic. The JSON arm at `0x1d1fddd` and branch at `0x1d1fde6` do the same. After a successful child result, the binary reader stores one in its presence slot at `0x1a49ce9`, and the JSON reader stores one in its corresponding slot at `0x1d200b7`. Thus, conditional on that success and the map continuing, either spelling followed by either spelling takes that duplicate route. Both readers have corresponding selected duplicate branches for all six recognized tags; their sites and decoded targets are in `fields.tsv`.

On JSON object completion, the checks at `0x1d207bd`, `0x1d207cb` and `0x1d207da` lead to `missing field` diagnostics for tags 0, 1 and 2, respectively. For absent tag 3, the branch at `0x1d209dc` reaches `0x1d20b77`, which stores two zero qwords in its temporary result. For absent tag 4, `0x1d20b95` reaches `0x1d20bc9`, which calls a helper and loads static data. For absent tag 5, `0x1d20c0f` reaches `0x1d20c1d`, which clears two registers before result assembly. These are observed default paths; the complete resulting container representations and helper behavior remain unresolved. Equivalent selected tag-3 zero stores in the binary map reader start at `0x1a490fa`. The diagnostic text, selected branches, exact byte windows and targets are retained in `records.json`.

### Writing and error propagation

The generic binary writer `0x230d7e0..0x230dae8` supplies a six-element count to either a map-header helper or an array-header helper according to its mode byte. With that byte equal to one, it sends names and values in the six tag order shown above; the tag-5 name is emitted through helper `0x23d5450`. At `0x230d9c6` it passes the input at `+0x90` to that helper. The tag-2 value is loaded as a byte at `+0xa8` and ORed with `0xc2` before a separate callee; this packet does not assume the callee's general behavior.

The direct binary writer `0x230daf0..0x230de3d` computes and writes header `0x86` when its mode byte is one and `0x96` when zero. For mode one it writes the two-byte field name `ar` with prefix `0xa2` in helper `0x23d72f0`; in mode zero it takes that helper's name-free tail path. It writes the canonical `asset_to_oi_szi` spelling. These observations are conditional on reaching each store and on helper success; no full encoded fixture is claimed.

The JSON writer `0x230de40..0x230e106` supplies the same field names in order, using `0x23d2c60` for `open_order_tracker` and `0x23d1d10` for `ar`; the boolean field is delegated to another helper. Selected writer error checks are not fallthrough successes: `records.json` decodes 28 conditional branches across the three writers, including six JSON value-error branches to `0x230e038` and the generic binary writer's distinct name/value error paths. This is a selected branch map, not an exhaustive instruction or error census.

### Inference and prior context

The shared field names, field order and selected input offsets support treating the readers and writers as alternative codecs for the same user-state value. Prior `RE-007-adl-user-scan-94` connects the user-state names and offsets to a clearinghouse scan; this packet studies different function starts and does not use that packet as proof of the wire decisions. The two spellings may represent an intentional compatibility alias, but the binary alone does not establish which release introduced either name or whether any other release accepts them. The reference's collection labels and types are not treated as authoritative.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiled comparison, normalization masks, complete call-target and vtable closure, real snapshot fixtures, and target execution: not yet measured. The authenticated node ELF is the only input fixture. The 11 focused unittest methods include wrong digest, mutated reader/writer code, both field-name immediates and vector constants, altered table entries, call and branch opcodes and displacements, field-layout corruption, NOBITS, out-of-range and section-crossing controls, and repeated byte-for-byte generation. Classifier examples operate on a bounded model derived from pinned comparisons; they do not execute the native readers or validate the child values.

## Results and limitations

The generated record contains 11 selected FDE extents, two 32-entry classifier length tables, two seven-entry map dispatch tables, seven accepted spellings, 12 duplicate branches, three JSON required-field checks, three JSON default branches, 28 selected writer branches, 36 selected direct calls, and 16 selected byte windows. These are bounded selected counts, not whole-node coverage. Tests passed with no skips. No component milestone gate is requested. No live state, network, chain action or execution of the captured node was used.

Next question: recover the nested values behind `asset_to_oi_szi` and `ar`, including their entry encodings and helper error cases, and validate complete fixtures in an authorized offline harness.
