# bridge: the VoteGlobal arms that set the withdraw fee, voter set, listed set and withdrawal flags in node #94

This packet finds who writes the bridge settings the other bridge paths only read, so a reconstruction can apply these votes from the bytes: case 95 replaces the listed set at state `+0x36a0` that deposit arm 84 and L1 hash arm 87 test, case 17 toggles voter keys in the set at state `+0x3898`, case 16 stores `bridge2_withdraw_fee` in the first dex, and case 76 selectors 1 and 5 write the two bytes of the withdraw3 gate, where clearing the first also clears `oaw`.

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`; the apply function is `l1/src/action/vote_global.rs` by a Location row, and only the bridge settings arms are claimed here)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for bytes, branch order, constants, serde names, jump table rows and node layouts; inference for the role of each set and byte; unresolved items are under limits
- Scope included and excluded: included are the reached rows of `0x2355f40` from its entry through the four cases, and whole bodies of the map and list caps, the toggle iterator, and the voter set insert and remove chains (`path.tsv`). The list drain `0x286d260` and drop `0x28a8ac0` are run and not edited, as they are shared and listed by other packets. The first dex lookup `0x3332700` and the recorder are stubs. Excluded are the other cases of the apply function, case 76 selectors other than 1 and 5, the vote quorum that leads to this function, and the twin `0x4caa870`, which is not run.

## Reproduce

```
python3 tools/bridge_settings_votes.py --out research/work-items/bridge-settings-votes-94
python3 -m unittest tests.test_bridge_settings_votes
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes of each function, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes about 7 minutes with four worker processes.

## Evidence

Addresses are virtual addresses. Instruction rows are in `function-rows.tsv`; for `0x2355f40` only reached rows are listed. Rows quoted below are bound in `key-rows.tsv`, so a moved row fails the run.

### The cases

`0x2355f40` takes the raw action tag, and for a tag of 0x12 or more uses the tag minus 0x12 as an index in the jump table `0x3dd1b8` (`cases.tsv`, read from table bytes).

| Case | Raw tag | Arm | Effect |
|---|---|---|---|
| 16 | `0x22` | `0x2356c45` | value below `0x0ccccccccccccccc`: first dex `+0x250`; else status `0x13f` with the value |
| 17 | `0x23` | `0x235815d` | map of at most 10000 rows: flag 0 removes the key from state `+0x3898`, any other flag inserts it |
| 76 | `0x5e` | `0x23582da` | byte `+8` selects from table `0x3dd380`, byte `+9` is the value |
| 95 | `0x71` | `0x2359474` | list of at most 10000 rows: replaces the set at state `+0x36a0` |

The serializers name two of the fields (`fields.tsv`): first dex `+0x250` is `bridge2_withdraw_fee` (`0x370c8c5`, key `0x370c8cc`), and bridge `+0x140`, which is state `+0x34d8`, is `oaw` (`0x22157e4`, key `0x22157eb`).

### Case 76, the two bytes

| Selector | Row | Effect |
|---|---|---|
| 1 | `0x235b43c` | state `+0x31a2` takes value bit 0. Bit clear: state `+0x34d8` is cleared too (`0x235bd9d`). Bit set: recorder 3 with the Location of `l1/src/action/vote_global.rs` line 1289, and `oaw` stays |
| 5 | `0x235b462` | state `+0x34d8` takes value bit 0, nothing else |

So `oaw` cannot outlive the first byte going low, but it survives that byte going high (`halt_from_01_to_1`, `halt_from_11_to_0`, `halt_on_oaw_on_halt_off`). `oaw` set while the first byte is low stays set (`oaw_set_with_no_halt_stays`). The withdraw3 core reads the pair at `0x27342ea..0x27342fc`: status `0x27` when `+0x31a2` is 1 and `+0x34d8` is 0 (in #497). The name of `+0x31a2` is not established.

### Case 17, the voter set

`0x1e802c0` refuses a length word above 10000 with status `0x143`, text "Invalid input length", and drains the map; the set is untouched (`toggle_cap_over`). At exactly 10000 it passes (`toggle_cap_exact`). The arm then walks the map in key order through `0x2872cc0` and reads the flag byte at node `+0x16c` (`0x2358242`):

- flag 0: `0x2867a60` removes the key, and a missing key is a no-op (`toggle_remove_missing`);
- any other byte: `0x2850460` inserts the key, and a present key is a no-op (`toggle_insert_present`, `toggle_flag_two_inserts`).

There is no error after the cap, and all 32 key bytes take part in the compare (`toggle_last_byte_differs`). Node layouts are in `node-layouts.tsv`; the voter set has the layout of the voter sets in `bridge-deposit-votes-94`.

Trees grow and shrink through the real split and merge rows, up to height 2 on 320 rows. After every operation the harness walks each set, checks counts, links, key order and length, and checks that every node was freed with its right size or is still reachable.

### Case 95, the listed set

`0x1e7fa70` has the same cap and status. On a pass the arm drops the old set with `0x28a8ac0`, then stores root, height and length at state `+0x36a0` (`0x23594ba..0x23594ce`). It replaces and does not merge (`list_replaces_not_merges`), an empty list clears (`list_empty_clears`), and a refused list leaves the old rows (`list_over_cap_keeps_old`).

This is the set read at `0x271243d`, the deposit credit, and `0x1e646e2`, arm 84, and tested by arm 87 (`bridge-deposit-votes-94`, `bridge-l1-hash-votes-94`). No other row in the apply function uses that offset (`twin-rows.tsv`). This does not prove a single writer: a displacement scan over `.text` finds 13 functions with `+0x36a0`, of which the state drop `0x1d52820` and the readers above were read and the rest were not.

### Reference differences

| Reference `l1/action/vote_global.rs` | Bytes |
|---|---|
| raw `0x71` is `SetReferenceOracleConfig` | raw `0x71` replaces a set of 20-byte keys at state `+0x36a0` |
| raw `0x5e` is `SetPerpDexsLocked(bool)` | raw `0x5e` is a selector byte and a value byte |
| `AddressToggle` has a 20-byte address | the key of case 17 is `0x20` bytes |

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the status, stub events, both sets, the fee and both bytes after every operation.

## Results and limitations

- 14 functions, 2524 instruction rows. 197 named scenarios with 204 operations and 200 generated scenarios: 0 mismatches.
- 466 byte edits on reached rows: 385 killed, 81 survived (`mutations.tsv`). A survivor has a class label only and is not proved equal. Each edit runs at most 40 of the cheapest scenarios that reach it.
- 440 rows of the whole-body helpers are not reached (`unreached.tsv`): panic rows, deep search rows and split rows of trees above height 2.
- `toggle_cap_exact` uses only flag 0 on an empty set, to bound the run time. The largest insert run is 320 rows.
- The twin `0x4caa870` has the same count of hits for the four offsets (`twin-rows.tsv`) and is not run.
- The roles are inference: which validators or addresses fill either set is not in the binary. The name of `+0x31a2`, and the names of the two sets, are not established. The serializer loads `oaw` with a 4-byte read while the setter writes one byte.
- What recorder code 3 does with its Location is not read here.
- That the callers `0x2387390` and `0x2704d90` reach this function only after a passed vote is not established here.

Next question: which function reads the voter set at state `+0x3898`, and what case 76 selector 3 does with `0x2760040`.
