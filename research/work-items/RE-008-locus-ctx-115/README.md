# RE-008: node #115 Locus field `ctx` is the 13-field struct Context (134th stage)

- Component ID: abci. Question: open PR #6589 showed that field 0 (`ctx`) of the MessagePack Locus visitor `0x332c430` is decoded by `0x30d1c60`. What does `0x30d1c60` decode, which keys does it accept, and which keys are required?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6589. It does not depend on its files.
- Claim status: instruction bytes, branch and call targets, RIP-relative references, relocations, jump-table entries, function extents from `.eh_frame_hdr`, and strings are observations. "required" and "other key" are inferred labels. The binary was not executed.
- Scope included: the two Locus call sites, the struct-name record, the key reader and field table, the 14 arms with their duplicate-field blocks and value calls, the 6 missing-field blocks, and the 6 sequence-length error sites. Scope excluded: the bodies of the 6 called field decoders and the 2 integer readers. No gate changes.

## Result

| Step | Address | Result |
|---|---|---|
| Callers | `0x332c6ad`, `0x332c805` in Locus `0x332c430` | Both call `0x30d1c60` (extent `0x2290`) |
| Struct name | record `0x6462690` | One `R_X86_64_RELATIVE` relocation to `0x793562`, length 31: `struct Context with 13 elements` |
| Key read | `0x30d2172` | Call through slot `0x64e41e0` (relocated to `0x348eca0`). On tag 9 the index byte selects an arm through table `0x68ac4c`. |
| Integer keys | `0x348ed00` | `min(k, 13)`, so index 13 is any other key; arm `0x30d20b1` calls the skip reader `0x31d5e50` |
| Duplicate check | 13 arms | Each arm tests its "set" flag and branches to a block that loads its name and length, then joins `0x30d3b02`, which loads the "duplicate field" template (`0x43351a`) |
| Missing check | 6 blocks | Name + the "missing field" template (`0x4325c4`) + call `0x3046740`, which always stores tag 6 (not the success tag 9) |
| Sequence form | 6 sites | The struct-name record is loaded at exactly 6 sites, with element index 0, 2, 5, 6, 7, 8, before the call to `0x2f7fe90` |

| Index | Key | Value read | Required |
|---|---|---|---|
| 0 | `hardfork_height` | slot `0x64e2580` → `0x348e980` | yes |
| 1 | `hardfork` | `0x32b03e0` | no |
| 2 | `height` | slot `0x64e2580` → `0x348e980` | yes |
| 3 | `tx_index` | `0x451c540` | no |
| 4 | `round` | `0x4524ae0` | no |
| 5 | `time` | `0x3d4f3c0` | yes |
| 6 | `prev_time` | `0x3d4f3c0` | yes |
| 7 | `next_oid` | slot `0x64e2580` → `0x348e980` | yes |
| 8 | `next_lid` | slot `0x64e2580` → `0x348e980` | yes |
| 9 | `next_twap_id` | slot `0x64e2580` → `0x348e980` | no |
| 10 | `system_nonce` | `0x421db60` | no |
| 11 | `use_system_nonce` | `0x37ce740` | no |
| 12 | `mac` | slot `0x64dfeb0` → `0x14b7aa0` | no |
| 13 | any other key | skip `0x31d5e50` | – |

For the 6 slot arms, the tool also checks that the arm's marker branch reaches the slot call and that the store after the call writes the same stack flag that the arm tests. The map form and the sequence form agree: the 6 keys with a missing-field block are exactly the 6 element indexes with a sequence-length error. The other 7 keys have neither, so they have a default (inference). `time` and `prev_time` use the same decoder. `use_system_nonce` uses `0x37ce740`, the same address that #6589 lists for Locus field `pdl`.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/locus_ctx_115.py --check
python3 -m unittest discover -s tests -p test_locus_ctx_115.py
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The 13 `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 6 byte runs with their meaning, checks 14 jump-table entries, 13 duplicate blocks (name, length, join), 13 value reads (7 direct calls with skip, 6 slot calls with flag binding), 4 relocations, 6 missing-field blocks, 6 sequence sites, and scans the decoder extent so that the struct record, the missing template and the duplicate template have no other loads. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the decoder on a sample state (not allowed for this repository).

## Results and limitations

- Result: Locus `ctx` is `struct Context` with 13 named fields; 6 are required in both the map and the sequence form.
- Limits: the value types of the 6 called decoders and the integer width of the 2 slot readers are not checked. Which Locus call site is the map arm and which the sequence element is not checked.
