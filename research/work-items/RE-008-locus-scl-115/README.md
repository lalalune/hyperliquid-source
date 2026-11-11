# RE-008: node #115 Locus field `scl` is the 14-field struct SpotClearinghouse (128th stage)

- Component ID: abci. Question: open PR #6589 showed that arm 2 of the MessagePack Locus visitor `0x332c430` (key `scl`) calls `0x31b5450`, and open PR #6593 saw only its first marker dispatch. What struct does `0x31b5450` decode, which fields does it have, and which are required?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6589 and #6593. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, relocations, function starts from `.eh_frame_hdr`, and strings are observations. "map path", "sequence path", "duplicate block" and "required" are inferred labels. The binary was not executed.
- Scope included: the top level of `0x31b5450` (marker dispatch, struct name record, key reader slot, field table, each field arm's duplicate check and decoder call, and the missing-field error sites). Scope excluded: the bodies of the 14 field decoders, the sequence path body, the default values of the 6 optional fields, and what the short names `eec`, `eebl`, `pmr` and `soh` stand for. No gate changes.

## Result

| Step | Address | Result |
|---|---|---|
| Caller | `0x332cd98` | Locus arm 2 (`scl`) calls `0x31b5450` (#6589) |
| Marker dispatch | `0x31b54d7`, `0x31b54ec` | A fixmap (below `0x90`) jumps to the map path `0x31b5778`. A fixarray (`0x90` to `0x9f`) jumps to the sequence path `0x31b557f`. |
| Struct name | `0x31b5a16` | Loads the expected-text record `0x6464940`. It has one `R_X86_64_RELATIVE` relocation to `0x796322` and length 41: `struct SpotClearinghouse with 14 elements`. |
| Key read | `0x31b5d86` | Calls through slot `0x64e3048`, relocated to `0x33f2fe0`. On result tag 9 it takes the field index and jumps through table `0x6ce708`. |
| Integer keys | `0x33f3040` | The key reader turns an integer key k into min(k, 14). Index 14 is the "any other key" arm. |

Field arms (table `0x6ce708`). Each arm 0 to 13 first tests whether its field is already set. If so, it jumps to a block that loads the field name and the template `duplicate field `...`` (`0x43351a`). That block binds the index to the name.

| Index | Key | Arm | Decoder | Missing-field error |
|---|---|---|---|---|
| 0 | `meta` | `0x31b5db0` | `0x323d8d0` | yes |
| 1 | `user_states` | `0x31b62b8` | `0x31541c0` | yes |
| 2 | `daily_exchange_scaled_and_raw_vlms` | `0x31b6160` | `0x310e930` | no |
| 3 | `token_to_genesis` | `0x31b61d2` | `0x3308e10` | yes |
| 4 | `token_to_max_supply` | `0x31b6003` | `0x3245580` | yes |
| 5 | `token_fees_collected` | `0x31b6354` | `0x3245580` | yes |
| 6 | `native_token` | `0x31b6462` | `0x451c230` | no |
| 7 | `spot_dusting_opted_out_users` | `0x31b6244` | `0x325ec80` | yes |
| 8 | `evm_transfer_escrows` | `0x31b6515` | `0x3088be0` | yes |
| 9 | `eec` | `0x31b60ed` | `0x30db2f0` | no |
| 10 | `eebl` | `0x31b64b2` | `0x45160c0` | no |
| 11 | `token_to_pending_evm_contract` | `0x31b5f62` | `0x331e590` | yes |
| 12 | `pmr` | `0x31b6075` | `0x32082b0` | no |
| 13 | `soh` | `0x31b63c6` | `0x3089400` | no |
| 14 | any other key | `0x31b5f3a` | `0x31d5e50` (skip) | — |

- "yes" means the function has a block that loads this name and the template `missing field `...`` (`0x4325c4`): the field is required. The 6 "no" fields have no such block in this function, so they are probably filled with a default. The default values are not proven.
- `scl` holds a `user_states` field of its own (decoder `0x31541c0`). It is a different decoder from the perp clearinghouse `user_states` reader `0x3274e70` in #6584.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/locus_scl_115.py --check
python3 -m unittest tests.test_locus_scl_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eleven `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 8 byte runs, each with its meaning. It checks 15 field-table entries, 14 duplicate branches with the name and stored length in each duplicate block, 14 duplicate-template loads, 14 decoder calls, 8 missing-field name and template loads, 4 other branches and calls, the key slot and its relocation, the struct-name record with its relocation and length, and the function that holds every checked site. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the decoder on a sample state (not allowed for this repository).

## Results and limitations

- Result: Locus field 2 `scl` is the struct `SpotClearinghouse` with 14 fields; 8 are required and 6 have no missing-field error.
- Limits: the field decoder bodies, the sequence path, the default values, and the meaning of the short names are not mapped.
