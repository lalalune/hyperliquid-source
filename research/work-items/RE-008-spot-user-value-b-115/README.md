# RE-008: node #115 spot per-user value field `b` is a map from a `Token` key to {t, h, e} (130th stage)

- Component ID: abci. Question: open PR #6596 showed that the spot per-user value `{b, D, S}` reads field `b` through `0x31a73f0`. What does `0x31a73f0` read?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6596. It does not depend on its files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, function starts from `.eh_frame_hdr`, and strings are observations. "map", "balance", "total", "hold" and "entry notional" are inferred labels. The binary was not executed.
- Scope included: the top level of `0x31a73f0`, the key and value calls of its map visitor `0x3747e60`, the element call of its sequence visitor `0x378dbb0`, and the key match, field arms, duplicate checks and defaults of the value reader `0x3077410`. Scope excluded: the bodies of `0x2f48380`, `0x2f782f0`, `0x2f53f30` and `0x32d1140`, the value reader's sequence form, and what `t`, `h` and `e` stand for. No gate changes.

## Result

| Step | Address | Result |
|---|---|---|
| Caller | `0x3208d6b` | Field 0 (`b`) of the spot per-user value `0x3208ad0` calls `0x31a73f0` (#6596) |
| Marker dispatch | `0x31a7445`, `0x31a7453` | A fixmap (below `0x90`) goes to the map visitor `0x3747e60` (call at `0x31a7525`). A fixarray (`0x90` to `0x9f`) goes to the sequence visitor `0x378dbb0` (call at `0x31a75d3`). |
| Map key | `0x3747f04` to `0x3747f22` | Read through `0x2f48380` with the 5-byte type name `Token` (`0x7c8235`). Result tag 9 is success. |
| Map value | `0x3747f39` | Read through `0x3077410`, with second argument 0 |
| Repeated key | `0x3748071` | Loads the 13-byte text `duplicate key` (`0x79dce8`) |
| Sequence element | `0x378dc58` | Read through `0x32d1140`; the visitor also loads `duplicate key` (`0x378dd59`) |
| Value key match | `0x3077974` to `0x30779b8` | A one-byte key is matched inline: `t` is field 0, `h` is field 1, `e` is field 2, any other key is field 3. The index goes to table `0x6701e4`. |

Value fields (table `0x6701e4`). Each arm 0 to 2 first tests whether its field is already set. If so, it jumps to a block that loads the one-byte name, stores length 1 and loads the template `duplicate field `...`` (`0x43351a`).

| Index | Key | Arm | Reader | Type name |
|---|---|---|---|---|
| 0 | `t` | `0x30776b5` | `0x2f782f0` | `Wei` (3 bytes) |
| 1 | `h` | `0x3077c11` | `0x2f782f0` | `Wei` (3 bytes) |
| 2 | `e` | `0x3077c62` | `0x2f53f30` | `UsdcBigSpotNtl` (14 bytes) |
| 3 | any other key | `0x30775cf` | skip | — |

- Defaults: at `0x30782c7` a zeroed register replaces each field whose seen flag is still 0 (three `cmove`). A missing `t`, `h` or `e` reads as 0; none of them is an error.
- Inference, not proven: `b` holds the spot balances of a user, one per token, with `t` = total, `h` = hold and `e` = entry notional. This comes from the type names `Token`, `Wei` and `UsdcBigSpotNtl`, not from field names in the binary.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/spot_user_value_b_115.py --check
python3 -m unittest tests.test_spot_user_value_b_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The thirteen `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 22 byte runs, each with its meaning. It checks 11 branch and call targets, 7 string loads with their text, 4 field-table entries, 3 seen-flag tests, 3 duplicate branches with the name in each duplicate block, and the function that holds each of 53 checked sites. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the decoder on a sample state (not allowed for this repository).

## Results and limitations

- Result: field `b` of the spot per-user value is a map from a `Token` key to a value with three optional one-byte keys: `t` and `h` of type `Wei`, and `e` of type `UsdcBigSpotNtl`. A missing field reads as 0.
- Limits: the reader bodies, the sequence element `0x32d1140`, the value reader's sequence form, and the meaning of `t`, `h` and `e` are not mapped.
