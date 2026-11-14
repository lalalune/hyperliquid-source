# RE-008: node #115 shared D decoder `0x3215260` is a map from a `Date` key to {a, c} (131st stage)

- Component ID: abci. Question: open PRs #6582 and #6596 showed that the second perp per-user value visitor `0x30bcb40` and the spot per-user value `0x3208ad0` both read field `D` through `0x3215260`. What does `0x3215260` read, and is it the same layout as the first D decoder `0x18d4f40` from open PR #6319?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6582, #6596 and #6597. It does not depend on their files.
- Claim status: instruction bytes, branch and call targets, RIP-relative references, function starts from `.eh_frame_hdr`, and strings are observations. "map" and "same layout" are inferred labels. The binary was not executed.
- Scope included: the four direct calls of `0x3215260`, its marker dispatch, the key and value calls of its map visitor `0x3730e50`, the duplicate text of its sequence visitor `0x376e720`, and the key match, field arms, duplicate checks and defaults of the value reader `0x3242730`. Scope excluded: the bodies of `0x2f68710`, of the integer reader behind slot `0x64e2580`, and of the sequence visitor's element path, and what `a` and `c` stand for. No gate changes.

## Result

| Step | Address | Result |
|---|---|---|
| Callers | `0x30bd65b`, `0x30be31e` in `0x30bcb40`; `0x320935d`, `0x3209966` in `0x3208ad0` | Four direct calls to `0x3215260` |
| Marker dispatch | `0x32152b5`, `0x32152c3` | A fixmap (below `0x90`) goes to the map visitor `0x3730e50` (call at `0x3215395`). A fixarray (`0x90` to `0x9f`) goes to the sequence visitor `0x376e720` (call at `0x3215443`). |
| Map key | `0x3730eeb` to `0x3730f07` | Read through `0x2f68710` with the 4-byte type name `Date` (`0x459fd0`). Result tag 9 is success. |
| Map value | `0x3730f17` | Read through `0x3242730`, with second argument 0 |
| Repeated key | `0x373104a`, `0x376e8ed` | Both visitors load the 13-byte text `duplicate key` (`0x79dce8`) |
| Value key match | `0x3242c4e` to `0x3242c65` | A one-byte key is matched inline: `a` is field 0, `c` is field 1, any other key is field 2 |
| Dispatch | `0x3242950` to `0x324295e` | Field 0 goes to `0x3242d00`, field 1 to `0x3242964`, field 2 is skipped through `0x31d5e50` (`0x3242889`) |

| Index | Key | Arm | Seen flag | Value kept at | Reader | Duplicate block |
|---|---|---|---|---|---|---|
| 0 | `a` | `0x3242d00` | `rsp+0x90` | `rsp+0xa0` | slot `0x64e2580` (call `0x3242e8a`) | `0x3243698` |
| 1 | `c` | `0x3242964` | `rsp+0x88` | `rsp+0x98` | slot `0x64e2580` (call `0x3242edb`) | `0x32436a4` |
| 2 | any other key | — | — | — | skip `0x31d5e50` | — |

- Both seen flags start at 0 (`0x3242864`, `0x3242870`). A repeated `a` or `c` loads its one-byte name, stores length 1 and loads the template `duplicate field `...`` (`0x43351a`).
- Defaults: at `0x324342c` a zeroed register replaces each field whose seen flag is still 0 (two `cmove`). A missing `a` or `c` reads as 0; neither is an error.
- Slot `0x64e2580` is the integer read slot that field `r` of the per-user value uses in #6239.

## Comparison with #6319

| | First D decoder `0x18d4f40` (#6319) | Shared D decoder `0x3215260` (this record) |
|---|---|---|
| Used by | first per-user value visitor `0x1a212f0` | second perp visitor `0x30bcb40`, spot value `0x3208ad0` |
| Key type name | `Date` | `Date` |
| Value keys | `a` (0), `c` (1), other skipped | `a` (0), `c` (1), other skipped |
| Values | integers | integers (slot `0x64e2580`) |
| Missing field | 0 | 0 |

The two decoders use different functions but the same layout. This record checks only `0x3215260`; the #6319 column is taken from that PR.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/shared_d_decoder_115.py --check
python3 -m unittest tests.test_shared_d_decoder_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The fourteen `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 25 byte runs, each with its meaning. It checks 15 branch and call targets, 2 calls through slot `0x64e2580`, 6 string loads with their text, and the function that holds each of 48 checked sites. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the decoder on a sample state (not allowed for this repository).

## Results and limitations

- Result: the shared `D` decoder reads a map from a `Date` key to a value with two optional one-byte keys `a` and `c`, both integers that read as 0 when missing. This is the same layout as the first D decoder in #6319.
- Limits: the key reader body, the integer reader body, the sequence visitor's element path, and the meaning of `a` and `c` are not mapped.
