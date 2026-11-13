# RE-008: node #115 shared S decoder `0x31c32d0` reads {s, r}, the same layout as the first S decoder (132nd stage)

- Component ID: abci. Question: open PRs #6582 and #6596 showed that the second perp per-user value visitor `0x30bcb40` (arm 4) and the spot per-user value `0x3208ad0` (field 2) both read field `S` through `0x31c32d0`. What does `0x31c32d0` read, and is it the same layout as the first S decoder `0x1adf620` from open PR #6239?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6582, #6596 and #6598. It does not depend on their files.
- Claim status: instruction bytes, branch and call targets, RIP-relative references, function extents from `.eh_frame_hdr`, and strings are observations. "struct" and "same layout" are inferred labels. The binary was not executed.
- Scope included: the four direct calls of `0x31c32d0`, its marker dispatch, its inline key match, its two field reads, its duplicate blocks and defaults, and a byte comparison with `0x1adf620` at the same offsets. Scope excluded: the body of the integer reader behind slot `0x64e2580`, the sequence path `0x31c3aac`, and what `s` and `r` stand for. No gate changes.

## Result

| Step | Address | Result |
|---|---|---|
| Callers | `0x30bd615`, `0x30be296` in `0x30bcb40`; `0x32093fb`, `0x3209aa0` in `0x3208ad0` | Four direct calls to `0x31c32d0` |
| Marker dispatch | `0x31c332a`, `0x31c3337` | A fixmap (below `0x90`) is read by the inline struct visitor. A fixarray (`0x90` to `0x9f`) goes to the sequence path `0x31c3aac` (jump at `0x31c333f`). |
| Struct name | — | No "struct X with N elements" record is loaded in this function |
| Key match | `0x31c3886` to `0x31c389a` (and `0x31c37f2` to `0x31c3805` for a borrowed key) | Only a key of length 1 is matched: `s` is field 0, `r` is field 1, any other key is field 2. There are no long key names. |
| Unknown key | `0x31c3424`, `0x31c3429` | Skipped through `0x31d5e50` (third argument 1) |

| Index | Key | Arm test | Seen flag | Value kept at | Reader | Duplicate block |
|---|---|---|---|---|---|---|
| 0 | `s` | `0x31c38a0` | `rsp+0x90` | `rsp+0xa0` | slot `0x64e2580` (call `0x31c3a2a`) | `0x31c4238` |
| 1 | `r` | `0x31c3504` | `rsp+0x88` | `rsp+0x98` | slot `0x64e2580` (call `0x31c3a7b`) | `0x31c4244` |
| 2 | any other key | — | — | — | skip `0x31d5e50` | — |

- Both seen flags start at 0 (`0x31c3404`, `0x31c3410`). A repeated `s` or `r` loads its one-byte name (`0x793170`, `0x793504`), stores length 1 and loads the template `duplicate field `...`` (`0x43351a`).
- Defaults: at `0x31c3fcc` a zeroed register replaces each field whose seen flag is still 0 (two `cmove`). A missing `s` or `r` reads as 0; neither is an error.
- Slot `0x64e2580` is the integer read slot that field `r` of the per-user value uses in #6239, and that `a` and `c` use in #6598.

## Comparison with #6239

| | First S decoder `0x1adf620` (#6239) | Shared S decoder `0x31c32d0` (this record) |
|---|---|---|
| Used by | first per-user value visitor `0x1a212f0` | second perp visitor `0x30bcb40`, spot value `0x3208ad0` |
| Unwind extent | `0x10c0` bytes | `0x10c0` bytes |
| Keys | `s` (0), `r` (1), other skipped | `s` (0), `r` (1), other skipped |
| Long key names | none | none |
| Values | integers (slot `0x64e2580`) | integers (slot `0x64e2580`) |
| Missing field | 0 | 0 |

The tool checks that the two functions have the same unwind extent and the same bytes at nine offsets: the seen-flag setup (`+0x134`), both arm tests (`+0x234`, `+0x5d0`), both key compares (`+0x522`, `+0x52b`, `+0x5c3`), both value stores (`+0x771`, `+0x7c2`) and the default block (`+0xcfc`). It also checks that both value reads in `0x1adf620` (`+0x75a`, `+0x7ab`) go through slot `0x64e2580`. So the shared decoder is a second copy of the first S decoder, built for a different caller.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/shared_s_decoder_115.py --check
python3 -m unittest tests.test_shared_s_decoder_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The twelve `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 19 byte runs, each with its meaning. It checks 8 branch and call targets, 2 calls through slot `0x64e2580` in each decoder, 3 string loads with their text, the byte comparison above, and the function that holds each of 32 checked sites. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the decoder on a sample state (not allowed for this repository).

## Results and limitations

- Result: the shared `S` decoder reads a struct with two optional one-byte keys `s` and `r`, both integers that read as 0 when missing. It is byte-for-byte the same at the checked offsets as the first S decoder in #6239.
- Limits: the integer reader body, the sequence path, and the meaning of `s` and `r` are not mapped.
