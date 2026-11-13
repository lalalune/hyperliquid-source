# RE-008: node #115 Locus `uaR` items are an enum whose first four variants are Perp, Spot, Token and Pdi (126th stage)

- Component ID: abci. Question: open PR #6591 showed that the `uaR` value reader `0x329edf0` reads a sequence and decodes each item through `0x2f3c470`, and did not read `0x2f3c470`. What type is one `uaR` item?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PR #6591 (and #6589). It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, RIP-relative references, function starts from `.eh_frame_hdr`, and strings are observations. "enum", "variant reader", "index reader" and "newtype reader" are inferred labels. The binary was not executed.
- Scope included: the item decoder `0x2f3c470`, the variant reader `0x3bdc730` up to its table and arms 0 to 3. Scope excluded: the variant-name matcher `0x3163ca0` (only the call to it is checked), arms 4 to 6, the reader `0x2f48380`, and what the name `uaR` stands for. No gate changes.

## Result

| Level | Function | Result |
|---|---|---|
| `uaR` value loop | `0x329efe8` | `call 0x2f3c470` for each item (#6591) |
| Item decoder | `0x2f3c470` | Accepts only a MessagePack map with exactly one entry: fixmap (`0x80`), map16 (`0xde`) or map32 (`0xdf`), each checked for length 1. Another length stores error tag 4 with the length. Another marker stores error tag 2 with the marker. With one entry it calls `0x3bdc730`. |
| Variant reader | `0x3bdc730` | Reads the variant index through `0x3163ca0` (argument 1). On result tag 9 it jumps through table `0x7b2e68`. |
| Table size | `0x7b2e68` | Entries 0 to 6 point inside `0x3bdc730`. Entry 7 (`0x7b2e84`) is the start of the next table: function `0x3bdca00` loads `0x7b2e84` at `0x3bdca18`. So the table has 7 entries. |

| Index | Arm | Type name (length) | Reader | Variant number stored |
|---|---|---|---|---|
| 0 | `0x3bdc770` | `Perp` (4) | `0x2f48380` | 0 |
| 1 | `0x3bdc8b3` | `Spot` (4) | `0x2f48380` | 1 |
| 2 | `0x3bdc855` | `Token` (5) | `0x2f48380` | 2 |
| 3 | `0x3bdc884` | `Pdi` (3) | `0x2f48380` | 3 |
| 4 to 6 | `0x3bdc7df`, `0x3bdc902`, `0x3bdc965` | not mapped | | |

- So one `uaR` item is an enum written as `{variant: value}`, with 7 variants. Variants 0 to 3 each wrap one value read by `0x2f48380` under the type names `Perp`, `Spot`, `Token` and `Pdi`. The success path stores result tag 9.
- Inferred, not proven: the variant names (they come from `0x3163ca0`, which is not read here), and what the wrapped values mean.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/locus_uar_item_115.py --check
python3 -m unittest tests.test_locus_uar_item_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The six `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Implementation and comparison

The tool pins 14 byte runs, each with its meaning. It checks 7 call targets, all 7 table entries, the next table's `lea`, 4 type-name `lea` targets with their strings, the name length and the stored variant number of each mapped arm, and the function that holds 13 sites. Tests change bytes in a copy of the image and expect rejection with a named reason. Alternative considered: running the reader on a sample state (not allowed for this repository).

## Results and limitations

- Result: each `uaR` item is a 7-variant enum in `{variant: value}` form; variants 0 to 3 wrap `Perp`, `Spot`, `Token` and `Pdi` values.
- Limits: the variant-name matcher `0x3163ca0`, arms 4 to 6, the reader `0x2f48380`, and the meaning of `uaR` are not mapped.
