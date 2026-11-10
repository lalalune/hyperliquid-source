# RE-008: node #115 position decoder (114th stage): long key names for s, l, f and e

- Component ID: abci. Question: open PR #6224 maps the position writer (`0x4634470`, `0x448ae20`) with the one-byte keys `s`, `l`, `M`, `f`, `e`. Open PR #6239 found that the per-user value field `p` accepts two long key names. Does the position decoder also accept long key names, and which defaults does it give a missing field?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6224 and #6239. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, call targets and strings are observations. "Key", "field", "default" and "skip" are inferred labels. The binary was not executed.
- Scope included: the position decoder `0x1bb6b90` (key path, field table, field arms, end-of-map defaults, duplicate-field names), the two key matchers `0x183e010` and `0x2d129d0`, and the M decoder head `0x2d15d00`. Scope excluded: the bodies of the field decoders, the map visitor and the output layout. No gate changes.

## Result

| Field index | Field | Accepted keys | Field decoder | Default when missing |
|---|---|---|---|---|
| 0 | s | `s`, `szi` | `0x17d63f0` (name `Szi`) | 0 |
| 1 | l | `l`, `leverage` | `0x17b62b0` | tag 0 with 0x14 (20) |
| 2 | M | `M` only | `0x2d15d00` (name `MarginTableId`) | 0x14 (20); a decoded 0 also becomes 20 |
| 3 | f | `f`, `cum_funding` | `0x1b2ee70` | 0, 0, 0 |
| 4 | e | `e`, `entry_ntl` | `0x17d4770` (name `Ntl`) | 0 |
| 5 | (other) | any other key | skip `0x19ccaf0` | — |

Both key matchers accept the same keys and give the same index. Both accept only keys of 1 to 11 bytes, so `margin_table_id` (15 bytes) is not a name for M: it is index 5 and its value is skipped.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/position_long_keys_115.py --check
python3 -m unittest tests.test_position_long_keys_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The six `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: two matchers, one key set

- After a string key, the decoder calls the UTF-8 check (slot `0x64dfca8`, `0x1bb71fc`). A key that fails the check goes to `0x183e010` (`0x1bb7215`). A valid key goes to `0x2d129d0` (`0x1bb7246`). A binary key goes to `0x183e010` (`0x1bb73a6`).
- `0x183e010` starts with `dec edx; cmp edx,0xa; ja other`, and `0x2d129d0` with `dec rdx; cmp rdx,0xa; ja other`. So only lengths 1 to 11 reach a key compare.
- Each matcher has a length table (`0x4abf4c`, `0x60fc28`). Lengths 3, 8, 9 and 11 go to the `szi`, `leverage`, `entry_ntl` and `cum_funding` arms. All other lengths from 2 to 11 go to the "other" arm (index 5).
- Length 1 goes to a byte table (`0x4abf78`, `0x60fc54`) for the bytes `M` to `s`. Only `M`, `e`, `f`, `l` and `s` have their own arm.
- `0x183e010` checks each byte (`cmp byte [rsi+n], c`). `0x2d129d0` compares 8-byte constants (for example `0x656761726576656c`, which is `leverage`). The tool reads the compare bytes at fixed addresses and spells each key from them.
- Each arm sets the field index (`mov al, n` or `mov cl, n`; `xor eax,eax` or `xor ecx,ecx` for 0). The "other" arm sets 5.

## Evidence 2: field table and field decoders

- The decoder loads the field table `0x59c45c` (`0x1bb6cd0`, `0x1bb728f`) and jumps on the index (`0x1bb6e4a`). Index 0 to 4 go to the s, l, M, f and e arms. Index 5 goes to `0x1bb6d80`, which calls the skip function `0x19ccaf0`.
- The s arm calls `0x17d63f0` with the 3-byte name `Szi`. The e arm calls `0x17d4770` with the 3-byte name `Ntl`. The M arm calls `0x2d15d00`, which jumps to `0x17e4bb0` with the 13-byte name `MarginTableId`. The f arm calls `0x1b2ee70`. The l arm calls `0x17b62b0`.
- A field seen twice gives `duplicate field` with a 1-byte name: `s` `0x5c87d4`, `e` `0x5c8d25`, `f` `0x5c898f`, `M` `0x5c94a3`, `l` `0x5c8994` (`0x1bb7fb0` to `0x1bb7fe3`). So the main name of each field is the one-byte key; the long names are second names.

## Evidence 3: defaults

- At map start the decoder sets each field to "not seen": s, e and f flags 0, the l tag 2 and M 0 (`0x1bb6cb4`).
- At the end of the map (`0x1bb7b1b`), a field that was not seen gets: s 0, e 0, f 0, 0, 0. If the l tag is still 2 (`cmp ebp,2`), l becomes tag 0 with 0x14. If M is 0 (`test r14d,r14d`), M becomes 0x14 (`mov ecx,0x14`; `cmove`). An empty map gives the same values (`0x1bb7649`).
- Tag 0 is probably the Cross variant, so the l default is probably Cross with leverage 20. This packet does not check the variant order; this is an inference.

## Implementation and comparison

The tool pins 17 instruction byte runs (each with its meaning), reads the field table and the four matcher tables, checks 9 call targets and 8 string loads, spells the four long keys from the compare bytes in both matchers, reads the length limit, and reads the default constant. Tests change bytes in a copy of the image and expect rejection (9 mutation tests). Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternatives considered: decoding a sample position by running the code (not allowed for this repository).

## Results and limitations

- Result: the position decoder accepts `szi`, `leverage`, `cum_funding` and `entry_ntl` as second names for `s`, `l`, `f` and `e`. M has no long name. Unknown keys are skipped.
- Limits: this packet does not map where each field is stored in the decoded position, so the link to the writer offsets in #6224 is by field index and name only. The field decoder bodies are not read. Whether the M decoder rejects 0 is not checked; if it does not, a stored M of 0 reads back as 20.
