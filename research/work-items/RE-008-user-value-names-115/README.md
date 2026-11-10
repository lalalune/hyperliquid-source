# RE-008: node #115 per-user value (110th stage): serde name sources show one-byte keys only

- Component ID: abci. Question: open PR #6223 found the writer `0x3beac00` that writes the per-user value with six one-byte keys in the order `u`, `p`, `D`, `l`, `S`, `r`. Open PR #6229 named the position item from its Debug formatters, but the per-user value has no Debug formatter. Which other name source in the binary gives long names for these six fields?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6223 and #6229. It does not depend on their files.
- Claim status: instruction bytes, jump tables, relocations, strings and the censuses are observations. "Field identifier visitor", "visit_map", "ignore arm", "duplicate_field" and "FIELDS array" are inferred serde labels. The link from these visitors to the per-user value is an inference from the same six keys in the same order (see Limits). The binary was not executed.
- Scope included: the field identifier dispatch census, the length guards, the jump tables and the field indexes; the `duplicate field` error calls in `0x1a212f0`; a window census of relocated `(ptr, len)` name arrays; the list of serde `struct X with 6 elements` descriptors. Scope excluded: the bodies of the visitors after the key match, the writer `0x3beac00`, info-API and RPC serializers, and Display impls. No gate changes.

## Result

| Key | Field index | Long name |
|---|---|---|
| `u` | 0 | not in the binary (see Evidence) |
| `p` | 1 | not in the binary |
| `D` | 2 | not in the binary |
| `l` | 3 | not in the binary |
| `S` | 4 | not in the binary |
| `r` | 5 | not in the binary |

No long name is pinned. The serde sources that could hold one hold only the one-byte names.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_value_names_115.py --check
python3 -m unittest tests.test_user_value_names_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The three `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the field visitors match one-byte keys only

The tool finds every place in `.text` that subtracts `0x44` (`D`) from a byte and then bounds it with `0x31` (`u`). There are 11, in five functions: `0x1a212f0`, `0x30bcb40` (both with rmp-serde `decode.rs` paths), `0x1e5b990` (serde_json `de.rs` and `read.rs` paths), `0x40bcb50` and `0x4a426f0`.

- Each site is reached only after a length check against 1 (for example `cmp r12d, 1` at `0x1a21c5c`).
- A key of any other length jumps to the same target as a byte outside `D..u` (for `0x30bd11b`, to one `mov rdi, [rsp+8]` before it). At `0x1a21c5a` that path has already set `al = 6`.
- Each jump table has exactly six arms that differ from its default: `D`, `S`, `l`, `p`, `r`, `u`.
- In six tables the arms set the field index: `u` = 0, `p` = 1, `D` = 2, `l` = 3, `S` = 4, `r` = 5. Index 6 is the ignore arm. This is the key order of the writer in #6223.

A `#[serde(alias = "...")]` with a long name would need a second compare for that length. There is none: a long key falls into the ignore arm.

## Evidence 2: error strings carry the one-byte names

`0x1a212f0` formats the template `0x43351a` (`duplicate field `{}``) six times (`0x1a22e1f..0x1a22f7a`). Each call passes a string of length 1: `S`, `l`, `r`, `p`, `D`, `u`.

## Evidence 3: no FIELDS array with the six names

The tool reads every relocated `(ptr, len)` pair with a length of 1 to 64. No six consecutive pairs hold exactly `u`, `p`, `D`, `l`, `S`, `r` in any order. The same scan finds the #6229 alias table `0x6483c28` (`l`, `leverage`, `raw_usd`, `u`) and a second copy at `0x6432b78`. A long-name FIELDS array cannot be checked this way, because its names are not known.

## Evidence 4: six-element struct descriptors

The binary has 19 serde descriptors of the form `struct X with 6 elements`. The tool lists them. It does not bind any of them to this value. `UserStates` has long field names next to it in the string pool (`user_to_state`, `users_with_positions`, `asset_to_oi_szi`, `open_order_tracker`); these belong to the container, not to the value.

## Limits

- The link from the five visitors to the per-user value is by key set and order. The tool does not follow a visitor's output stores to the layout in #6223.
- The visitor's `struct X with 6 elements` text (its Rust type name) was not found near the five visitors.
- No `missing field` call for these names was found in `0x1a212f0`; other visitors were not read for it.
- Not checked: info-API JSON serializers that may write the same data with long names (they sit in RPC code, which is out of scope), and Display impls.
- The `D` item `{a, c}` and the `S` value `{s, r}` were not checked.
