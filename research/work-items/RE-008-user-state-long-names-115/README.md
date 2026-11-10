# RE-008: node #115 position item and CumFunding long field names (109th stage)

- Component ID: user-state. Question: open PRs #6224 and #6226 mapped the per-user position item `{s, l, M, f, e}` and its `f` struct `{a, o, c}` from the serde writers, which use one-letter keys only. They left open what the Rust field names are. #6226 found alias tables (such as `0x6483c28`) only for the `l` enum.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6224 and #6226. It does not depend on their files.
- Claim status: instruction bytes, string bytes, relocations, vtable sizes, FDE extents and the slot call census are observations. "Debug formatter", "five-field Debug helper", "DebugStruct field call" and the pairing of a Debug body with a serde writer by offset and type are inferences from the call shapes. The binary was not executed.
- Scope included: the Debug bodies `0x44dbc30` (Position), `0x44e85c0` (CumFunding) and `0x44e7cc0` (Leverage); the key and offset instructions of the position JSON writer `0x448ae20` and the `f` JSON writer `0x448b410`. Scope excluded: the msgpack writers, the helper bodies `0x167f960` and `0x167d950`, the per-user value, `S` and `D`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/user_state_long_names_115.py --check
python3 -m unittest tests.test_user_state_long_names_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Result: short to long names

| Struct | Key | Offset | Long name | Debug value size |
|---|---|---|---|---|
| position item (`Position`) | `s` | `+0x10` | `szi` | 8 |
| | `l` | `+0x0` | `leverage` | 16 |
| | `M` | `+0x38` | `margin_table_id` | 4 |
| | `f` | `+0x18` | `cum_funding` | 24 |
| | `e` | `+0x30` | `entry_ntl` | 8 (by reference) |
| `f` struct (`CumFunding`) | `a` | `+0x0` | `all_time` | |
| | `o` | `+0x8` | `since_open` | |
| | `c` | `+0x10` | `since_change` | |

## Evidence 1: the Position Debug body

- `0x44dbc30` loads the item base as `r10 = **rdi`, builds the arguments and calls slot `0x64e1ef0` (relocated to `0x167f960`) at `0x44dbcd7`. That slot has 6 call sites in `.text`.
- Register arguments: struct name `0x458d20` length 8 (`Position`), then the first field name `0x7d13be` length 3 (`szi`) with value `r9 = r10+0x10`. The other 17 arguments are pushes. The tool decodes them in reverse push order as (vtable, name, length, value, vtable, ...):

| Name (va, length) | Value | Vtable | Vtable size | Vtable fmt |
|---|---|---|---|---|
| `szi` (`0x7d13be`, 3) | `+0x10` | `0x648ce48` | 8 | `0x42167b0` |
| `leverage` (`0x458f18`, 8) | `+0x0` | `0x648ce68` | 16 | `0x44e7cc0` |
| `margin_table_id` (`0x7d334e`, 15) | `+0x38` | `0x648ce88` | 4 | `0x44eaf00` |
| `cum_funding` (`0x7d13c2`, 11) | `+0x18` | `0x648cea8` | 24 | `0x44e85c0` |
| `entry_ntl` (`0x7d13ce`, 9) | `&(+0x30)` (spilled at `0x44dbc50`) | `0x648c6e0` | 8 | `0x46dcd10` |

- Inference: `0x167f960` is the standard five-field Debug helper (name, then five name/value/vtable groups). The vtable sizes match the serde types from #6224/#6226: i64, the 16-byte `Leverage`, u32, the 24-byte `f` struct and a reference.

## Evidence 2: the same offsets in the serde writer

In the position JSON writer `0x448ae20` (`rbx = rdi` at `0x448ae2e`):

| Key (string va) | Key load | Value |
|---|---|---|
| `s` (`0x7d082f`) | `0x448af18` | `r14 = [rbx+0x10]` (`0x448ae59`), passed at `0x448af6c` |
| `l` (`0x7d0946`) | `0x448af87` | `rdi = rbx` (`0x448afd6`) to `0x420a0d0` (the Leverage writer from #6226) |
| `M` (`0x7d13c1`) | `0x448afff` | `rcx = rbx+0x38` (`0x448affb`) |
| `f` (`0x7d13cd`) | `0x448b06d` | `rdi = rbx+0x18` (`0x448b08e`) to `0x448b410` |
| `e` (`0x7d0bd9`) | `0x448b0f3` | `rbx += 0x30` (`0x448b0ef`), `rcx = rbx` (`0x448b104`) |

The keys `M` and `f` are single bytes inside the packed string `sziMcum_fundingfentry_ntl` at `0x7d13be`, which also holds three of the Debug names. This is a linker merge and is not used as evidence.

## Evidence 3: CumFunding

- The `cum_funding` vtable's fmt `0x44e85c0` writes `CumFunding` (`0x7d2578`, 10) and calls slot `0x64dfad0` (relocated to `0x167d950`, inferred DebugStruct field) three times: `all_time` (`0x459428`, 8) with `rdi+0x0`, `since_open` (`0x7d2582`, 10) with `rdi+0x8`, `since_change` (`0x7d258c`, 12) with a reference to `rdi+0x10`.
- The `f` JSON writer `0x448b410` loads `[rdi]`, `[rdi+0x8]`, `[rdi+0x10]` and writes them under `a` (`0x7d098e`), `o` (`0x7d0929`) and `c` (`0x7d0c8d`) in that order.

## Evidence 4: Leverage cross-check

The `leverage` vtable's fmt `0x44e7cc0` tests `dword [rdi] == 1`. Tag 1 writes `Isolated` with `leverage` (`+0x4`) and `raw_usd` (`+0x8`); any other tag writes `Cross` with `+0x4`. These are the long names of the serde alias tables `0x6483c28` (`l`/`leverage`, `u`/`raw_usd`) and `0x6483c68` (`C`/`Cross`, `I`/`Isolated`) from #6226, so the Debug names and the serde names agree for this type.

## Implementation and comparison

The tool pins 45 instruction byte runs, 21 references, 2 relocations and 16 strings, decodes the 0x44dbc30 argument set-up from bytes (only the encodings in that window are accepted), checks the five decoded offsets against the serde offsets, checks two field vtables against the CumFunding and Leverage Debug bodies, and recomputes the slot `0x64e1ef0` call census. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: serde alias tables like `0x6483c28` (a scan of relocated (pointer, length) arrays found none for these structs: they have no `alias` attributes); the strings `szi`, `entryPx`, `positionValue` near the info API names (API names, not field names).

## Results and limitations

- Result: the position item is `Position {szi, leverage, margin_table_id, cum_funding, entry_ntl}` and its `f` struct is `CumFunding {all_time, since_open, since_change}`.
- Limits:
  - The per-user value `{u, p, D, l, S, r}`, `S {s, r}` and `D {a, c}` are not bound. A review-only text census of the 351 loads of the DebugStruct field slot `0x64dfad0` and the 6 calls through `0x64e1ef0` lists the struct names those formatters write. The only `UserState` there is the book-order state `{book_order_keys, reduce_only_oids, untriggered_orders}`. By inspection, none fits these three types. This census is not in the tool. Debug bodies that use other helpers or were removed by the compiler are not covered.
  - The pairing of a Debug body with a serde writer relies on equal offsets, vtable sizes and the vtable link; no single function references both.
  - The helper bodies `0x167f960` and `0x167d950` are not read; their names are inferred.
