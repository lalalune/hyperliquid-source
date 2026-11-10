# RE-008: node #115 hourly line framing (stage 78): `[time,value]` for visor_abci_states, bare objects for abci_hashes and abci_digest_quorum

- Component ID: abci. Question: stage 77b (open PR #6076) found that the `node save visor_abci_state` thread appends one line to the hourly `visor_abci_states` log through `0x4e3fe00` → `0x50e50b0` → the compact serializer `0x51addb0`. It left open how the line is framed and how the time is written, and whether the other hourly logs (#6033, #6034) use the same framing.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #5876, #6033, #6034 and #6076. Imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, relocations, call sites and censuses are observations. "Date", "time", "Display", "core::fmt::write", "line" and "log" are inferred labels from the call shapes and characters written. The binary was not executed.
- Scope included: the framer `0x50e50b0`, the time writer `0x4fcd860`, its Display function `0x57a6f10` and one separator in each of its two callees, the two bare framers `0x50e5fc0` and `0x50e6fe0` at their record call and newline, and a byte-shape census of the callers of the line writer `0x14c37f0`. Scope excluded: the bodies of the date and time formatters beyond the pinned separators, the fraction digits, the pieces table contents, and the 75 non-visor framers. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/hourly_line_framing_115.py --check
python3 -m unittest tests.test_hourly_line_framing_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: the visor_abci_states framer

`0x4e3ff5c` calls `0x50e50b0`. It allocates 0x80 bytes and writes:

| Step | Address | Bytes |
|---|---|---|
| `[` | `0x50e50ed` | `c6 00 5b` |
| time | `0x50e5112` | `call 0x4fcd860` |
| `,` | `0x50e513d` | `c6 04 30 2c` |
| value | `0x50e5151` | `call 0x51addb0` (the #6076 compact serializer) |
| `]` | `0x50e51d4` | `c6 04 30 5d` |
| newline | `0x50e521b` | `41 c6 04 06 0a` |
| write | `0x50e5231` | `call 0x14c37f0` (the #5876 line writer) |

So each line is `[<time>,<object>]` plus a newline, the same frame as the `mempool_txs` line in #5876.

## Evidence 2: the time is a quoted ISO-style string

`0x4fcd860` writes `"` (`0x4fcd889`), calls `core::fmt::write` (slot `0x64df6f0` → `0x1680500`) with the pieces table `0x649ffd0` and the Display function `0x57a6f10` (`0x4fcd8b0`), then writes `"` (`0x4fcd8ec`).

`0x57a6f10` calls the date formatter through slot `0x64e1158` (→ `0x1628bc0`, which writes `-` at `0x1628d09`), writes `T` (`mov esi, 0x54` at `0x57a6f34`), then tail-jumps through slot `0x64e1160` (→ `0x162a760`, which writes `:` at `0x162a81f` and compares the nanoseconds with 1000000000 at `0x162a789`) on the value at `+4`.

Inference: the time is written as `"YYYY-MM-DDTHH:MM:SS…"`, the shape of chrono's `NaiveDateTime` debug form. The fraction digits are not bound.

## Evidence 3: abci_hashes and abci_digest_quorum lines are bare objects

- `abci_hashes` (#6034): `0x4e3a8dc` calls `0x50e5fc0`, which calls the record serializer `0x537d5e0` (`0x50e600e`), appends a newline (`0x50e60bb`) and writes. It does not call `0x4fcd860` and writes no `[`.
- `abci_digest_quorum` (#6033): `0x4e3a15c` calls `0x50e6fe0`, which calls `0x537d7b0` (`0x50e702e`), appends a newline (`0x50e70db`) and writes. Same shape.

## Evidence 4: line-writer census

`0x14c37f0` has 96 direct call sites in 96 functions. By byte shape:

| Class | Functions | Rule |
|---|---|---|
| time_framed | 21 | calls `0x4fcd860` |
| bracket_no_time | 39 | stores `[` at a fresh buffer (`c6 00 5b`) without calling `0x4fcd860` |
| other | 36 | neither |

`0x4fcd860` has 27 direct calls in all.

## Results and limitations

- Result: `visor_abci_states` lines are `["<date>T<time>",{…six fields…}]`; `abci_hashes` and `abci_digest_quorum` lines are bare JSON objects.
- Limits: the census is a byte-shape check, not a data-flow proof; `bracket_no_time` and `other` are not mapped one by one; the fraction format, the pieces table and whether the time is UTC are not bound.
- Next lead: map the 39 `bracket_no_time` framers' time source.
