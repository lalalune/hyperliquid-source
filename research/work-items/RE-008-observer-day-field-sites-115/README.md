# RE-008: node #115 observer census sites at `+0x208` / `+0x218`

- Component ID: abci. Question: open PR #5952 counted 30 `[reg+0x208]` / `[reg+0x218]` operands (32-bit displacement, base not `rsp`) in the 77 functions that call the observer record slot `0x64e1010` or the constructor slot `0x64e1020`. It named 7 of them (the record entry, the constructor and two spot checks) and left 23 unclassified. Do any of the 23 read the observer's day fields (#5946: `+0x208` the day's record-call count; #5952: `+0x210` an f64 sum; `+0x218` the scaled guard constant from #5865)?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5946 and #5952. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, the name string, RIP-relative targets, FDE extents and the census are observations. "Lazy path", "state", "begin/end pair", "pointer" and "not an observer" are inferred labels from the pinned instruction shapes. The binary was not executed.
- Scope included: the 23 sites, the instructions that load each site's base register, and the instructions that show the base's layout. Scope excluded: what the non-observer structs are, the full bodies of the five functions, and operand shapes the #5952 census does not match. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/observer_day_field_sites_115.py --check
python3 -m unittest tests.test_observer_day_field_sites_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Result: five shapes

The tool recomputes the #5952 census and fails unless it equals the 7 named sites plus the 23 below.

| Shape | Sites | Functions | Base | What the operand does |
|---|---|---|---|---|
| A | 2 | `0x2f19520` | output `rbx` (`mov rbx, rdi` at `0x2f1952e`) | 16-byte stores of a moved observer's `+0x200..+0x21f` |
| B | 5 | `0x2bdf8f0`, `0x54a9c70`, `0x54b66b0` | `rax` after `add rax, 0x110` / `mov rax, [rax]` or slot `0x64e4e70` | `mov rdx, [rax+0x208]`, then `rdx = max(rdx, r13 == -1)` |
| C | 3 | `0x2bdf8f0`, `0x54a9c70`, `0x54b66b0` | `r14 = [rsp+0x18]`, which also holds `+0x9d8` or `+0x1548` | `[r14+0x218]` compared with `0x8000000000000000` |
| D | 6 | `0x2cc1120` | `[rsp]` / `r15`, which also holds byte `+0xfb0` and dwords `+0xfb8`, `+0xfbc` | `+0x208`/`+0x210` = begin/end of u32 items (`lea rcx, [rax+rcx*4]`); `+0x218` = a pointer (`lea rax, [rsi+0xfbc]`) |
| E | 7 | `0x422abf0` | `[rsp]` / `rbx` | `+0x208..+0x227` read whole and reset to `(0, 8, 0, 0)` at `0x422acec`, `0x422bdda`, `0x422c27c` |

The full per-site list (ModRM address, function, displacement, shape, instruction) is in `evidence.json`.

### Shape A: `0x2f19520` moves one observer behind a tag

1. It calls the constructor slot (`0x2f1954d`) with the name `handle_request_rate_limiter` (`0x644408`, 27 bytes) into `rsp`, then stores `1` at `rsp+0x0` and `2.0` at `rsp+0x8` (the getter pattern from #5865).
2. It saves observer `+0x0..+0x1f8` to `rsp+0x260`, copies observer `+0x200..+0x260` to `rbx+0x208..+0x268` (the two census operands are in this run), restores the first 0x1f8 bytes at `rsp+0x7`, writes tag byte `0` at `rbx+0x0`, and copies 0x1ff bytes from `rsp` to `rbx+0x1`. Together these put observer byte `k` at `rbx+0x8+k`.
3. It stores `6000` at `rbx+0x200` (observer `+0x1f8`, the window length limit in #5952) and `1` at `rbx+0x268`.

So the two operands write the observer's own `+0x200`/`+0x210` as part of a whole-object move. They do not read the day fields.

### Shapes B to E: other structs

The bases in B to E hold fields that do not fit the observer: a sentinel compare against `0x8000000000000000` at `+0x218` (C), a u32 begin/end pair and a pointer (D), and a reset to `(0, 8, 0, 0)` that writes the integer 8 where the observer keeps an f64 (E). In B, the base comes from the lazy path, not from the constructor or a holder. These are inferred to be other structs.

## Implementation and comparison

The tool pins 66 instruction byte runs, 7 RIP-relative references and the name string, checks that each census site lies inside its pinned instruction, and recomputes the census. Tests change one byte at a time in a copy of the image (7 tests) or drop one classified site (1 test) and expect rejection. Alternatives considered: data-flow tracing of each base (not needed for these shapes); emulation (not allowed for this repository).

## Results and limitations

- Result: of the 30 census sites, the only reads of observer `+0x208` are the record entry's own increment (#5952). No site in the 77 functions reads observer `+0x218` outside the constructor's store. Shape A is the only other observer base, and it only moves the object.
- Limits: the census matches one operand shape (32-bit displacement, base not `rsp`). It misses 8-bit displacements, `rsp`-based observers, offsets inside larger holders (for example `holder + 0x260*k + 0x208`), and code outside the 77 functions. B to E are classified by layout, not by type.
- Next lead: repeat the census for holder offsets (`0x260*k + 0x208`, `0x260*k + 0x218` for small `k`, and the `+0x8` shift from shape A) across the holder functions in #5850 and #5872.
