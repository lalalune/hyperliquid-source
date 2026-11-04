# RE-001-node115-lu-sizerep: the node #115 lu size representative helper

- Component ID: `0x63e8c80` size representative helper, node #115
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (fetch-confirmed unmoved before analysis)
- Claim status: observation for all decoded instructions, census, and FDE bounds; inference for the representative reading of the two-round logic; unresolved for table contents, base provenance, and the fourth caller's purpose
- Scope included and excluded: included — the full `0x63e8c80..0x63e8d87` FDE (263 bytes), its census, and its contract relative to sibling `0x63e8bf0`. Excluded — the sibling's bytes, the table-writer FDE at `0x63e8d90`, the `.bss` table contents (not in the file), and all caller FDEs beyond their call sites (cited by address only).

## Reproduce

Working directory: the worktree root. Static analysis only; the node
binary is never executed. `objdump -d --start-address=0x63e8c80
--stop-address=0x63e8d87 artifacts/node/115/hl-node` reproduces the
full FDE disassembly; `readelf --debug-dump=frames
artifacts/node/115/hl-node` shows
`pc=00000000063e8c80..00000000063e8d87`. Coordinate system: `.text`
file offset = VA − 0x1000. `python3 tools/node115_lu_sizerep.py`
re-runs every check in this packet (exit 0); `python3 -m unittest
tests.test_node115_lu_sizerep` re-runs the unit tests (10/10).

## Evidence

FDE bounds from the unwind tables: `0x63e8c80..0x63e8d87`
(263 bytes); the following bytes to `0x63e8d90` are `int3` padding
and the next function's `endbr64`. Two `ret` sites (`0x63e8d4a`,
`0x63e8d5f`), zero `call` instructions, all jump targets inside
the FDE, no stores to memory anywhere in the FDE — the function is
pure in (input, base, table).

Round 1 (exhibits `sr_entry`, `sr_index`): `rsi = x`,
`rdi = [0x6728140]` (base `B`), `rax = x - B`, `rdx = rax + 1`.
If `rdx > 0x7000000000000000`, index 198 (`0xc6` at `0x63e8d70`).
Otherwise `ecx = ceil_log2(rdx)` via the `bsr` + `and` + `sbb`
idiom, clamped to a minimum of 14; `r9d = ecx - 14`; if zero, the
small path (`sr_small`) returns `x` when `(d >> 12) & 3 == 0`, else
uses index `((d >> 12) & 3) - 1`. Otherwise `index = (edi - 14) *
4 + ((d >> (edi - 3)) & 3) - 1`.

Cover check and round 2 (exhibits `sr_table`, `sr_round2`):
`r11 = T[index]` (qword load from table base `0x6728180`),
candidate `B + T[index]`; `jae` to the return-`x` path when the
candidate covers `x`. Otherwise round 2 recomputes the index from
`T[index]` with the same idiom minus the `-1` (clamped shift 12
in the small case, huge corner index 199 `0xc7` at `0x63e8d80`)
and returns `B + T[j]` unconditionally.

Census: whole-`.text` byte scan for E8 with a rel32 target filter,
each site confirmed by per-site objdump as `call 63e8c80`:
`0x63b09cb`, `0x63b0f62`, `0x63b0fbc` (#226 finder FDE),
`0x63d934b` (FDE starting `0x63d9340`). No E9 tail jumps, no LEA
references, no `.rela.dyn` addend equal to `0x63e8c80` among
60,723 entries.

Sibling comparison (address citation only): `0x63e8bf0` reads the
same base `0x6728140` and the same table `0x6728180`, runs the
same round-1 index computation, and returns `B + T[i]`
unconditionally — no cover check, no second round. Its FDE is
`0x63e8bf0..0x63e8c77`, disjoint from this packet's FDE.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed in
this packet. The verifier and unit tests check byte-level facts
only (exhibit bytes, strict mnemonic counts, key bytes, census,
FDE bounds, MANIFEST coverage, tamper control).

## Results and limitations

Machine-readable metrics: 5 exhibits, 180 bytes, 47 strict
mnemonics; census 4 E8 / 0 E9 / 0 LEA / 0 GOT; FDE 263 bytes;
MANIFEST 15/15 entries. What remains unknown: the numeric table
contents (runtime `.bss`), the base value's provenance, the
fourth caller's purpose, and whether table values are class
maxima, minima, or canonical sizes. Next question: decode the FDE
starting at `0x63e8d90` end to end — what it writes to
`[0x6728140]` and how it fills table `0x6728180`.
