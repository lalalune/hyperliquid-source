# foundation-set-once-94: what do the set-once cell setter windows compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl was a search lead only. No inferred implementation
  was copied, and no reference label is treated as established fact below.
- Claim: observations about five target instruction windows and their
  per-window fields and ranges; their source-level names, types, and the
  meaning of the 0/1/8 returns remain inferences or unknowns.
- Included: the five FDE windows at `0x1515880`, `0x15158c0`, `0x1515900`,
  `0x1515940`, and `0x1515980`, their int3 padding bytes, and the exact
  set-once protocol each one implements.
- Excluded: the rest of the setter run past `0x15159c0` (it continues to
  `0x1515ce0`), the caller of any window, all #115 addresses, target
  execution, Rust reconstruction, and complete caller behavior.

## Why this packet

The component map asks to map small helpers and distinguish library code
from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds five adjacent, previously
unclaimed windows that all implement one directly readable protocol with
different fields and ranges, and it separates what the bytes show from
what they do not show. It establishes a concrete small entrypoint for
further reconstruction without declaring the component mapped.

This packet was checked for overlap before building: no work-item, tool, or
test in the tree mentions `0x1515880`, `0x15158c0`, `0x1515900`,
`0x1515940`, or `0x1515980`, and no open pull request title mentions any
of those addresses or set-once/set_once.

## Distinction from the submitted once-flag packet (PR #174)

This family is mechanically distinct from the twin once-flag windows bound
in PR #174, and the distinction is stated here rather than assumed. The
once-flag windows use an atomic exchange, a shared global slot, a
thread-local zero test, and a tail jump through an imported syscall slot.
These five windows contain none of that: no lock prefix, no atomic
exchange, no call of any kind, no thread-local test, and no tail jump
through an imported slot. Every path in all five windows ends in a plain
`ret`, and every cell they touch is reached by a fixed displacement from
the incoming `rdi` pointer. The shared shape is the set-once protocol
itself, not the once-flag mechanism.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python
3.12.3, GNU objdump 2.42 (Binutils for Ubuntu), GnuPG 2.4.4. The checker and
tests use Python's standard library only. No llvm-objdump, Ghidra, or Java
was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in
CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_set_once.py --check research/work-items/foundation-set-once-94/evidence.json
python3 -m unittest tests.test_foundation_set_once -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured
service, networked node, chain operation, or model-backed program was
executed. All analysis below is static byte evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1515880 --stop-address=0x15159c0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `set_once.objdump.txt` file retains complete disassembly of the five
windows including their padding. The `set_once.frames.txt` file retains
excerpts selecting the FDEs at `.eh_frame` section offsets `0x14454`,
`0x14468`, `0x1447c`, `0x14490`, and `0x144a4`. The checker locks these raw
FDE records and their shared CIE, and reads their PC/range fields. It does
not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers the packet's retained files.

A note on the retained disassembly: objdump annotates each window with a
nearest-symbol label. Those labels are objdump's proximity guesses, not
recovered symbol names, and nothing in this packet relies on them.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`;
the retained `.eh_frame` has equal file offsets and VAs. The tools resolve
sections rather than assuming one global VA/file-offset relationship.

### FDE extents and the index-stride correction

| Window | FDE extent | Bytes | Stride | int3 padding |
| --- | --- | --- | --- | --- |
| `0x1515880` | `[0x1515880, 0x15158b2)` | 50 | 64 | 14 |
| `0x15158c0` | `[0x15158c0, 0x1515900)` | 64 | 64 | 0 |
| `0x1515900` | `[0x1515900, 0x1515937)` | 55 | 64 | 9 |
| `0x1515940` | `[0x1515940, 0x1515979)` | 57 | 64 | 7 |
| `0x1515980` | `[0x1515980, 0x15159b9)` | 57 | 64 | 7 |

Each FDE extent was confirmed by GNU's independent frame dump, not by the
unwind-index stride alone. Where the stride is longer than the FDE, the
difference is exactly the trailing `int3` bytes, and the checker locks the
body and the padding separately. The packet #1 lesson (80-byte stride vs
75-byte FDE) applies here in the same way.

### The shared protocol

Every window implements the same protocol, read directly from its
instruction stream:

- Out-of-range input returns `0` and touches nothing.
- An unset cell stores the input (after any window-specific remap) and
  returns `8`.
- A set cell returns `8` when the stored value matches the input and `1`
  when it differs.
- The equal/mismatch choice is made by one `cmove` selecting between the
  immediates `8` and `1` in every window.

The returns `0`, `1`, and `8` are observed values only. Their meaning as
any enum, status code, or boolean is not proven and is not claimed.

### Byte cell, `0x1515880`

- Field: byte at `[rdi+0xa0]`. Sentinel: `7` means unset.
- `dec rsi; cmp $6, rsi; ja` out-of-range return: original inputs `1..7`
  are valid, and the stored value is the original input minus one
  (`0..6`). Inputs `0` and `8+` return `0`.
- `movzbl 0xa0(rdi), eax; cmp $7, al`: cell `7` stores `sil` and returns
  `8`; otherwise `cmp sil, al` with `cmove` returns `8` on equality, `1`
  on mismatch.

### Byte cell with table remap, `0x15158c0`

- Same field `[rdi+0xa0]`, same sentinel `7`, same store/compare/return
  shape as `0x1515880`.
- Input path differs: `cmp $6, rsi; ja` out-of-range return admits original
  inputs `0..6`; `shl $3, esi` then `movabs $0x5040302010006, rax; shr
  cl, rax` takes the low byte of the table at index `input`, giving the
  map `0→6, 1→0, 2→1, 3→2, 4→3, 5→4, 6→5`. The remapped value is what is
  stored and compared, so the stored range is again `0..6` and never the
  sentinel `7`.

### Flag cell with byte test and 12-to-0 remap, `0x1515900`

- Fields: flag at `[rdi+0x78]`, value at `[rdi+0x7c]`.
- `lea rcx = rsi - 1; cmp $0xb, rcx; ja` out-of-range return: original
  inputs `1..12` are valid. `cmp $0xc, rsi; cmove eax, esi` zeroes the
  value when the input is `12`, so `12` is stored as `0`.
- The set test reads only the low byte of the flag field: `cmpb $0,
  0x78(rdi); je` store arm. A zero low byte stores the full u32 value `1`
  to `[rdi+0x78]` and the value to `[rdi+0x7c]`, then returns `8`. A
  nonzero low byte goes to `cmp esi, 0x7c(rdi)` with the usual `cmove`
  returning `8` on equality, `1` on mismatch.
- This window's test is genuinely different from the next two: they test
  the full u32 flag against `1`, while this one tests only the low byte
  against `0`. The README records the difference rather than smoothing
  it into one description.

### Flag cells with full u32 test, `0x1515940` and `0x1515980`

- `0x1515940`: flag at `[rdi+0x80]`, value at `[rdi+0x84]`, input range
  `0..59` (`cmp $0x3b, rsi; ja` return `0`).
- `0x1515980`: flag at `[rdi+0x88]`, value at `[rdi+0x8c]`, input range
  `0..60` (`cmp $0x3c, rsi; ja` return `0`).
- Both: `cmpl $1, flag(rdi); jne` store arm. A flag other than `1` stores
  flag `1` and the value, then returns `8`. A flag of `1` goes to `cmp
  esi, value(rdi)` with the usual `cmove` returning `8` on equality, `1`
  on mismatch.

## Inferences and unknowns

- **Inferred:** these five windows implement the same set-once protocol
  with per-window fields and ranges. The identical return triple, the
  identical `cmove` shape, and the identical store/compare structure
  support that label.
- The `0/1/8` returns are not given enum meanings: no callers, no
  consumers of the returns, and no type information were recovered.
- The struct or object owning the `rdi` fields is not proven: the fields
  are displacements from an incoming pointer, and no allocation site or
  type layout was decoded. The flag fields at `0x78`/`0x80`/`0x88` and the
  byte cell at `0xa0` are close together, but adjacency alone does not
  prove they belong to one struct.
- The byte table at `0x15158c0` is a literal constant in the instruction
  stream; why the map `0→6, 1→0, 2→1, 3→2, 4→3, 5→4, 6→5` exists is
  unknown. The `12` stored as `0` in `0x1515900` is likewise an observed
  remap with an unknown reason.
- The rest of the setter run past `0x15159c0` was not decoded, so whether
  later windows share this protocol, and whether any caller uses more than
  one of these windows, is not closed.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence
comparison, normalization mask, behavioral execution, or whole-ELF match is
claimed. All are **not yet implemented/measured**. The raw instruction bytes
in the checker are static evidence locks, not executable reconstruction or
transplanted code. New checker/test/documentation code is independently
authored; imported bytes and disassembly retain the artifact's original
rights.

The repository's required verification, catalogue, and test recipes are run
for this change below. After the change, the new checker and the new unit
test pass. The added controls use the authenticated
real target (explicitly skip if LFS is absent), not fabricated behavior
fixtures. They reject:

- wrong identity and truncation;
- changed range immediates, sentinel compare, or flag compare;
- changed byte-table constant or table shift;
- changed store opcodes, store fields, or store values;
- changed compare/cmov return selection;
- changed FDE extent, FDE range, or FDE padding bytes.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at
SHA-256. The command-line tool always authenticates the complete target
first.

**No progress gate requested.** Foundation's four gates and generated
progress files stay unchanged. The denominator here is five bounded
windows, not all setters. Next question: decode the next windows of the
setter run past `0x15159c0` only if they stay this small and directly
readable; otherwise leave the run here.
