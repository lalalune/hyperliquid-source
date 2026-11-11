# RE-015: layout-b rmp `write_uint` copies, width helpers and RawVec growth (node #115)

This packet makes it possible to rebuild, as one executable Python model, the MessagePack unsigned-integer writer
that the layout-b `newtype(VecDeque<u64>)` chain writers call: which of five forms is chosen (positive fixint,
0xcc/0xcd/0xce/0xcf), that the tag byte is stored before the capacity of the payload is checked, the exact growth
rule (double, never below 8, or the exact requirement), which of the two growth sites reports `Err(0)` and
`Err(1)`, how the result record is laid out per copy family, and the `reserve` / `finish_grow` pair underneath it
(minimum capacity by element size, `isize::MAX - align` refusal, plain versus aligned allocator selection). The
model was checked against the real bytes of 3 `write_uint` copies, 10 width helpers, 3 `reserve` and 3
`finish_grow` copies (19 functions, 1,848 instructions) on 24,858 generated cases with 0 mismatches, and 337 of
337 negative controls were detected.

- Component ID: `constants` (RE-015 serializer/string-reference work)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: lalalune/hyperliquid-source main `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source
  used (references/can1357-hl was not consulted)
- Claim status: observation (bytes, call pattern, executed behaviour of the original instructions) + inference
  (the rmp / RawVec names for the roles)
- Scope included: `write_uint` at 0x25e9c70 (family 226), 0x3d517e0 (419), 0x57d00b0 (52f); the width helpers
  0x25ea4b0/0x25ea780/0x25ea910, 0x3d51d10/0x3d51f40/0x3d520d0, 0x57d0250/0x57d0510/0x57d0750/0x57d08e0;
  `reserve` 0x231e050/0x43bd910/0x5963a10; `finish_grow` 0x231dc90/0x43bd550/0x5963650, all run for real.
  Excluded: the layout-a `write_uint` copies (901 bytes, owned by RE-015-rmp-vecdeque-u64-115), the allocator
  behind the four relocated GOT slots (stubbed), the callers (chain writers, owned elsewhere). No progress gate
  is requested.

## Reproduce

From the repository root (Python 3 standard library only; binutils not needed; the binary is never executed):

```
python3 tools/re015_rmp_write_uint_b_115.py --out research/work-items/RE-015-rmp-write-uint-b-115
python3 -m unittest tests.test_re015_rmp_write_uint_b_115
```

- The tool checks the input SHA-256 first and stops on any other binary.
- It writes `functions.tsv`, `allocator-slots.tsv`, `cases-sample.tsv`, `controls.tsv`, `coverage.tsv`,
  `equivalent-flips.txt`, `summary.json` and `measure.json`; `MANIFEST.sha256` lists every file in this folder.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical files.
- A full run takes about 135 s and peaks at about 540 MB resident. Cases are generated and evaluated one at a
  time; the case list is the only large structure.
- Case generation is a SHA-512 counter stream keyed by family; every list is deterministic and no clock, path or
  random value reaches an output file.
- The evaluator (lines before the `target constants` section of the tool) is the concrete x86-64 evaluator of the
  RE-015 vecdeque packet; this tool adds the new target, model, cases and controls. ELF sections, relocations and
  FDE extents come from `tools/elf_index.py` and `tools/fde_extents.py`; SHT_NOBITS sections are never read.

## Evidence

Coordinates are virtual addresses of the loaded image (file offset = VA minus section address plus section
offset, read through the section table). FDE starts and ends come from `.eh_frame_hdr` records.

Observations read from bytes (all in `functions.tsv`, rechecked by `facts()` on every run):

- Each `write_uint` copy calls exactly the set {its width helpers, its `reserve`, its `finish_grow`}; every helper
  calls exactly {`reserve`, `finish_grow`}; `reserve` calls only `finish_grow`; `finish_grow` has no direct call
  and reaches the allocator through the four GOT slots in `allocator-slots.tsv` plus the alloc-error slot
  0x64df498 used by `reserve`.
- Families 226 and 419 store the 0xcc tag inline in `write_uint` (no u8 helper); family 52f has a u8 helper
  0x57d0250 and no inline 0xcc store. Every helper stores its own tag (`movb $0xcd|0xce|0xcf`).
- The 52f helpers receive the serializer pointer and load the vector pointer themselves; the 226 and 419 helpers
  receive the vector pointer. The three `write_uint` copies and the helpers all return 2 on success.
- The four GOT slots are RELATIVE relocations (not dynamic imports): their targets are internal allocator
  wrappers, so `allocator-slots.tsv` shows `-` as the import symbol. Their roles are fixed by use inside
  `finish_grow`: 0x64df480 is called with the size only (malloc), 0x64df588 with pointer and size (realloc),
  0x64df590 with size and a tzcnt of the alignment (aligned alloc), 0x64df580 with pointer, size and the same
  tzcnt (aligned realloc).

Behaviour of the original instructions (what the 24,858 cases compare):

| step | rule observed |
| --- | --- |
| form choice | v < 0x80 fixint; < 0x100 tag 0xcc; < 0x10000 tag 0xcd; < 2^32 tag 0xce; else tag 0xcf |
| fixint | one byte; a full buffer (cap == len) grows first to max(8, 2*len); failure returns `Err(0)` |
| width helper | grow if full (max(8, 2*len), failure `Err(0)`), store tag, len += 1; if free bytes < payload width: required = old len + 1 + width, `Err(1)` if that wraps below the new len, else grow to max(8, 2*cap, required), failure `Err(1)`; store big-endian payload |
| failed second growth | the tag byte stays written and len stays advanced; cap and pointer are unchanged |
| result record | success (2, marker): fixint marker is byte 0 = 0x00, byte 1 = value, the other bytes untouched; tag marker is the tag as a full qword in families 226 and 52f, but a one-byte store in family 419 (other bytes untouched); error (code, 0x2600000003) |
| `finish_grow` | size = newcap * elem; multiply overflow or size > 2^63 - align refuses before any allocator call; cap 0 and size 0 returns the alignment as pointer; plain allocator when align < 0x11 and align <= size or when align is odd, otherwise aligned allocator with tzcnt(align); NULL result gives (1, align, size) |
| `reserve` | elem 0 or len + add carry calls handle_alloc_error(0, len); new cap = max(2*cap, len + add, 8 | 4 | 1) where the minimum is 8 for 1-byte elements, 4 up to 0x400 bytes, else 1 |

## Implementation and comparison

The independent model is `write_uint_b`, `helper`, `push_fix`, `finish_grow`, `reserve_model` and `VecModel`
in the tool (no Rust path is claimed; this is a Python reconstruction). The expectation side never reads the
evaluator: it computes the result record, the final {cap, ptr, len}, the whole final buffer and the ordered
allocator call list (`malloc`, `realloc`, `amalloc`, `arealloc` with sizes and old sizes) from the case alone.

The stub allocator is a declared contract: call number k fails when k equals the case's `fail_at` or when the
size exceeds 0x10000; the n-th successful call returns a fresh region at a fixed address; realloc copies
min(old, new) bytes. Both the machine stub and the model apply the same rule, written separately.

Case groups per family (all deterministic):

- exhaustive: every (cap, len <= cap) up to 12, 12 boundary values, no failure / first / second allocation
  failing (3,276 cases per family);
- random: 2,200 states in six shapes (small, full, one byte free, 0x8000..0x10000 capacities, ...) with boundary
  and random values;
- direct helper entries: 1,400 per family with values inside each helper's width;
- capacity extremes: cap = len at 2^62 - 1, 2^62, 2^62 + 1 (doubling and size-limit refusals) and at the
  0x2001..0x10000 allocator limit, the large ones with a wrapped pointer so no memory is touched;
- wrapped-length cases: len within 11 of 2^64 with a pointer chosen so ptr + len lands in a small region, which
  targets the `required < new len` carry check of the helpers (see coverage for what was reached);
- direct `finish_grow` (700 per family; 9 alignments, 8 element sizes, overflow sizes) and direct `reserve`
  (500 per family, including elem 0 and carry).

Negative controls (337, all detected; `controls.tsv`): 16 model mutants (width limits 0x80/0x100/0x10000/2^32,
no doubling, minimum capacity 4, wrong tag, room off by one, wrap check removed, little-endian payload, swapped
error codes, allocator limit, no realloc copy, size limit, plain-allocator condition, minimum capacity by element
size); 5 range controls (flipped binary digest, helper address not an FDE start, helper swapped with the u32
helper, wrong tag constant, wrong allocator slot); and 316 single-bit byte flips at executed tag stores, width
limit immediates, the shift, room compares, minimum-capacity immediates, conditional jumps and conditional moves.
For each site the first of six bit positions that changes any result is used; three `mincap8` sites (one per
family, the u64 helper) change no result under any tried bit and are listed as equivalent in
`equivalent-flips.txt`, not counted as controls.

## Results and limitations

- 24,858 cases, 0 mismatches on the first full run: `call` 14,572 (of which 6,236 with an allocator failure),
  `call-wrap` 450, direct `finish_grow` 2,100, direct `reserve` 1,500 (`summary.json` has the exact split).
- 1,582 of 1,848 instructions executed (`coverage.tsv`); `finish_grow` and `reserve` are fully covered. The
  unexecuted instructions are the `reserve` call arms inside `write_uint` and the helpers (for example 0x25e9ea0)
  that need a vector with cap == len after a successful grow, i.e. len > cap; they were not reached by any case
  and are not modelled. This is stated as unreached, not as proved unreachable.
- The allocator behind the GOT slots is stubbed; the model says nothing about what it does with alignment beyond
  the call list. `handle_alloc_error` arguments of the overflow arm include an uninitialised stack word that the
  comparison ignores.
- Cases keep len <= cap except the wrapped-length group, where cap = len + extra by construction.
- No gate is requested; callers of these `write_uint` copies (the chain writers) are covered by
  RE-015-rmp-vecdeque-u64-115.

Next question: the layout-a copies of the same helpers (0x25ea640, 0x25ea6e0 and their 419/52f twins, which have
no growth of their own) and the 658/727/850-byte other-shape `newtype` bodies listed in the vecdeque packet.
