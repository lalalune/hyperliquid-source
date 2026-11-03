# RE-001: node #115 record initializer 0x5d50930

## Bounded question

What does routine `0x5d50930` (FDE `0x5d50930..0x5d509bc`, 140 bytes)
write into the record its `rdi` argument points to, which bytes does
it leave alone, and does it call anything?

## Answer, pinned to the target

The routine initializes a record in place. It takes exactly one
argument, the destination pointer in `rdi`, makes no calls at all,
and writes only constant values — no input besides the pointer is
read. The writes, in the order the routine issues them:

| offset | width | value |
| ------ | ----- | ----- |
| `+0x00` | 8 | 0 |
| `+0x08` | 2 | 0 |
| `+0x0a` | 1 | 0 |
| `+0x0c` | 4 | 4 |
| `+0x10` | 1 | 0 |
| `+0x18` | 16 | 0 |
| `+0x28` | 16 | 0 |
| `+0x38` | 16 | 0 |
| `+0x48` | 8 | 0 |
| `+0x50` | 2 | 0x100 (256) |
| `+0x58` | 8 | 0 |
| `+0x60` | 8 | 0x00ffffffffffffff (72057594037927935) |
| `+0x68` | 4 | 0 |
| `+0x6c` | 2 | 0 |
| `+0x70` | 8 | 0 |
| `+0x78` | 4 | 0 |
| `+0x7c` | 2 | 0 |
| `+0x80` | 8 | 0 |
| `+0xf0` | 16 | 0 |

Three values are non-zero and therefore pin the record's shape:
the dword 4 at `+0x0c`, the word 0x100 at `+0x50`, and the qword
0x00ffffffffffffff at `+0x60`. Everything else the routine writes
is zero. The zeroed 16-byte blocks at `+0x18`, `+0x28`, `+0x38`
and `+0xf0` come from one zeroed `xmm0` register, so they are
exactly zero, not merely "cleared in passing".

Bytes inside `0x00..0x100` that the routine never touches, and
that therefore keep whatever value they had before the call:

    0x0b, 0x11..0x17, 0x52..0x57, 0x6e..0x6f, 0x7e..0x7f, 0x88..0xef

The routine writes nothing outside `0x00..0x100`. At `ret`, `rax`
still holds 0x00ffffffffffffff (the `+0x60` constant, loaded before
it was stored); whether any caller reads that register value is
not claimed.

The bytes after the FDE range (`0x5d509bc..0x5d509c0`) are int3
padding to the next routine, not a landing-pad block: this routine
has no landing-pad block and no exception path of its own.

## Consumers (site-only)

The census finds 6 direct call sites, all recorded with their
enclosing caller FDE range in callers.tsv. Caller semantics beyond
sites and FDE ranges are not claimed.

## Neighbour, not claimed as paired

The immediately following routine, `0x5d509c0` (FDE
`0x5d509c0..0x5d50a06`), reads the `+0x50` byte, the `+0x80`
pointer and the `+0x70` pointer that this initializer writes, and
frees the two pointers when non-null. That routine is recorded
here as the next candidate only: this packet does not claim it is
this record's destructor, and it does not claim what the `+0xc0`
member it conditionally destroys denotes, since this initializer
never writes `+0xc0..0xef`.

## NOT claimed

What the record and its fields denote; the meaning of the
non-zero constants 4, 0x100 and 0x00ffffffffffffff beyond their
exact values and positions; the values of the untouched bytes;
caller semantics beyond sites and FDE ranges; behaviour for a
null or short destination (the model raises, stated openly).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d50930 --stop-address=0x5d509bc work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text, never as
  a per-instruction list in records.json. The opening `endbr64`
  (bytes `f3 0f 1e fa`) is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json`: semantic records only (write table, untouched
  ranges, census).
- `frames.txt`: FDE lines for the routine and the caller functions.
  `callers.tsv`: all 6 direct call sites with their smallest
  enclosing caller FDE range. `relocations.txt` is empty: no
  relocation record mentions this routine.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the FDE
  ranges, the empty relocation set, the census, the records, and the
  model tests. `census.py` reproduces the census; `export_excerpts.py`
  regenerates `main.txt`.
- Model: `tools/record_init_50930_115.py`, tested by
  `tests/test_record_init_50930_115.py`.
