# RE-001: node #115 record teardown 0x5d509c0

## Bounded question

What does routine `0x5d509c0` (FDE `0x5d509c0..0x5d50a06`, 70 bytes)
destroy when it is called on a record, in what order, and what does
it leave alone?

## Answer, pinned to the target

The routine tears down one record, pointed to by `rdi`. It reads
exactly four things and writes no record slot at all:

| offset | width | role |
| ------ | ----- | ---- |
| `+0x50` | 1 byte | flag: nonzero destroys the `+0xc0` member first |
| `+0x70` | 8 bytes | second heap buffer pointer |
| `+0x80` | 8 bytes | first heap buffer pointer |
| `+0xc0` | 48 bytes | condition variable, addressed only |

The sequence, in order:

1. If the byte at `+0x50` is nonzero, destroy the condition
   variable at record `+0xc0` (call to the
   `std::condition_variable` destructor entry point, `0x63f1060`).
   If the byte is zero, this step is skipped entirely.
2. If the pointer at `+0x80` is non-null, free it with operator
   `delete[]` (entry point `0x63f0dc0`). A null pointer is
   skipped, not freed.
3. If the pointer at `+0x70` is non-null, free it the same way —
   via a tail jump to the same `delete[]` entry point, so the
   delete returns directly to this routine's caller. A null
   pointer is skipped, and the routine returns normally.

The routine does NOT free the record itself, and it writes no
record slot: the `+0x50` flag, the `+0x70`/`+0x80` pointers and
every other field keep their values after the call. It never
reads `+0x00..+0x4f`, `+0x51..+0x6f`, `+0x78..+0x7f`,
`+0x88..+0xbf`, or anything at `+0xf0` or beyond, and it never
reads the condition variable's contents as data — only its
address is passed to the destructor.

Value consistency with the neighbouring initializer (observed,
not a pairing claim): the neighbouring routine `0x5d50930`
writes the word 0x100 at `+0x50` (so the flag byte at `+0x50`
is 0), writes 0 to `+0x70` and to `+0x80`, and never writes
`+0xc0..+0xef`. A record exactly as that initializer leaves it
therefore takes the flag-zero path here and frees nothing. This
packet does not claim the two routines are paired, and it does
not claim what the record, its buffers, or the condition
variable denote.

The block at `0x5d50a06..0x5d50a6c` is NOT this routine's
landing pad: it is a separate FDE, the cleanup of an enclosing
function that calls this routine twice (sites `0x5d50a32` and
`0x5d50a3a`, recorded site-only in callers.tsv). This routine
has no landing-pad block of its own, and the bytes after its
FDE range are the start of that separate block, not padding
belonging to this routine.

## Consumers (site-only)

The census finds 39 direct call sites, all recorded with their
smallest enclosing caller FDE range in callers.tsv. Caller
semantics beyond sites and FDE ranges are not claimed.

## NOT claimed

What the record, its buffers, or the condition variable denote;
what the `+0x50` flag byte denotes beyond gating the `+0xc0`
destroy; caller semantics beyond sites and FDE ranges; behaviour
on dangling pointers or a partially constructed condition
variable (the model raises on a dangling token, stated openly);
the destructor's internals beyond the entry point called.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d509c0 --stop-address=0x5d50a06 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text, never as
  a per-instruction list in records.json. The opening `endbr64`
  (bytes `f3 0f 1e fa`) is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json`: semantic records only (reads, order, census).
- `frames.txt`: FDE lines for the routine and the caller functions.
  `callers.tsv`: all 39 direct call sites with their smallest
  enclosing caller FDE range. `relocations.txt` is empty: no
  relocation record mentions this routine.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the FDE
  ranges, the empty relocation set, the census, the records, and the
  model tests. `census.py` reproduces the census; `export_excerpts.py`
  regenerates `main.txt`.
- Model: `tools/record_teardown_509c0_115.py`, tested by
  `tests/test_record_teardown_509c0_115.py`.
