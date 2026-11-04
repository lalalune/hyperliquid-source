# RE-001: node #115 four-string record disposal 0x5d50740

## Bounded question

What does routine `0x5d50740` (FDE `0x5d50740..0x5d507c2`, 130 bytes)
dispose, in what order, and under what condition is each field's
buffer freed rather than left alone?

## Answer, pinned to the target

The routine disposes the four string fields of one record. It walks
them in exactly this order (base offsets from the record pointer):

    0x80, 0x60, 0x20, 0x00

Each field is one 32-byte string: pointer at field `+0x00`, size at
`+0x08` (never read by this routine), capacity-or-inline-buffer at
`+0x10`. For each field, in order:

1. Load the pointer at field `+0x00`.
2. Compare it with the address of the field's own `+0x10` slot.
3. Equal (the pointer is the inline buffer, SSO) → free nothing,
   move to the next field.
4. Different (a heap string) → free the buffer with
   delete(pointer, capacity + 1), where the capacity is read from
   the field's `+0x10` slot.

The first three fields are freed with a direct call to the delete
entry point (`0x63f0d80`, the `_ZdlPvm` PLT); the last field
(`+0x00`) is freed by a tail jump to the same entry point. The
observable effect is identical: the buffer is freed with size
capacity + 1 either way.

The routine frees only those four fields. It does NOT free the
record itself, does not write to any record slot (the pointer and
capacity slots are left exactly as they were), and does not read or
touch any other field of the record — including the `+0x08` size
slots of the four strings and every byte outside the four fields.
The bytes after the FDE range (`0x5d507c2..0x5d507d0`) are int3
padding to the next function, not a landing-pad block: this routine
has no landing-pad block inside or after its range.

Distinct from the neighbouring four-string disposals at `0x5d506b0`
(fields 0xf8, 0xd8, 0x48, 0x28) and `0x5d507d0` (ten fields): this is
a different routine with its own field set and its own call sites.

## Consumers (site-only)

The census finds 9 direct call sites, all recorded with their
enclosing caller FDE range in callers.tsv. Caller semantics beyond
sites and FDE ranges are not claimed.

## NOT claimed

What the record and its strings denote; the meaning of the fields
between the four strings that this routine never touches; caller
semantics beyond sites and FDE ranges; behaviour for dangling
pointers or inconsistent capacity values (the model records the
freed size as data and does not dereference anything).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d50740 --stop-address=0x5d507c2 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text, never as
  a per-instruction list in records.json. The opening `endbr64`
  (bytes `f3 0f 1e fa`) is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json`: semantic records only (field walk order, dispose
  rule, census).
- `frames.txt`: FDE lines for the routine and the caller functions.
  `callers.tsv`: all 9 direct call sites with their smallest
  enclosing caller FDE range. `relocations.txt` is empty: no
  relocation record mentions this routine.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the FDE
  ranges, the empty relocation set, the census, the records, and the
  model tests. `census.py` reproduces the census; `export_excerpts.py`
  regenerates `main.txt`.
- Model: `tools/string_dispose_50740_115.py`, tested by
  `tests/test_string_dispose_50740_115.py`.
