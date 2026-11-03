# RE-001: node #115 shared-handle copy 0x5d50400

## Bounded question

What does routine `0x5d50400` (FDE `0x5d50400..0x5d50462`, 98 bytes)
copy, how does it choose between its two handle slots, and what does
it do to the copied handle's reference count?

## Answer, pinned to the target

The routine copies one 16-byte reference-counted handle out of a
two-slot holder. The holder layout, read directly from the routine:

- Slot A at holder `+0x00`: 16 bytes, a (pointer, control) pair —
  pointer at `+0x00`, control pointer at `+0x08`.
- Selector pointer at holder `+0x10`.
- Slot B at holder `+0x20`: 16 bytes, the same (pointer, control)
  shape as slot A.

Selection, in order:

1. Selector pointer null → copy slot A.
2. Selector pointer non-null and the byte at selector `+0x68`
   equal to 0 → copy slot A.
3. Selector pointer non-null and the byte at selector `+0x68`
   not equal to 0 → copy slot B.

The copy is a verbatim 16-byte copy into the destination at `rdi`,
and the routine returns the destination pointer (`rax = rdi`).

Reference count: if the copied control pointer is non-null, the
32-bit count at control `+0x08` is increased by exactly 1. The
increment is `lock`-prefixed when the byte at global address
`0x64ed290` is 0, and a plain add when that byte is non-zero. The
captured work binary holds 0 at that address, so the locked form is
the form in effect for the captured bytes; both branches are recorded
literally because the byte is read fresh on every call. If the copied
control pointer is null, nothing is incremented.

The routine does NOT release the destination's previous pair: it
overwrites the 16 destination bytes unconditionally. Every examined
caller passes a fresh stack temporary as the destination (see
callers.tsv), so the overwrite is safe there; callers that reused a
live destination would leak the old pair's count, and that behaviour
is recorded here, not smoothed over.

## Consumers (site-only)

The census finds 27 direct call sites, all recorded with their
enclosing caller FDE range in callers.tsv. Two were read in full:

- Site `0x5d66a14` (caller `0x5d665e0..0x5d66e22`): destination is a
  fresh stack temporary, source is a field at base `+0x570`; the
  caller then dereferences the returned pair's target.
- Site `0x5d729fe` (caller `0x5d71fe0..0x5d72e50`): destination is a
  fresh stack temporary, source is a register-held holder; the caller
  passes the copied pair onward.

Caller semantics beyond sites and FDE ranges are not claimed.

## NOT claimed

What the holder, the selector, the two slots, the flag byte, or the
managed targets denote; any field of the control block other than the
count dword at `+0x08`; the meaning of the global byte at `0x64ed290`
beyond the two increment branches it selects; caller semantics beyond
sites and FDE ranges; behaviour for a dangling selector or control
pointer (the model does not dereference them, it records the flag and
count as data).

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x5d50400 --stop-address=0x5d50462 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt text, never as
  a per-instruction list in records.json. The opening `endbr64`
  (bytes `f3 0f 1e fa`) is a genuine instruction present in the
  target binary, not a placeholder.
- `records.json`: semantic records only (layout, selection rule,
  count rule, census).
- `frames.txt`: FDE lines for the routine and the two examined
  caller functions. `callers.tsv`: all 27 direct call sites with
  their smallest enclosing caller FDE range. `relocations.txt` is
  empty: no relocation record mentions this routine.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, the FDE
  ranges, the empty relocation set, the census, the records, and the
  model tests. `census.py` reproduces the census; `export_excerpts.py`
  regenerates `main.txt`.
- Model: `tools/shared_handle_copy_115.py`, tested by
  `tests/test_shared_handle_copy_115.py`.
