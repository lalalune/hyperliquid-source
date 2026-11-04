# RE-001: map node #115 shared-release array teardown 0x5d590c0 with its refcount decrement and 6 callers

Bounded question: what does node #115 routine 0x5d590c0 (FDE
0x5d590c0..0x5d591c1, 257 bytes) do to the holder in rdi, end to end?

## Answer

It is a shared-release array teardown, not a destructor: it releases
one shared control block and disposes one string per element of the
holder's array, then frees the holder's buffer — but it never frees
the holder itself, never reads a holder table slot, and performs no
canary check. It pushes r14/r13/r12/rbp/rbx and reserves no stack.

Holder layout: element range [holder+0x00, holder+0x08), element
stride 0x40, buffer capacity end at holder+0x10. Per element, in
order:

1. Control release (element+0x38). A null pointer skips the release
   and the string step still runs. Otherwise the control block at
   +0x08 holds one combined 64-bit count: low 32 bits use count,
   high 32 bits weak count.
   - Sentinel: when the combined count equals 0x100000001 (use 1,
     weak 1), the whole count is zeroed, then the dispose table
     slot (+0x10) and the destroy table slot (+0x18) of the object
     at [control+0x00] are called directly. The helper below is not
     used on this path.
   - Otherwise the use count is decremented: plainly when the
     __libc_single_threaded byte (reached through the pointer held
     at slot 0x64ed290, a GLOB_DAT relocation to
     __libc_single_threaded) is nonzero, with LOCK XADD otherwise.
     Observable results are identical in both modes. A zero use
     count wraps to 2**32 - 1 with no dispose call.
   - When the old use count was 1, helper 0x5d35070 (76 bytes,
     verified separately) is called with the control block: it
     calls the dispose table slot (+0x10), decrements the weak
     count with the same single-threaded rule, and tail-dispatches
     the destroy table slot (+0x18) only when the old weak count
     was 1. When reached from this routine that destroy arm cannot
     fire: (use, weak) == (1, 1) is intercepted by the sentinel
     path first, so any old weak count the helper sees differs
     from 1.
2. String dispose (element+0x08). Short form (data pointer equals
   element+0x18, i.e. string address + 0x10) frees nothing;
   otherwise a sized delete of (pointer, capacity + 1) with capacity
   at element+0x18.
3. After the loop, the holder buffer exit: when the begin pointer at
   holder+0x00 is non-null, a tail jump to the sized-delete PLT
   frees (begin, [holder+0x10] - begin); the +0x08 end is not reset.
   When the begin pointer is null, the routine returns plainly. An
   empty range skips straight to this exit.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 6 direct calls + 0 tail jumps across 6 caller
FDEs (see callers.tsv); 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations for the routine — reached only by code, never
by data.

Relation to neighbouring work: the plain/locked decrement shapes are
the release side of the shared-copy increment routine 0x5d50400
(covered by #2712), which reads the same flag slot. Distinct from
the record-loop teardown 0x5d591d0: that routine walks 0x218-byte
records with a +0x210 pointer and string vectors, while this routine
walks a flat 0x40-byte element array with one control release plus
one string per element and no record fields.

## Unknowns (not claimed)

- What the dispose/destroy table slots compute beyond their
  positions; on the sentinel path they are recorded as call-shape
  only.
- What the six caller functions do with the holder before or after
  this call; only the call sites and their FDEs are recorded.
- Behaviour on a null begin with a non-null end (the binary would
  dereference the null begin); the model requires a valid range or
  a null pair.

## Evidence and verification

- Packet: research/work-items/RE-001-shared-release-array-590c0-115/
  (semantic records.json only; whole-function verbatim excerpt
  main.txt; caller_sites.txt with 32-byte windows at each of the 6
  sites; frames.txt with the routine + 6 caller FDEs; callers.tsv;
  relocations.txt; verify.py + export_excerpts.py + census.py in
  packet; MANIFEST.sha256).
- Model: tools/shared_release_array_590c0_115.py;
  tests: tests/test_shared_release_array_590c0_115.py.
- Regenerate excerpts: `python3
  research/work-items/RE-001-shared-release-array-590c0-115/export_excerpts.py`
  (objdump command: `objdump -d --start-address=0x5d590c0
  --stop-address=0x5d591c1 work/hl-node-115.bin`).
- Check everything: `python3
  research/work-items/RE-001-shared-release-array-590c0-115/verify.py`
  (digest, provenance, manifest, excerpt regeneration byte-for-byte
  from fresh objdump runs, every main.txt line byte-for-byte vs the
  raw binary, all FDE lines, census incl. exact site list, empty
  relocation census, flag-slot resolution, records, model spot
  checks, model tests).
- The raw excerpts are verbatim objdump output: tokens such as
  `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- Bound to artifact digest
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (provenance/artifacts.json entry artifacts/node/115/hl-node).
- Environment honesty: this VM has no cargo/rustc, no git-lfs, no
  Ghidra/Java, and pytest is not installed (model tests are invoked
  directly by verify.py). `make verify` / `make test` /
  `make catalogue-check` were not run in a tooled environment and no
  hosted CI result is claimed.
