# RE-001: map node #115 record teardown 0x5d593f0 with its four per-record fields and two callers

Bounded question: what does node #115 routine 0x5d593f0 (FDE
0x5d593f0..0x5d594dd, 237 bytes) do to the holder in rdi, end to end?

## Answer

It is a record teardown, not a destructor: it disposes four
pointer/capacity fields per record of the holder's array, then frees
the holder's buffer — but it never frees the holder itself, writes
nothing to the holder or the records, and performs no canary check.
It pushes r12/rbp/rbx and reserves no stack.

Holder layout: record range [holder+0x00, holder+0x08), record
stride 0x130, buffer capacity end at holder+0x10. The loop end is
loaded once at entry; an empty range skips straight to the buffer
exit. Per record, in order:

1. Field at record+0x100: pointer at +0x100, capacity at +0x110.
2. Field at record+0xe0: pointer at +0xe0, capacity at +0xf0.
3. Field at record+0x50: pointer at +0x50, capacity at +0x60.
4. Field at record+0x30: pointer at +0x30, capacity at +0x40.

Each field follows the same short-form rule: when the data pointer
equals the field base + 0x10 (the address of its capacity slot),
nothing is freed; otherwise a sized delete of (pointer,
capacity + 1) through the _ZdlPvm PLT at 0x63f0d80. The fourth
field advances the record cursor before its sized-delete call; the
observable free order is unchanged.

After the loop, the holder buffer exit reloads the begin pointer
from holder+0x00: when it is non-null, a tail jump to the
sized-delete PLT frees (begin, [holder+0x10] - begin); the +0x08
end is not reset and the begin pointer is not cleared. When the
begin pointer is null, the routine returns plainly.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 2 direct calls + 0 tail jumps across 2 caller
FDEs (see callers.tsv); 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations for the routine — reached only by code, never
by data.

Relation to neighbouring work: distinct from the record-loop
teardown 0x5d591d0 (0x218-byte records with a +0x210 pointer and
string vectors) and from the adjacent loop 0x5d59510 (0x1d8-byte
records with eleven fields). This routine walks 0x130-byte records
with exactly four fields and no other per-record step, and it shares
no field offset set with either neighbour.

## Unknowns (not claimed)

- What the four fields hold beyond their pointer/capacity shape;
  they are recorded as observed pairs only.
- What the two caller functions do with the holder before or after
  this call; only the call sites and their FDEs are recorded.
- Behaviour on a null begin with a non-empty range (the binary would
  dereference the null begin); the model requires a valid range or
  a null pair.

## Evidence and verification

- Packet: research/work-items/RE-001-record-teardown-593f0-115/
  (semantic records.json only; whole-function verbatim excerpt
  main.txt; caller_sites.txt with 32-byte windows at each of the 2
  sites; frames.txt with the routine + 2 caller FDEs; callers.tsv;
  relocations.txt; verify.py + export_excerpts.py + census.py in
  packet; MANIFEST.sha256).
- Model: tools/record_teardown_593f0_115.py;
  tests: tests/test_record_teardown_593f0_115.py.
- Regenerate excerpts: `python3
  research/work-items/RE-001-record-teardown-593f0-115/export_excerpts.py`
  (objdump command: `objdump -d --start-address=0x5d593f0
  --stop-address=0x5d594dd work/hl-node-115.bin`).
- Check everything: `python3
  research/work-items/RE-001-record-teardown-593f0-115/verify.py`
  (digest, provenance, manifest, excerpt regeneration byte-for-byte
  from fresh objdump runs, every main.txt line byte-for-byte vs the
  raw binary, all FDE lines, census incl. exact site list, empty
  relocation census, records, model spot checks, model tests).
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
