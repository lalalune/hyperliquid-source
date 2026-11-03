# Tracked work item RE-005-node115-spawn-payload-fields

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static trace of the three questions the record-producer
           packet (PR #2555) left open, over six pinned bodies: the
           payload producers spawn_d (0x2ad5980) and spawn_e
           (0x2ad6560) again, the helpers they call -- the GOT-slot
           0x64e7360 callee 0x4784130 and the direct callee
           0x2d4d540 -- the GOT-slot 0x64e1760 callee 0x5cf9600,
           and lvl4_c (0x2ae1690), the caller that hands the last
           of those its two structs.  Inside the spawns, the slot
           callee writes the record struct at [0x10..0x200) (with
           its second argument a scalar rate parameter, not a
           length), the direct callee writes no byte of the record
           at all (it reads the record copy as a lookup key and
           writes into the context object instead), the 0x148-byte
           head copy and the spawns' own stores finish the head,
           and record [0x1f0..0x2ff8) has no writer in any pinned
           body before the payload copy reads it.  The range
           0x64478a0..0x6447910 the predecessor called a handler
           table is a run of adjacent .data.rel.ro statics -- two
           relocated pointers to .rodata file-name strings, two
           {function, 0x340, 0x8} descriptors, and the bare
           relocated pointers to spawn_e/spawn_d; a complete
           reference census (every candidate verified against the
           FDE-synced disassembly of its containing function)
           finds twelve references, all passing an address as a
           call argument, none loading through, indexing, or
           calling through the range, and the spawn pointers
           named by no instruction at all.  The 0x64e1760 callee
           fills only the phase struct's [0x0..0x50) head: a tag
           and result word on the short arm, a fresh 0x98-byte
           block pointer, the query pointer and a result pair on
           the long arm, nothing at all on the wrapper arm; it
           reads the query struct and stores into it nowhere.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the six owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins for the four exported bodies, the two GOT slots'
  relocation and rip-relative reference censuses, the
  handler-table-range census (slot contents, twelve verified
  references with their forms, every raw candidate with its
  verified/refuted verdict, base-qword and addend scans), the
  direct-call-site census of the three callee bodies (with
  tail-call and lea census), the spawns' direct-access census,
  the classified access censuses of the three callee bodies
  (stores, loads and address-takens by entry register and
  offset), the spawn-payload, handler-table and phase-fill
  findings records, the boundaries and the method limits.
- `*.objdump.txt` — full objdump exports of the four bodies of at
  most about 4 KB (spawn_d, spawn_e, the 0x64e7360 callee, the
  direct callee 0x2d4d540). Path normalised to
  `<authenticated-node115>`; regenerate to compare.
- `frames.txt` — the `readelf -wf` lines for the six owner
  functions.
- `MANIFEST.sha256` — hashes for every packet file.

## Regeneration

Run from the repository root with the artifact materialised:

### Regenerate the packet files

```sh
python3 tools/spawn_payload_fields_static.py --generate
```

### Verify the manifest

```sh
(cd research/work-items/RE-005-node115-spawn-payload-fields && \
 sha256sum -c MANIFEST.sha256)
```

### Run the dedicated tests

```sh
python3 -m unittest tests.test_spawn_payload_fields_static -v
```

## Static boundary

No captured instruction was executed.  The classified access
census classifies each instruction of the three callee bodies by
operand position in fresh objdump text; register identity follows
the entry assignments and, for the phase callee, the census is
split at its first r14 reload and its rbx stores are enumerated by
address because rbx is reloaded on a later arm.  Whole-record
copies move bytes without naming fields -- the copies observed
(the spawns' struct copies, the head copy, the slot callee's
[0x78..0x128) copy) are enumerated in the findings -- so for
copied fields the census is a statement about direct accesses and
the copies actually observed.  The handler-table census verifies
every candidate reference by re-disassembling its containing FDE
from its start; raw byte-pattern hits that do not survive that
check are recorded as phantoms, not references.  How spawn_e and
spawn_d come to be invoked is not established: their addresses
sit as bare relocated fields among the statics, named by nothing.
