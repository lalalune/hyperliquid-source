# Tracked work item RE-005-node115-record-producer

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: static trace of who produces the pipeline records the
           RE-005 level-3 functions operate on, from the level-3
           callers pinned by the block-fill packet (PR #2543) upward:
           twenty-two pinned bodies (the level-3 callers, the level
           above them, the registration stub and frame constructor of
           the c chain, and the spawner/wrapper producers of the d/e
           chains).  On the a and c chains the producers are stack
           constructors: lvl4_c builds every record it hands down on
           its own ~0xb328-byte frame, filling the phase struct it
           passes to lvl4_a through an indirect call via GOT slot
           0x64e1760, and ctor_c passes its own frame as the phase
           struct and is reachable only through a 39-byte
           registration stub -- the binary's main function; lvl3_a
           builds the lvl2_a record head
           out of its own struct's fields plus a GOT-slot call
           result, and lvl4_a/lvl3_c shape their sub-records out of
           their phase structs' head fields.  On the d/e chains the
           level-3 bodies are pure forwarders reached through
           .data.rel.ro cells embedded in 0x3080-byte heap task
           records by four wrapper spawners, and the payload that
           lands at task record +0x38 -- the lvl2 record's offset --
           is assembled by spawn_d/spawn_e on their own stacks
           through helper calls and copies, then handed down through
           the pre_* bodies.  The direct-access census of the five
           descriptor fields and the named head sources, mapped
           through every embedding, is empty in all twenty-two
           bodies: the byte-level first writers sit one step inside
           the producers, in the helper calls and whole-record
           copies whose sources are themselves stack-built.  None of
           the pinned bodies is among PR #2300's six reader-state
           extents; the trace does not enter that area.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the twenty-two owner records
  (FDE extent, file offset, byte count, SHA-256), the per-instruction
  byte pins for the eighteen exported bodies, the direct-call-site
  census of all twenty-nine subjects (with tail-call and
  modrm-checked lea census), the six-slot indirect-invocation census
  (relocation addend, neighbour addends, rip-relative references),
  the per-body direct-access census of the descriptor fields, head
  sources and pinned aliases through every embedding, the per-body
  call-path records, the record-producer identity records, the
  boundaries and the method limits.
- `*.objdump.txt` — full objdump exports of the eighteen bodies of
  at most about 4 KB (the four level-3 forwarders, ctor_c, the
  registration stub, the four wrapper spawners, the four pre_*
  forwarders, call4a_b, pre_4ab, spawn_d, spawn_e). Path normalised
  to `<authenticated-node115>`; regenerate to compare.
- `frames.txt` — the `readelf -wf` lines for the twenty-two owner
  functions.
- `MANIFEST.sha256` — hashes for every packet file.

## Regeneration

Run from the repository root with the artifact materialised:

### Regenerate the packet files

```sh
python3 tools/record_producer_static.py --generate
```

### Verify the manifest

```sh
(cd research/work-items/RE-005-node115-record-producer && \
 sha256sum -c MANIFEST.sha256)
```

### Run the dedicated tests

```sh
python3 -m unittest tests.test_record_producer_static -v
```

## Static boundary

No captured instruction was executed.  The direct-access census
covers the record registers, the pinned alias registers and the
stack bases of the twenty-two pinned bodies, at the embeddings the
traced call sites establish; whole-record copies move bytes without
naming fields -- the copies observed (the spawn bodies' struct
copies, the wrappers' payload and record copies, the shaping copies
of lvl4_a/lvl3_c) are enumerated in the call paths -- so for copied
fields the census is a statement about direct accesses and the
copies actually observed.  The step from the wrappers' heap task
records to the lvl3_d/e invocations is established by the
relocation slots, the wrappers' slot-address stores and the exact
offset alignment (payload byte 0 lands at task record +0x38, the
lvl2 record's embedding offset in the lvl3 entry structs); the
executor that performs the invocation is not identified.  The
phase-struct layout shared by lvl4_a, lvl3_c and ctor_c's frame
(dispatch byte +0x21a, shaping at +0x220) is established by
identical offsets and store shapes, not by type information.  The
two registrars and the helper bodies 0x5cf93f0 and 0x2d4d540 are
censused as call targets only; their bodies are not pinned by this
packet.
