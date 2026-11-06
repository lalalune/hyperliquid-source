# Tracked work item RE-005-node115-thread-handle-internals

```text
program:   node #115 x86-64 node software
source:    artifacts/node/115/hl-node (byte-identical node captured
           by the enclosing repository)
technique: constructor / drop-chain reconstruction over the
           authenticated ELF -- a binary-wide census of the
           malloc(0x30) construction pattern, per-instruction
           byte pins for the three constructor bodies, the
           field-drop glue, the name validator and the ThreadId
           panic shim, plus the GOT-slot relocation records and
           panic Locations that name the mechanisms -- answering
           the one question the packet-cell-context packet
           (PR #3204) left open as its "thread_handle_internals"
           boundary: the decomposition of the main-thread
           handle's own allocation beyond the parker state word
           at handle +0x28.  That packet pinned ScopeData's field
           at A+0x10 as the main thread's handle, the context
           release's strong-count decrement on it and the payload
           drop's parker-word xchg at [A+0x10]+0x28, and saw the
           drop glue free a (pointer, length) buffer from
           +0x18/+0x20; PR #3206 pinned that thread::scope is
           not instantiated, which does not by itself decompose
           the handle type.  The evidence here closes the
           decomposition: (1) the handle allocation is exactly
           0x30 bytes through the libc malloc slot (0x64e1570) at
           all 16 construction sites -- the 14 spawn bodies, the
           current-thread lazy initialiser 0x5c9d1f0 (which
           carries the thread/current.rs line 315 Location and
           calls the field-drop glue on its own unwind path) and
           a sibling unnamed initialiser 0x5c82fd0 -- and every
           site executes the same store map: strong = 1 at +0x00,
           weak = 1 at +0x08, thread id at +0x10, a (pointer,
           length) pair at +0x18/+0x20, zeroed word at +0x28, and
           no store at +0x2c; (2) the id is minted inline from
           the global counter 0x6500050 with a lock cmpxchg loop
           (ThreadId::new inlined) whose overflow arm calls the
           panic shim 0x5ca4480 (message "failed to generate
           unique thread ID: bitspace exhausted", thread/id.rs
           Location line 38 col 13; exactly 22 direct callers);
           (3) the +0x18/+0x20 pair is the thread's name: the
           spawn constructions pass the string through the
           validator 0x5ca5760, which scans it for an interior
           NUL and panics at the thread/thread.rs Location
           (line 24 col 40, "thread name may not contain
           interior null bytes") or returns the pair unchanged,
           while the two initialisers store a zero pointer and
           never store the length; (4) the field-drop glue
           0x5c98b40 (108 call sites through its slot, 77
           distinct owner bodies) zeroes the name buffer's first
           byte, frees it by (pointer, length) through the
           dealloc slot when both are nonzero, decrements the
           weak count and at zero tail-jumps to libc free on the
           whole block -- the size-free free is why the total
           size had to come from the constructors.  Conclusion:
           the handle is a 0x30-byte Arc allocation, inner
           layout {+0x10 thread id, +0x18 name buffer pointer,
           +0x20 name buffer length, +0x28 parker state word},
           header at +0x00/+0x08, and nothing beyond the parker
           word but 4 bytes of tail padding.
execution: none
result:    records.json is generated from an authenticated ELF;
           the attempted check fails closed before any packet file
           is regenerated
```

## Files

- `records.json` — artifact identity, the six owner records (FDE
  extent, file offset, byte count, SHA-256), the per-instruction
  byte pins, the GOT-slot relocation records, the three panic
  Locations, the closed layout table, and the three censuses:
  the construction census (16 malloc(0x30) sites with their
  named/unnamed store-map variants), the field-drop glue's
  call-site census, and the ThreadId panic shim's direct-caller
  census.
- `main_thread_ctor.objdump.txt` — disassembly of the
  current-thread lazy initialiser 0x5c9d1f0..0x5c9d323: the
  inlined ThreadId mint, the malloc(0x30), the unnamed store
  block, the alloc-error arm and the unwind-path drop call.
- `scoped_region_ctor.objdump.txt` — disassembly of the sibling
  unnamed initialiser 0x5c82fd0..0x5c8312c in the
  scoped-machinery neighborhood.
- `spawn_thread_ctor.objdump.txt` — disassembly of one spawn
  constructor 0x5613a70..0x56141ee: the name validation call,
  the inlined ThreadId mint and the named store block.
- `thread_field_drop.objdump.txt` — disassembly of the shared
  field-drop glue 0x5c98b40..0x5c98b89: the name buffer release,
  the weak-count decrement and the tail jump to free.
- `name_validator.objdump.txt` — disassembly of the thread-name
  validator 0x5ca5760..0x5ca58c3: the interior-NUL scan and the
  thread.rs line 24 panic arm.
- `thread_id_panic_shim.objdump.txt` — disassembly of the
  ThreadId overflow panic shim 0x5ca4480..0x5ca449d.
- `frames.txt` — the .eh_frame FDE lines of the six owner
  bodies.
- `MANIFEST.sha256` — SHA-256 of every other file in this
  directory.
