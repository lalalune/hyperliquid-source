# RE-005 node115 dispatcher table: registrar, walk, and caller

Question left open by the builder-wrapper-identities packet
(PR #2969): that packet pinned the 67-byte adapter A (0x155fa10)
of the base/src/lu.rs runner, called once through GOT slot
0x64e1190 by a 498-byte dispatcher (0x15b8fd0) whose address sits
in a static .data.rel.ro table cell (0x6400548) — but it did not
say who put the dispatcher's address in that cell, what the
dispatcher walks, or who calls the dispatcher. This packet
answers all three from the binary alone. All addresses are
virtual addresses in the pinned node 115 artifact
(sha256 a6e2897c…b5301); every claim below is re-derived by
`tools/dispatcher_table_static.py` and checked by
`tests/test_dispatcher_table_static.py`.

## 1. The registrar is the linker; there is no run-time registration

Cell 0x6400548 is the method slot (+0x18) of one entry of a
four-entry static table of one-method trait-object vtables in
.data.rel.ro. Each entry is 0x20 bytes:
{drop_in_place, size, align = 8, method}.

| entry base | drop_in_place | size | method |
|---|---|---|---|
| 0x64004d0 | 0x15bb900 | 0x30 | 0x15b8cd0 |
| 0x64004f0 | 0x15bd430 | 0x38 | 0x15b8e40 |
| 0x6400510 | 0x15bc390 | 0x28 | 0x15b91d0 |
| 0x6400530 | 0x15bb300 | 0x58 | **0x15b8fd0 (dispatcher)** |

Evidence that the table is complete at link time and never
written afterwards:

- Every pointer cell of the table is the target of exactly one
  R_X86_64_RELATIVE relocation; the relocation whose addend is
  the dispatcher lands on cell 0x6400548 and on no other cell
  (a census over all 61,001 dynamic relocations).
- The table lies inside PT_GNU_RELRO (0x63f2ba0..0x64ef000),
  so the loader makes it read-only after relocation.
- A .text-wide census of rip-relative lea/load/store/cmp/test
  forms into the window 0x6400480..0x6400578 finds nine
  references, all `lea`, and no store into the table range
  (0x64004d0..0x6400550). Nothing references the method cell
  0x6400548 itself.
- Each vtable base is referenced exactly once, by a single
  `lea` inside one of four sibling spawn bodies (0x15b6d10,
  0x15b73c0, 0x15b7a80, 0x15b80e0 at sites 0x15b7028, 0x15b76d0,
  0x15b7d51, 0x15b8436). Each spawn body allocates a closure
  object of exactly its entry's size (0x30/0x38/0x28/0x58) and
  forms the fat pointer {object, its own vtable base}.
- .init_array holds 168 entries; none of them is any body
  pinned in this packet.

So the "registration" is the compiler/linker emitting the
vtable when a spawn body coerces its closure to a fat pointer.
There is no run-time registrar, no registration call, and no
mutable table to audit.

## 2. The dispatcher walks no list — it drains one packet cell

Per call, the dispatcher (0x15b8fd0..0x15b91c2):

1. calls adapter_0 (0x155f9e0) through GOT slot 0x64e1318 at
   0x15b9054, on a copy of self+0x00..0x20 (adapter_0 forwards
   the 0x20 bytes by value through slot 0x64e1188 to body
   0x5c908b0, a callee shared with five other call sites);
2. calls adapter A through slot 0x64e1190 at 0x15b907d, on a
   copy of self+0x28..0x58;
3. loads the shared packet pointer at self+0x20 (0x15b9086) and
   tests its state qword at +0x18 (cmp at 0x15b908a; the je at
   0x15b908f skips to 0x15b90da when the state is zero).

When the state is nonzero it enters the drain block at
0x15b9091. The block's only in-body branch sources are that
fall-through and the unwind landing pad's jne at 0x15b91b7.
The block loads the single fat pointer stored in the packet
({data at +0x20, vtable at +0x28}): if the data is non-null
and the vtable's drop slot (+0x00) is non-null it calls the
drop function on the data (load at 0x15b909e, indirect call at
0x15b90ae); if the vtable's size (+0x08) is nonzero it
deallocates the data through slot 0x64df4a0 (call at
0x15b90d4) with the vtable's size/align. It then writes state
1 at +0x18 (0x15b90da), writes 0 to +0x20 (r14 was zeroed at
0x15b9083) and the caller-side r15 value to +0x28, decrements
the packet strong count at +0x00 (0x15b90ef), and calls the
weak-release glue through slot 0x64dfe60 (0x15b90fb) when the
count reaches zero.

No packet field is ever followed as a next pointer and there
is no loop back edge: one packet, one stored fat pointer,
drained once. (This corrects the earlier packet's
"list-walking" shorthand for this body.) The only list-shaped
object in the neighbourhood is the static four-entry vtable
table of section 1.

## 3. The caller is the new OS thread

No code calls the dispatcher directly: the census of direct
rel32 call/jump targets over the whole .text has zero hits
for 0x15b8fd0, and the table cell is the only pointer to it
anywhere. The invocation path is:

- Spawn body 0x15b80e0 (the sibling whose entry carries the
  dispatcher) builds the RUST_MIN_STACK name from immediates
  (movabs at 0x15b8138, length 0xf, lookup through slot
  0x64e0a30 at 0x15b8179), defaults the stack to 0x200000,
  allocates the 0x58-byte closure object and a 0x18-byte
  package {thread Arc at +0x00, closure data at +0x08, vtable
  base 0x6400530 at +0x10 — store at 0x15b8461}, and hands
  (stack size, package) to the thread-create body 0x5c87b50
  through GOT slot 0x64e1580 (call at 0x15b8476; the slot's
  other 13 call sites belong to other spawn monomorphisations,
  one in each sibling body among them).
- Thread-create 0x5c87b50 sets up pthread attributes
  (pthread_attr_init / pthread_attr_setstacksize / sysconf /
  pthread_attr_destroy through their GLOB_DAT slots) and calls
  pthread_create through GLOB_DAT slot 0x64ec838 (call at
  0x5c87c2b) with start routine 0x5ca44a0 (lea at 0x5c87c19).
- Start routine 0x5ca44a0 installs the current-thread state,
  unpacks the package — closure data from +0x08 (0x5ca45a2),
  vtable from +0x10 (0x5ca45a6) — frees the 0x18-byte package,
  and calls the vtable method slot: `call *0x18(%r15)` at
  0x5ca45d7. For this entry that slot holds the dispatcher.
  After the call it frees the closure object with the
  vtable's size (+0x08, loaded at 0x5ca45db) and align.

The mirror body 0x15b8810 joins the thread: pthread_join
through slot 0x64e1590 (call at 0x15b8824; two further call
sites belong to other join monomorphisations), then a
try-unwrap of the same packet Arc and extraction of the
result fat pointer at packet +0x20/+0x28 under the flag byte
at +0x18 (test at 0x15b8873, clear at 0x15b8877). Its failure
path carries the 41-byte message "threads should not
terminate unexpectedly", the 23-byte prefix "failed to join
thread: " (length-prefixed at 0x43d3e1), and two Locations in
std/src/thread/lifecycle.rs — 247:14 and 251:14, in cells
0x6400550 and 0x6400568 immediately after the vtable table.

## Boundaries

- The three leas to the preceding statics at 0x6400488,
  0x64004a0 and 0x64004b8 (sites 0x1533e56 and 0x1533e5f in
  the body starting 0x1533d60, and 0x15d5c49 in the body
  starting 0x15d5b00) are not part of the vtable cluster and
  are recorded as boundary only.
- Which source-level closure each sibling vtable entry runs
  is identified only for the entry whose method is the
  dispatcher; the packet cell's stored fat pointer is
  described operationally (its source type, and the value in
  r15 stored back to packet +0x28, are not established inside
  the dispatcher body).
- Out of scope, as before: the 0x3d0/0x2c40 argument layouts,
  the sv[1] writer (PR #2952), the wrapper-B registration
  cell (PR #2972), and the kind-1 Once cache.

## Files

- `records.json` — bodies (FDE extents + sha256), byte pins,
  slot resolutions, the table decode, the censuses, strings
  and Locations, all re-derived by the tool.
- `frames.txt` — the readelf -wf lines for the 21 bodies.
- `*.objdump.txt` — intel-syntax disassembly of each body,
  with every pinned site present as an instruction start.
- `MANIFEST.sha256` — digests of the packet files.
