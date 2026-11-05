# RE-005 node115 neighbor statics: the three cells before the dispatcher table

Question left open by the dispatcher-table packet (PR #3000):
that packet pinned the four-entry one-method vtable table at
0x64004d0..0x6400550 in .data.rel.ro and recorded, as a
boundary only, three `lea` references to the statics sitting
immediately before the table — cells 0x6400488 and 0x64004a0
(lea'd at 0x1533e56 and 0x1533e5f inside the body at
0x1533d60) and cell 0x64004b8 (lea'd at 0x15d5c49 inside the
body at 0x15d5b00). This packet identifies all three cells,
how each referencing body reads them, and whether they belong
to the table's closure family. All addresses are virtual
addresses in the pinned node 115 artifact (sha256
a6e2897c…b5301); every claim below is re-derived by
`tools/neighbor_statics.py` and checked by
`tests/test_neighbor_statics.py`.

The short answer: none of the three is a vtable entry or a
closure-family member. They are three 0x18-byte statics of
two different kinds — one io error-message datum and two
`core::panic::Location` statics — referenced once each by
two bodies that are not spawn siblings.

## 1. Cell 0x6400488 — a static io error-message datum ("failed to write whole buffer", WriteZero)

The cell is 0x18 bytes: {&str at +0x00, dword 23 at +0x10,
dword 0 at +0x14}. Its only relocation is one
R_X86_64_RELATIVE at +0x00, whose addend (0x469219) is the
28-byte string "failed to write whole buffer"; the +0x08
qword is its length. This is not a panic Location (its &str
is a sentence, not a source path, and its second tail dword
is 0), and it is not a vtable entry (no drop/size/align/
method fields, no code pointer).

The shape is the one std's io error machinery uses for a
statically allocated error message ({message &str, kind,
zero}). The kind dword is calibrated inside this binary: a
census of every .data.rel.ro static of this exact shape whose
string is a sentence (length ≥ 10, contains a space, no '/')
finds twelve distinct messages, each mapping to exactly one
dword, and the values line up with the std ErrorKind
declaration order — 20 for the six InvalidInput messages
("invalid argument", "invalid stack size", "could not
resolve to any addresses", …), 21 for the two InvalidData
messages ("invalid timestamp", "stream did not contain
valid UTF-8"), 23 for both write messages ("failed to write
whole buffer", "failed to write the buffered data"), 37 for
"failed to fill whole buffer", 38 for "failed to allocate
read buffer". So dword 23 is ErrorKind::WriteZero here.

Its only referencer is a 277-byte buffered-write body
(0x1533d60..0x1533e75, itself reached only through the
pointer cell 0x64e0010 — no direct callers). The body writes
through the libc `write` function pointer (GLOB_DAT slot
0x64dffc0), retries on EINTR (errno from `__errno_location`,
slot 0x64dffc8; the temporary error is disposed of by the
error-drop body 0x15be1a0, called at 0x1533e37), uses memcpy
(slot 0x64df508) when the data fits its buffer, and returns a
single pointer-sized result in rax:

- 0 (xor at 0x1533e41) on success;
- (errno << 32) | 2 (built at 0x1533e17 / 0x1533e1b) for an
  OS error;
- **the address of this cell** (lea at 0x1533e56) when
  `write` returns 0.

The body never dereferences the cell — the address itself is
the error value, and its low bits (0) are the tag the
error-drop body 0x15be1a0 (209 bytes; it reads the tag with
`and ecx, 3` at 0x15be1ad and returns at once for tags 0 and
2) treats as the nothing-to-free static-message variant.
Copies of this same message static exist all over the binary
(one per monomorphised write-all-style instantiation); this
is the copy the 0x1533d60 body returns.

## 2. Cell 0x64004a0 — a panic Location: std/src/io/mod.rs:1881:36

The cell decodes exactly as a `core::panic::Location`
static: {file ptr at +0x00 (RELATIVE → 0x43870c), file
length 73 at +0x08, line 1881 at +0x10, column 36 at +0x14},
naming `/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/
library/std/src/io/mod.rs` — the same rustc the lifecycle.rs
Locations of PR #3000 name.

The same write body lea's it at 0x1533e5f into rcx, the
fourth argument of a call through GOT slot 0x64df570 to a
200-byte slice range-check helper (0x16817e0). The call sits
on the guard path where the byte count returned by `write`
exceeds the remaining buffer length (the `jb` at 0x1533e01):
the helper checks start ≤ length (`cmp rdi, rdx` at
0x16817e8) and panics with the format pieces "range start
index .. out of range for slice of length .." (pieces at
0x447d95), the offending indices, and this Location — the
`&buf[n..]` advance inside std's write-all implementation.

## 3. Cell 0x64004b8 — a panic Location: std/src/thread/functions.rs:131:29

The same Location layout: file length 83, line 131, column
29, naming `…/library/std/src/thread/functions.rs` (file
pointer 0x440e73). Its referencer is a 430-byte body
(0x15d5b00..0x15d5cae, itself reached only through the
pointer cell 0x6401300) that invokes the entry-3 spawn
sibling 0x15b7a80 directly (call at 0x15d5b51) and supervises
the result. When the spawn result's first word is null it
falls to the block at 0x15d5c37, which loads:

- rdi / esi — the 22-byte message "failed to spawn thread"
  at 0x46925d;
- rdx — a pointer to the failed spawn result (the error
  value);
- rcx — the error value's own one-method vtable at
  0x64005f0 ({drop = 0x15be1a0, the error-drop body of
  section 1; size 8; align 8; method = 0x5ca5610}) — a
  different static, past the table, recorded here as context;
- r8 — **this cell**, as the panic call's Location argument;

and calls through GOT slot 0x64df6a0, which resolves to the
panic-message thunk 0x1680c30 — the body PR #3000 pinned as
panic_msg_thunk. Its sha256 re-derived here
(2d00fd36…67a) is identical to PR #3000's record, and the
objdump export in this packet is byte-identical to PR
#3000's file for that body. A `ud2` follows the call
(0x15d5c5e).

## 4. Family verdict and census completeness

The dispatcher table's entries are 0x20-byte records
{drop_in_place, size, align = 8, method} whose pointer cells
name code bodies; each base is lea'd exactly once, by one of
the four spawn siblings, to form a trait-object fat pointer.
The three cells before the table share none of that:

- size 0x18, not 0x20 — the run 0x6400488 / 0x64004a0 /
  0x64004b8 ends exactly where the table begins (0x64004d0)
  because the linker packed unrelated 0x18-byte statics in
  front of it (the cells just before them, at 0x6400440 /
  0x6400458 / 0x6400470, are h2-crate Location statics);
- no code pointer anywhere in them: their single RELATIVE
  relocation each names a .rodata string;
- referenced by a buffered-write body and a spawn-supervising
  body — not by any spawn sibling — and consumed
  incompatibly with vtable use: two are passed by address as
  &Location arguments to panic machinery (the same kind as
  the lifecycle.rs Locations at 0x6400550 / 0x6400568 that
  PR #3000 pinned immediately *after* the table), and one is
  never dereferenced at all, only returned by address as an
  error value.

Completeness of the reference census (all re-derived):

- .text-wide rip-relative census (REX and no-REX forms, wide
  opcode set) into 0x6400488..0x64004d0: exactly the three
  lea sites above, no load / store / cmp / test / branch use;
  the same census over PR #3000's window
  0x6400480..0x6400578 reproduces its nine references exactly;
- no movabs immediate anywhere in .text names a cell;
- no relocation addend anywhere names any of the three cells
  (the only references to them in the relocation table are
  the three RELATIVE entries that write their own +0x00
  string pointers), and no raw qword in any allocated data
  section holds a cell address;
- exactly three relocations land in the three cells, one per
  cell, all at +0x00; none lands in any tail field;
- all three cells lie inside PT_GNU_RELRO
  (0x63f2ba0..0x64ef000), hence read-only after relocation —
  consistent with there being no store reference.

No pin in PR #3000 or PR #2999 is contradicted: the one body
this packet shares with PR #3000 (panic_msg_thunk) hashes
identically, the relocation totals (61,001; 59,534 RELATIVE)
and the nine-reference window census match PR #3000's
records exactly, and no body pinned by PR #2999 is touched.

## Boundaries

- The two referencing bodies are described behaviourally; no
  source-level type name for either is pinned. Which std
  routine the write body monomorphises is not established.
- The name WriteZero for kind dword 23 rests on the in-binary
  message-to-discriminant calibration above plus the std
  declaration order, not on any symbol in the artifact.
- The error-value vtable at 0x64005f0 is recorded as context
  for the spawn supervisor's panic call; auditing it is not
  part of this question.
- Out of scope, as in PR #3000: the 0x3d0/0x2c40 argument
  layouts, the sv[1] writer (PR #2952), the wrapper-B
  registration cell (PR #2972), and the kind-1 Once cache
  (PR #2999).

## Files

- `records.json` — bodies (FDE extents + sha256), byte pins,
  slot resolutions, the three cell decodes, the
  message-static calibration census, the error-value vtable
  record, the reference censuses, and the cross-checks
  against PR #3000, all re-derived by the tool.
- `frames.txt` — the readelf -wf lines for the five bodies.
- `*.objdump.txt` — intel-syntax disassembly of each body,
  with every pinned site present as an instruction start.
- `MANIFEST.sha256` — digests of the packet files.
