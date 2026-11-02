# RE-001: node #94 BlockCache entry-name table initializer 0x51601c0

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x51601c0 initialize at load, in what order, and how are
its entries built and later torn down — the two 14-entry string
tables, the string-from-C-string routine that fills them, and the
table destructor registered for process exit?

## Bound to

work/hl-node-94.bin SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching provenance/artifacts.json for node #94.

## A note on the excerpts

The packet's disassembly files are verbatim objdump output for
whole functions, exactly as objdump emitted them. Instruction
mnemonics that appear there (for example the `endbr64` at each
window start) are genuine instructions present in the target
binary, not placeholders and not sanitized tokens. The JSON file
in this packet carries semantic records only; instruction-level
detail lives in the raw excerpt text files.

## What the window does

The window (0x51601c0..0x516054e, FDE 0x00634f68, 910 bytes, no
padding — the next FDE 0x516054e starts immediately) is a static
initializer. It has no direct caller: the only reference to its
address is the .init_array RELATIVE relocation at vaddr 0x5662eb0
(slot 44 of .init_array, which starts at 0x5662d50), so the runtime
runs it at load. It takes no arguments and returns void (its tail
is a jump to __cxa_atexit, not a return to a caller).

- Tables. Two tables of 14 std::string records each, stride
  0x20 bytes: pointer at +0x00, length at +0x08, 16 bytes at
  +0x10..+0x20 that hold the inline buffer for short strings or
  the heap capacity for long ones. The first table sits at
  0x578c2e0, the second at 0x578c120. Each table is filled entry
  by entry in order, entry i at base + i * 0x20, by calling the
  routine 0x515f7a0 with the destination record in rdi and a
  .rodata C string in rsi.
- First table (0x578c2e0, PascalCase). This is the name table the
  BlockCache report formatter 0x514f770 reads (own packet PR
  #1677, which took these names as model parameters): DataBlock,
  FilterBlock, FilterMetaBlock, DeprecatedFilterBlock, IndexBlock,
  OtherBlock, WriteBuffer, CompressionDictionaryBuildingBuffer,
  FilterConstruction, BlockBasedTableReader, FileMetadata,
  BlobValue, BlobCache, Misc.
- Second table (0x578c120, kebab-case). The same 14 entries in the
  same order, spelled kebab-case: data-block, filter-block,
  filter-meta-block, deprecated-filter-block, index-block,
  other-block, write-buffer,
  compression-dictionary-building-buffer, filter-construction,
  block-based-table-reader, file-metadata, blob-value, blob-cache,
  misc.
- Destructor registration. After the first table's 14 assignments,
  the window calls __cxa_atexit (0x51602e3) with the destructor
  0x515f870, the first table's base, and __dso_handle 0x577a660.
  After the second table's 14 assignments, it tail-jumps to
  __cxa_atexit (0x51603f9) with the same destructor, the second
  table's base, and the same handle. Registration order is
  therefore first table, then second table.
- Landing stubs. The tail of the window's FDE range
  (0x51603fe..0x516054e) holds endbr64 stubs that jump into the
  0x516007c cleanup region; which stub serves which assignment
  call site is not claimed (LSDA mapping not claimed).

## The string-from-C-string routine 0x515f7a0

FDE 0x0029b1ec, 0x515f7a0..0x515f870 (208 bytes, 0 int3 padding
to the next FDE). Arguments: destination string in rdi, source
C string in rsi. It first stores the destination's own +0x10
address into the pointer field, then:

- Null source: the canary-checked path throws logic_error via
  the message at 0x7e0c18, "basic_string: construction from null
  is not valid" (call at 0x515f86b). The destination is left
  unchanged apart from the pointer field write.
- Length: strlen of the source (call at 0x515f7d3), saved on the
  stack.
- Length 1: the single byte is copied directly into the inline
  buffer at destination +0x10 (0x515f7eb), with no memcpy call.
- Length 0: no copy at all; the length field is stored as 0 and
  the NUL terminator is written at the pointer (the inline
  buffer).
- Lengths 2..15: memcpy (call at 0x515f848) into the inline
  buffer at destination +0x10, which stays the pointer.
- Lengths above 15: _M_create (call at 0x515f82c) allocates a
  heap buffer, the heap pointer replaces the pointer field, and
  memcpy fills it. The exact heap capacity _M_create allocates is
  not pinned here; the model records only that the pointer is a
  heap buffer, the length is the source length, and a NUL sits at
  pointer + length.
- Epilogue: the length is stored at destination +0x08, a NUL byte
  is written at pointer + length, the canary (fs:0x28, saved at
  rsp+0x08) is checked, and the routine returns.

## The table destructor 0x515f870

FDE 0x0029b228, 0x515f870..0x515f8c5 (85 bytes, 11 int3 padding to
the next FDE 0x515f8d0). Argument: a table base in rdi. It walks
backwards from entry 13 (base + 0x1a0) down to entry 0, stepping
-0x20. For each entry it compares the pointer field with the
entry's own +0x10 address: when they differ, the buffer is a heap
buffer and operator delete[] is called with (pointer, length + 1)
(call at 0x515f898); when they are equal, the entry is inline
and nothing is freed. Inline entries are therefore left alone,
and heap entries are freed in reverse order.

## Caller census

Method: full .text e8/e9 scan plus a whole-file qword scan, plus
the .rela.dyn RELATIVE relocation for the initializer's address.

- Initializer 0x51601c0: no direct e8 caller, no e9 tail jump,
  no absolute qword reference in the file image. Its reaching
  path is the .init_array slot at 0x5662eb0 (index 44), via the
  RELATIVE relocation to 0x51601c0.
- Assign routine 0x515f7a0: called 28 times from the initializer
  (once per entry of each table); no other direct caller was
  found in the .text scan for this packet's census scope, and
  the routine is cited here as the initializer's callee, not as
  a standalone item.
- Destructor 0x515f870: passed as the function argument to both
  __cxa_atexit registrations above; no direct call site.

## Unknowns

- Which consumers read the second (kebab-case) table; only the
  first table's consumer (the 0x514f770 formatter) is pinned.
- The exact heap capacity _M_create allocates for long names
  (only the heap/inline distinction and the length are pinned).
- Which landing stub in 0x51603fe..0x516054e serves which
  assignment call site (LSDA mapping not claimed).
- The 16 unused bytes at record +0x10..+0x20 for inline entries
  beyond the buffer contents (the buffer itself is 16 bytes, so
  a 15-byte name plus its NUL exactly fills it; no further claim).
