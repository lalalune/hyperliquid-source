# RE-001: map node #115 arena aligned allocation (0x605d7b0) with its slow path (0x605d6c0)

Task: RE-001 (#115 function map). Bounded question: how does the
arena object hand out an aligned block — when does it try a fresh
huge-page-style block first, when does it bump-allocate from its
cursor, and what does the slow installer do when the cursor runs out?

- Component: node #115 arena aligned allocation, two whole functions
  plus the exception-cleanup stub they share, extracted from the
  digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  main window `0x605d7b0..0x605d926` (374 bytes; FDE .eh_frame
  offset 0x75a194, length 0x50, CIE 0x730230, LSDA augmentation
  `f3 dd 01 ff` — the call-site table is not decoded in this packet),
  slow window `0x605d6c0..0x605d785` (197 bytes; FDE .eh_frame
  offset 0x367694, length 0x5c, CIE 0, no LSDA), cleanup stub
  `0x605d786..0x605d7ab` (37 bytes; FDE .eh_frame offset 0x75a1e8,
  length 0x1c, CIE 0x730230, LSDA augmentation `ae dd 01 ff` — its
  call-site table is likewise not decoded).
- Claim status: observation for the window bounds, the gate and
  rounding arithmetic, the bump update, the slow install arms, the
  report strings, the caller census and the vtable slot; inference
  for the names "arena", "gate", "block hint" and "cursor" (they
  describe the observed roles, not proven source names — except that
  the report strings themselves name the file `memory/arena.cc` and
  the function `AllocateAligned`); unresolved for the items listed
  in records.json (the callees' internals, the +0x810 hint's exact
  role, the consume-clear end field, the four non-virtual callers'
  purposes, the 0x605d930 neighbour's role, the LSDA tables).
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them
  (including `endbr64` at both window entries) are genuine
  instructions present in the target binary, not placeholders; the
  packet checker re-verifies sampled instructions byte-for-byte
  against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers these windows
  (checked this cycle: open-PR snapshot of 108 open PRs plus a
  repository search for 605d7b0 and 605d6c0, no hit). The main
  window is the fourth virtual (slot 0x64d1fd0) of the member class
  whose destroy 0x605cc30 was mapped by the destructor-pair packet
  (its vtable 0x64d1fb8 holds 0x605cc30, 0x605cf80, 0x605d930,
  0x605d7b0, 0x605cc20), and its two destructor-pair-class virtual
  callers 0x5f117a0 and 0x5f11c40 call both this window and the
  slow window. The 0x605d930 neighbour virtual is cited only as a
  tail-jump caller of the slow window; its own behaviour is not
  modelled here.

- The main window, stated literally. Arguments: rdi = arena object,
  rsi = size, rdx = quantum (the rounding unit), rcx = logger (used
  only by the report call). If the gate field at object + 0x8d8 is
  zero, or the quantum is zero, or the size is zero, the window
  takes the fast path directly. Otherwise it rounds the size up:
  rounded = ((size - 1) // quantum + 1) * quantum, computed with a
  64-bit division by the quantum, and calls the grow callee
  0x605d000 with (object, rounded). A nonzero grow result is
  returned at once: the cursor and remaining fields are untouched.
  A zero grow result builds a temporary error string from errno
  (via __errno_location and 0x61d1f30), reports it once via
  0x5fceda0 with level 2, the logger, format
  "[%s:119] AllocateAligned fail to allocate huge TLB pages: %s"
  and file "memory/arena.cc", frees the heap temporary afterwards
  with sized operator delete of size (field at + 0x10) + 1 unless
  the data pointer equals the object's own + 0x10 buffer (the
  small-string case, where nothing is freed), and then runs the
  fast path. The fast path aligns the cursor at + 0x8c8 up to 16
  bytes (pad = (16 - (cursor & 0xf)) % 16), needs size + pad bytes
  of the remaining field at + 0x8d0, tail-jumps to the slow window
  with consume flag 1 when the remaining space is short, and
  otherwise returns cursor + pad while storing cursor + size + pad
  and remaining - (size + pad). The landing pad at 0x605d91a
  disposes the temporary string through the stub at 0x605d786
  (basic_string::_M_dispose on the string at rsp, then
  _Unwind_Resume) when unwinding through the error-report region.

- The slow window, stated literally. Arguments: rdi = arena object,
  rsi = size, rdx = consume flag (low byte only). If size exceeds
  (block hint at + 0x810) >> 2, the big-path counter at + 0x8b8 is
  incremented by 1 and the window tail-jumps to the block callee
  0x605d3c0 with (object, size); that call's return is the result
  and no cursor field is installed. Otherwise, when the gate field
  at + 0x8d8 is nonzero, the window calls the grow callee 0x605d000
  with (object, gate); a nonzero grow result installs with hint =
  gate, while a zero grow result reloads the block hint and falls
  through to the block callee with (object, block hint). When the
  gate is zero the window calls the block callee directly with
  (object, block hint). Installation sets remaining (+ 0x8d0) to
  hint - size; with consume set, cursor (+ 0x8c8) becomes block
  start + size and end (+ 0x8c0) becomes block start + hint; with
  consume clear, cursor becomes block start and end becomes block
  start + remaining. Both install arms return the block start. The
  consume-clear end value (block start + remaining, not block start
  + hint) is recorded literally; its interpretation is left open
  because no modelled caller reads + 0x8c0.

- The census, stated literally. Main window direct callers (each
  confirmed as a real e8 call in objdump output disassembled from
  its containing FDE start): 0x5f11f0e (inside the
  destructor-pair-class virtual 0x5f11c40), 0x5f11864, 0x5f11a55
  and 0x5f11b63 (inside the virtual 0x5f117a0), plus 0x5dcd2f9,
  0x5f9a0d4, 0x605c97b and 0x612c72e (four further functions whose
  internals were not read). No tail jump targets the main window.
  Its one whole-file qword hit (file offset 0x11a778) is the
  addend field of the RELATIVE entry for its vtable slot 0x64d1fd0
  (entry at file offset 0x11a768), not a separate reference. Slow
  window direct callers: 0x5f11e39 and 0x5f120c6 (both inside
  0x5f11c40); tail jumps: 0x605d88d (the main window's slow path)
  and 0x605d962 (inside the neighbouring member virtual 0x605d930,
  which tail-jumps to the slow window at its end). The slow window
  has no RELATIVE slot and no qword hit.
