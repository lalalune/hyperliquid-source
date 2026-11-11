# RE-001: pin node #115 arena allocate 0x605d930, the end-carving third virtual of the member arena

Task: RE-001 (#115 function map). Bounded question: what does the
member arena's third virtual do with a size — when does it carve
in place, exactly which fields does it move, what does it return,
and what contract does it hand to the slow window when it cannot?

- Component: node #115 arena allocate, one whole function end to
  end, extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  window `0x605d930..0x605d967` (55 bytes; FDE .eh_frame offset
  0x3676f4, length 0x14, CIE 0 — the FDE carries no augmentation
  data and only DW_CFA_nop instructions, so there is no LSDA and
  no landing pad).
- Claim status: observation for the window bounds, the unsigned
  guard, the two field updates, the returned value, the slow-arm
  tail jump and its forced third argument, and the census;
  inference for the names "end" and "remaining" (they keep the
  arena packet's field names for + 0x8c0 and + 0x8d0 and describe
  the observed roles, not proven source names); unresolved for
  the items listed in records.json (which callers dispatch
  through the slot at runtime, the invariant that keeps this
  window's end carve and the main window's cursor bump disjoint,
  the neighbouring virtuals 0x605cf80 and 0x605cc20, and the
  source-level name beyond the vendor attribution).
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: two merged packets cite this
  window without modelling it. The arena packet
  (RE-001-arena-allocate-aligned-115) lists as an unknown "the
  role of the neighbouring member virtual 0x605d930 beyond its
  tail jump to the slow window"; the destructor-pair packet
  (RE-001-destructor-pair-115) lists the behaviour of the member
  vtable's virtuals (0x605d930, 0x605d7b0) as unresolved. This
  packet pins the window itself; the slow window it tail-jumps
  to (0x605d6c0) stays the arena packet's, cited by contract.
  The RE-002 vendor census attributes this exact window
  (node115-vendor-605d930) to the native build's
  `rocksdb::Arena::Allocate`; that attribution is the census's
  claim, cited here — the behavioural pin below is derived from
  the #115 binary alone. No open PR covers this window (checked
  this cycle: full open-PR snapshot, no 0x605d930 reference in
  any title, body or packet file list). The window is the third
  virtual of the member class whose vtable 0x64d1fb8 holds
  0x605cc30 (member destroy), 0x605cf80, 0x605d930, 0x605d7b0
  (AllocateAligned, the arena packet's main window, counted
  there as the fourth virtual) and 0x605cc20; the member is the
  arena embedded at + 0x60 in the outer object of the two
  allocate packets. The census finds no direct call and no tail
  jump targeting the window, and its single whole-file qword
  hit (file offset 0x11a760) is the addend field of the
  RELATIVE entry for slot 0x64d1fc8, not a separate reference.

- The window, stated literally. Arguments: rdi = arena object,
  rsi = size. The remaining field at this + 0x8d0 is loaded and
  compared against the size as an unsigned 64-bit value. When
  the remaining is at least the size, the window takes the fast
  path; otherwise it takes the slow arm. The third argument
  register is never read on the fast path.

- The fast path, stated literally. The end field at this +
  0x8c0 is loaded; the remaining field is stored back as
  remaining - size and the end field as end - size (plain
  64-bit subtraction, no saturation, no second check), and the
  window returns the post-decrement end field. The returned
  range is therefore [new end, new end + size): the carve
  comes off the end of the current block, the exact complement
  of the main window's upward cursor bump — and the cursor
  field at this + 0x8c8 is neither read nor written here, nor
  is any other memory. Size 0 always takes this path (0 >= 0
  included): both fields are rewritten with their own values
  and the end field is returned. Because the guard is the only
  check, an inconsistent state (end smaller than the size
  while remaining covers it) wraps the end field in 64-bit
  arithmetic, literally.

- The slow arm, stated literally. At 0x605d960 the window
  zeroes rdx and tail-jumps to the slow window 0x605d6c0 with
  rdi and rsi unchanged, so the call contract is
  (this, size, 0), the slow window's return value becomes this
  window's return value, and this window writes neither field
  on that path. What the slow window does with the request
  (block install, consume/grow arms, the report path) is the
  arena packet's ground, not re-derived here.
