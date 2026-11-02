# RE-001: map node #94 shard bucket array construction (0x516adf0)

Task: RE-001 (#94 function map). Bounded question: how does node #94
build the sharded bucket array that the #2003 access function reads —
what bucket-count rule, what allocation layout, what install order,
and what release protocol runs when an array is replaced?

- Component: node #94 shard bucket array construction. One window,
  extracted from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x516adf0..0x516afa2` (434 bytes, FDE
  0x1317140, LSDA 0xbd8bd8). This is the construction half of the
  #2003 access half: #2003 pinned the read side (bucket count
  `1 << (host +0xd18)`, slots at `host +0xd10 + index * 16`); this
  packet pins where that array comes from. The window's only direct
  caller is the host constructor (0x51702e8 in 0x516fdc0..0x51706c8),
  which passes `host +0xd10` and reads the shift back at `host +0xd18`.
- Claim status: observation for the window bounds, the count rule,
  the allocation layout and size, the zero-fill, the store order,
  the release protocol, the landing pad and the census; inference
  for the names "shard array" and "host" (the array object is the
  two-field struct at host +0xd10 whose slots the #2003 access
  indexes); unresolved for why the compiler keeps the full release
  sequence after a prologue that nulls the old pointer (see below),
  for the host object's identity, and for absurd
  hardware_concurrency values. The release semantics themselves are
  pinned: the identical sequence is live as standalone helper
  0x5169bac, called from host teardown (0x516fbdf) and from this
  window's landing pad.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at each window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR snapshot, no 0x516adf0 or
  shard-array-construct title; repository search for 516adf0 returns
  nothing). #2003 covers the access side only and does not claim
  construction; the 0x516aa50 teardown variant is cited only as the
  host teardown's next call after the release helper, not re-claimed.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim from
  work/fde94/node-94-fde.tsv.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in
  AGENTS.md is therefore unavailable and this packet is grounded in
  objdump disassembly plus relocation and FDE records only. pytest
  is not installed, so the pytest-style test file runs under plain
  python3 via its `__main__` runner.

## Answer

`construct_shard_array(obj)` — obj is a 16-byte struct: +0 slots
pointer, +8 shift.

### Prologue

The slot field is zeroed first, then `hardware_concurrency` is
called. The shift is stored to obj +0x8 before any allocation, so
on an allocation failure the object holds a shift with a null slots
pointer.

### Bucket-count rule

- concurrency <= 8 (including 0, the "unknown" return): shift 3,
  count 8, allocation 0x88 bytes.
- Otherwise the loop starts at shift 4 and advances while
  `2^shift < concurrency` (signed 32-bit compare on the shifted
  value), so shift is the smallest value >= 4 with
  `2^shift >= concurrency`, and count is `1 << shift`.
- Overflow guard: if `count >> 59` is nonzero, the size argument
  stays -1, so operator new[] fails instead of allocating a
  wrapped size; otherwise the size is `8 + 16 * count`.

### Allocation layout

The allocation base holds the count (8 bytes). The slots begin at
base + 8: `count` 16-byte entries, each a shared_ptr slot (pointer,
then control block pointer), zero-filled by a 16-byte vector store
per slot. The slots pointer (base + 8) is stored to obj +0 only
after the zero-fill.

### Release sequence (present in the window, live via 0x5169bac)

After installing the new slots, the window loads the old slots
pointer and, when nonzero, walks it in reverse: the end pointer is
`old + count * 16`, each step reads the control block at
`slot + 8` and moves down 16 bytes. A null control block skips the
slot. A control block whose +0x8 word is `0x100000001` is zeroed
and its vtable +0x10 then +0x18 virtuals are called with the
control block as argument. Otherwise the +0x8 word is decremented
(plain when the __libc_single_threaded flag at GOT 0x5777ed8 is
nonzero, locked xadd otherwise) and the destroyer 0x4f94a40 is
called when the old low 32-bit value is 1. The sentinel comparison
uses the full packed 64-bit strong/weak count word, but the ordinary
decrement updates only the low strong-count DWORD and preserves the
upper weak-count DWORD (`0x5169c1a..0x5169c2e` in the helper and
`0x516aeb8..0x516aefd` in construction). The model and a regression
test cover this distinction for both single-threaded flag values.
After the walk, the old allocation
is freed with operator delete[] on `old - 8` with size
`count * 16 + 8`.

Prologue nuance, stated plainly: because the prologue zeroes the
slot field before allocation, the post-install release on this
function's own path always observes a null old pointer and is a
no-op. The sequence is documented in full because it is present
in the binary and because the identical sequence is the live
release path as standalone helper 0x5169bac (callers: this
window's landing pad 0x516af95, and host teardown 0x516fbdf,
which null-checks host +0xd10 before calling it). The model
implements construction exactly and implements the release
sequence with the standalone helper's observable behavior.

### Landing pad (0x516af86)

On unwinding, the slot field is loaded; when nonzero it is
released with helper 0x5169bac, then unwinding resumes. This
covers the allocation failure case (field still null, a no-op)
and a destroyer throw during the release sequence (field holds
the new slots).

### Census

One direct call (0x51702e8, host construction), no tail jumps,
no qword references, no RELATIVE slots. The release helper's
callers are 0x516af95 and 0x516fbdf.
