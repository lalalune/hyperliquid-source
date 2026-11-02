# RE-001: map node #94 WAL reader destructor 0x5162ed0

- Component ID: RE-001 (#94 function map), WAL log reader teardown
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json; local copy `work/hl-node-94.bin`, hash verified to match)
- Source commit / reference commit: upstream main `e5c9b643` at submission time
- Claim status: observation for every field release, call and branch
  condition below; inference for the shared-count reading of the
  refcount protocol (the (weak << 32 | strong) packing and the
  last-strong/no-weak meaning of the 0x100000001 sentinel), flagged as
  inference in records.json, with the branch conditions pinned exactly
  regardless. The object types behind the +0x78, +0xa8, +0xb0 and +0x18
  pointers are not pinned.
- Scope included and excluded: the whole 1503-byte complete destructor
  0x5162ed0..0x51632af (including its cold arms), its 27-byte deleting
  destructor 0x51632b0..0x51632cb, the 35-byte prefix-free helper
  0x543be20 it uses for the +0xa8/+0xb0 fields, the known-type
  destructor 0x5160ec0 it inlines for the +0x78 object, the vtable
  entries from the relocations, and the full direct-caller census
  (19 direct calls, 1 tail jump, vtable slots). Excluded,
  callee-only: the internals of 0x55d9080 (destroys the +0x78
  object's +0x18 field), of the release function 0x4f94a40, and of
  0x50badf0 (used by the constructor's cleanup stub, PR #1865);
  their call contracts are pinned, their bodies are not re-mapped
  here. The constructor (PR #1865), logical reader (PR #1860) and
  physical-record decode (PR #1848) are cross-checked, not re-pinned.

## Bounded question

How does node #94 tear down the WAL reader object that the constructor
(PR #1865) builds and the logical reader (PR #1860) and physical-record
decode (PR #1848) operate on: in what order are its owned fields
released, which releases are conditional on null, how does the
shared-count release protocol decide between a plain decrement, a
lock-add decrement, an inline dispose-and-destroy, and a release call,
and who calls the destructor directly?

## Reproduce

From the repository root, with the digest-verified binary at
`work/hl-node-94.bin`:

```
objdump -d --start-address=0x5162ed0 --stop-address=0x51632af work/hl-node-94.bin
python3 research/work-items/RE-001-wal-reader-dtor-94/export_excerpts.py
python3 research/work-items/RE-001-wal-reader-dtor-94/verify.py
python3 -m unittest tests.test_wal_reader_dtor -v
```

Note: `endbr64` and the other instruction mnemonics in the excerpt files
are genuine instructions present in the target binary, not placeholders.
Instruction-level detail lives only in those verbatim excerpts; the JSON
in this packet holds semantic records, never a per-instruction list.
The objdump header spells the binary path exactly as given, so the
excerpts must be regenerated from the repository root with the relative
path, as `export_excerpts.py` does.

## Evidence

Window: FDE `0x00635420 pc=0000000005162ed0..0x51632af`, 1503 bytes,
no canary (pushes r15/r14/r13/r12/rbp/rbx, 8-byte stack adjustment).
Argument: the reader object in rdi. The deleting destructor is a
separate FDE `0x51632b0..0x51632cb`: it calls this destructor, then
operator delete with size 0xb8 (184 bytes), so the reader object is
184 bytes.

Teardown, in exact order:

1. The vtable pointer 0x575b0b8 is stored at +0x00 (the same value the
   constructor installs).
2. The +0x30 buffer (the 0x8000-byte operator new[] buffer from
   construction) is freed with operator delete[] when nonzero.
3. The +0x78 object pointer: when nonzero, its vtable slot 1 is
   compared against the qword at 0x5778380, which the loader installs
   as 0x5160ec0 per its R_X86_64_RELATIVE relocation. When they differ,
   the object's own vtable slot 1 (its deleting destructor) is called
   on it. When they are equal (the known 0x38-byte type), the window
   inlines that type's destructor: it installs vtable 0x5766048, calls
   0x55d9080 on the object's +0x18 field, then operator delete with
   size 0x38. The known type's own deleting destructor 0x5160ec0
   (FDE 0x5160ec0..0x5160eed, excerpted in known-type-dtor.txt) is
   byte-for-byte that same sequence, and its complete destructor
   0x5160ef0 is the install-plus-call without the delete.
4. The +0xa8 field, when nonzero, is released through helper 0x543be20
   (FDE 0x543be20..0x543be43, 35 bytes, excerpted in helper.txt):
   null returns 0, otherwise free(pointer minus the byte stored at
   pointer - 1) through free@plt.
5. The +0xb0 field, same helper, same rule.
6. The +0x88 string (pointer +0x88, inline buffer +0x98): when the
   pointer differs from the +0x98 buffer address, operator delete is
   called with the pointer and size (capacity at +0x98) + 1.
7. The +0x80 heap array pointer is freed with operator delete[] when
   nonzero.
8. The +0x18 taken object, when nonzero, is destroyed in full
   (168 bytes, operator delete size 0xa8): first every element of its
   +0x88/+0x90 vector (stride 0x10, element +0x08 a control pointer;
   null elements skipped) goes through the refcount protocol below;
   then the array buffer is freed with operator delete, size
   (+0x98 field) minus (+0x88 field); then vtable 0x575f6a0 is
   installed at its +0x30; then its +0x60 string is freed when its
   pointer differs from its +0x70 inline buffer (size capacity + 1);
   then its +0x50 field goes through the refcount protocol; then
   vtable 0x5759bc0 is installed at its +0x30; then its +0x40 object
   is deleted through its vtable slot 1 when nonzero; then its +0x28
   field goes through the refcount protocol; then its +0x00 string is
   freed when its pointer differs from its +0x10 inline buffer (size
   capacity + 1); then the sub-object itself is freed with size 0xa8.
   The two vtable resets bracket the two base-class phases
   (their slot 0 values are 0x5276300 and 0x50b6dd0 per their
   RELATIVE relocations).
9. The +0x10 refcounted source goes through the refcount protocol;
   null returns normally. Its sentinel path disposes and then
   tail-jumps through the control's vtable slot 0x18, and its
   old-strong-1 path tail-jumps to the release function 0x4f94a40
   (both with the frame already popped, so the release returns
   directly to the destructor's caller).

Refcount protocol (one control pointer P; the count word is at P+0x08):

- The global byte at 0x5777ed8 selects the decrement form: nonzero
  selects a plain 32-bit decrement of the strong count, zero selects a
  lock xadd with -1. Both forms touch only the low 32 bits.
- When the whole 64-bit word equals 0x100000001, the word is zeroed
  and the control's vtable slot 0x10 (dispose) is called, then its
  vtable slot 0x18 (destroy); the release function is not called.
  Under the inferred shared-count reading this is the last strong
  reference with no outstanding weak references.
- Otherwise, when the old strong count is 1, the release function
  0x4f94a40 is called (it disposes through vtable slot 0x10 and then
  handles the weak count); when the old strong count is above 1, the
  decrement stands and nothing is called.

Vtable (from the R_X86_64_RELATIVE relocations; the file bytes at
these .data.rel.ro slots read zero in this capture, so the relocation
addends are the installed values): slot 0x575b0b8 is this destructor,
slot 0x575b0c0 is the deleting destructor, slot 0x575b0c8 is the
logical reader (PR #1860), slot 0x575b0e8 is 0x50db890 — a derived
destructor that installs 0x575b0e8, frees its own +0xb8 string when
heap-allocated, and tail-jumps to this destructor (excerpted in
caller-wrapper.txt).

Callers (census: full executable-segment e8/e9 scan for 0x5162ed0 and
0x51632b0, plus a whole-file qword scan): 19 direct calls and 1 tail
jump to the complete destructor, listed with enclosing functions in
records.json; the deleting destructor has no direct callers (virtual
dispatch through vtable slot 0x575b0c0 only). The whole-file qword
scan's only hits for either address are the two vtable-slot
relocations themselves. The replay loop 0x520ad30..0x520c053 destroys
a reader on its cleanup path (call at 0x520b6de, excerpted in
caller-replay.txt); it is the enclosing function of the constructor
caller 0x520b49e (PR #1865).

Fields the destructor never touches (plain data, no cleanup):
+0x08, +0x20, +0x28, +0x38, +0x40, +0x48, +0x50, +0x58, +0x60, +0x68,
+0x70 — all read by the logical reader or the decode (PRs #1860 and
#1848), none freed here. The object itself is freed only by the
deleting destructor, never by the complete destructor.
