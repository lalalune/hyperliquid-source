# RE-001: map node #94 WAL writer close 0x5163e20 with its status handoff, shared-release protocol and member teardown

Task: RE-001 (#94 function map). Bounded question: how does the node #94
WAL writer close routine release a writer handle — what status does it hand
back, in what order does it release the writer's members, and which members
does it free outright?

- Component: node #94 WAL writer close, window `0x5163e20..0x51641d0`
  (944 bytes, FDE 0x1316bf4, LSDA 0xbd8a11), plus the exception landing pad
  at `0x51641c4` (which jumps to the shared cleanup stub at `0x5163dec`,
  owned by the neighbouring setup window) and the two direct call sites.
  The status helper `0x52b2550` (6784 bytes, FDE 0x132b218), the
  destroyer `0x4f94a40` (76 bytes, FDE 0xf6b400), the `+0xc8` member's
  second virtual, the `+0x30` member's second virtual and the `+0x30`
  member's `+0x30` sub-member virtual are used by contract only; their
  internals are not pinned here.
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the window bounds, the close order, the
  status field offsets and widths, the shared-release branches, the
  member dispatch value and both vtable resets, the string free rules
  and the delete sizes 0x70 and 0xe0, and the census; inference for the
  writer attribution (see below) and for the string shape (std::string
  layout inferred from the pointer/capacity-plus-one free pattern);
  unresolved for the helper internals and the reason it is called twice,
  the destroyer internals, the classes behind the `+0xc8` and `+0x30`
  members, the setters of the object fields outside this window, and
  bytes 6-7 of the status record (never written here).
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: PR #1958 mapped the writer direction of
  the fragment grammar (AddRecord `0x5163730`, emitter `0x5163550`,
  setup `0x5163ba0`) and its 16-byte result record. This window is the
  matching close side: it sits immediately after the setup window, it
  consumes and produces the same 16-byte record shape, and it nulls the
  handle after teardown. The writer's own fields from #1958 (+0x44 flag,
  +0x45 compression type) are not touched here, so the writer
  attribution rests on adjacency plus record shape, and is marked as
  inference in records.json. No open WalkCrypto PR covers this window
  (checked this cycle).

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; `objdump --dwarf=frames` is not used
  for frames.txt (rows are verbatim from work/fde94/node-94-fde.tsv).
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in AGENTS.md
  is therefore unavailable and this packet is grounded in objdump
  disassembly plus relocation and FDE records only. pytest is not
  installed, so the pytest-style test file runs under plain python3
  via its `__main__` runner.

## Answer

`close(out_status, handle)` returns the out status pointer. The status
record is 16 bytes: u16 at +0, u8 at +2 (always 0 on return — zeroed by
the entry init and never overwritten by the copy), u16 at +3, u8 at +5,
two padding bytes at +6 (never written here), and a message pointer at
+8. Caller `0x503ccce` corroborates the layout: after the call it
move-assigns exactly u16 at +0, u16 at +3, byte at +5 and pointer at +8
into its own record.

Close order, exactly as observed:

1. Zero the out record (u32 +0, u16 +4, qword +8). A null handle slot
   returns this zeroed record with no teardown.
2. Call the status helper `0x52b2550` with (stack temp, object) and
   move-assign the temp into the out record (fields +0, +3, +5, +8).
   The two delete[] calls emitted after this move free null pointers
   only — the out pointer was just zeroed by step 1 and the temp slot
   was just cleared by the move — so they have no observable effect.
   (An earlier reading of this packet misdescribed them as freeing the
   old message; the re-read against the init sequence corrects that.)
3. Take ownership: object = handle slot, handle slot = 0. A second
   null check on the taken object exists but cannot fire from step 1
   without mutation.
4. Call the helper a second time on the same object; the returned
   message pointer is freed if non-null and the rest of the second
   result is discarded. Why the helper runs twice is unresolved — the
   first result is kept, the second is dropped — but the asymmetry is
   real: the first message survives in the out record, the second is
   freed.
5. If the `+0xc8` member is non-null, call its second virtual
   (vtable +0x8); the result is ignored.
6. Walk the vector at `+0xb0` (begin) .. `+0xb8` (end), stride 0x10,
   and run the shared-release protocol on each element's `+0x8`
   pointer. Elements are not deleted individually here.
7. Free the vector backing array with sized delete (size = `+0xc0`
   end minus `+0xb0` begin) when `+0xb0` is non-null; free the `+0x48`
   array with delete[] when non-null.
8. Tear down the `+0x30` member (below).
9. Run the shared-release protocol on the `+0x28` member.
10. Free the outer string at +0 (pointer +0, capacity-or-inline-buffer
    +0x10): skipped when the pointer equals the address of the `+0x10`
    slot (inline/empty form), else sized delete with size = value at
    `+0x10` plus 1.
11. Sized delete of the object itself, 0xe0 bytes.

Shared-release protocol (one shared object: vtable pointer at +0, count
word at +8; used for every vector element `+0x8`, the `+0x30` member's
`+0x40`, and the outer `+0x28`):

- Null pointer: no-op.
- Count word exactly `0x100000001`: the count word is zeroed, then
  virtual +0x10 (dispose) and virtual +0x18 (destroy) are called on the
  object, in that order; no decrement happens.
- Otherwise the low 32 bits are decremented by 1 (modulo 2^32). When
  `__libc_single_threaded` (GLOB_DAT slot `0x5777ed8`) is nonzero the
  decrement is a plain 32-bit load/decrement/store; when it is zero
  the decrement is a 32-bit lock xadd. When the old low 32 bits equal
  1, the 76-byte routine `0x4f94a40` is called on the object after the
  decrement.

`+0x30` member teardown (a 0x70-byte polymorphic object):

- If the member is null, skip to step 9.
- Its second virtual function (vtable +0x8) is compared against the
  relocated qword at `0x5777bd0` (value `0x505d960`). On mismatch the
  second virtual is called on the member and the inline teardown below
  is skipped entirely.
- On match, the inline teardown runs: the member vtable pointer is set
  to `0x575f768` (first virtual at that slot relocates to `0x505d8f0`);
  the member string at `+0x50` (pointer `+0x50`,
  capacity-or-inline-buffer `+0x60`) is freed under the same rule as
  step 10 (skip when the pointer equals the address of the `+0x60`
  slot, else sized delete with size = value at `+0x60` plus 1); the
  member's `+0x40` shared pointer is released by the protocol above;
  the member vtable pointer is set a second time, to `0x5759318`
  (first virtual at that slot relocates to `0x5056c90`); if the
  member's `+0x30` pointer is non-null, its second virtual is called;
  then the member is freed with sized delete, 0x70 bytes. The two
  successive vtable resets are recorded as observed; whether they are
  nested destructor stages is not pinned.

Callers (census only, not modelled): exactly two direct call sites,
`0x503ccce` in `0x503ca50..0x503d043` (a guarded single close whose
caller then move-assigns the out record, corroborating the layout)
and `0x50b4ac7` in `0x50b4230..0x50b68fe` (a close inside a loop over
an array of handles). No tail jumps, no qword references to the
window address anywhere in the file.
