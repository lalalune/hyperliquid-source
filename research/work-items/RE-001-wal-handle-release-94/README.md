# RE-001: map node #94 WAL handle release 0x51641d0 with its finalize-status helper, outer member teardown and inner close

Task: RE-001 (#94 function map). Bounded question: how does the node #94
release routine at `0x51641d0` tear down a WAL handle — what does it
finalize first, which of the handle's own members does it free, and how
does it close the inner object the handle points to?

- Component: node #94 WAL handle release, window `0x51641d0..0x516458d`
  (957 bytes, FDE 0x1316c68, LSDA 0xbd8a22), plus the finalize-status
  helper `0x5163460` (173 bytes, FDE 0x1316a48) and two direct call
  sites. The status helper `0x52b2550` (6784 bytes, FDE 0x132b218),
  the completion step `0x52b13f0` (2908 bytes, FDE 0x132b0d4), the
  destroyer `0x4f94a40` (76 bytes, FDE 0xf6b400) and the member
  teardown helper `0x5566950` (339 bytes) are used by contract only;
  their internals are not pinned here.
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the window bounds, the release order,
  the finalize helper's flag branch and error record, the member
  dispatch values and both vtable resets, the shared-release protocol
  (all three application points), the vector bounds and sized-delete
  sizes, the string free rules, the delete sizes 0x70 and 0xe0, and
  the census; inference for the WAL attribution (see below) and for
  the string shape (std::string layout inferred from the
  pointer/capacity-plus-one free pattern); unresolved for the helper
  internals, the reason both status results are discarded, the class
  names behind the handle, the inner object and any member, and the
  setter of the inner `+0x89` flag.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: PR #1964 mapped the writer close
  `0x5163e20`, whose steps 5-13 are the inner-object teardown
  repeated here (status helper, `+0xc8` virtual, vector walk, vector
  free, `+0x48` free, `+0x30` member teardown, `+0x28` release,
  string free, sized delete 0xe0). This window is the wrapper layer
  above it: it first finalizes through helper `0x5163460`, frees the
  handle's own `+0x48` member and `+0x50` array, and only then runs
  that close on the inner object. The new, non-duplicate content is
  the wrapper layer and the finalize helper; the inner teardown is
  re-verified in this window, not copied on trust, and the shared
  protocol is stated once in records.json and cited from #1964.
  PR #1958 mapped the writer direction (AddRecord `0x5163730`,
  emitter `0x5163550`, setup `0x5163ba0`); the finalize helper's
  completion-step call is the same `0x52b13f0` step that setup uses.
  No open WalkCrypto PR covers this window (checked this cycle).

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

`release(handle)` returns void. The handle is a 0x58-byte struct
(the callers free the shell themselves with size 0x58 after the call,
see below): a pointer to the inner object at `+0x00`, a polymorphic
member at `+0x48`, and a heap array at `+0x50`. The inner object is
0xe0 bytes: a string at `+0x00`, a shared member at `+0x28`, a
polymorphic member at `+0x30`, a heap array at `+0x48`, a vector at
`+0xb0` (begin `+0xb0`, end `+0xb8`, capacity end `+0xc0`), and a
pointer member at `+0xc8`. The stack status record is 16 bytes at
`rsp+0x00` (code u32 `+0`, sub u16 `+4`, message pointer `+8`); the
frame canary sits at `rsp+0x18` and is checked on both exits.

Release order, exactly as observed:

1. If `*handle` is non-null, call the finalize helper `0x5163460`
   with (stack status record, handle) and free the record message
   pointer if non-null. The code/sub fields are discarded.
2. Release the handle's `+0x48` polymorphic member (below). This step
   runs even when `*handle` is null.
3. Free the handle's `+0x50` array with operator delete[] when
   non-null. This step also runs even when `*handle` is null.
4. `inner = *handle`; if null, return through the canary-checked
   epilogue. The handle shell is not freed here.
5. Call the status helper `0x52b2550` with (stack status record,
   inner) and free the record message pointer if non-null. The rest
   of the result is discarded.
6. If `inner+0xc8` is non-null, call its second virtual (vtable
   `+0x8`); the result is ignored.
7. Walk the vector at `inner+0xb0` (begin) .. `inner+0xb8` (end),
   stride 0x10, and run the shared-release protocol on each element's
   `+0x8` pointer. Elements are not deleted individually here.
8. Free the vector backing array with sized delete (size =
   `inner+0xc0` minus `inner+0xb0`) when `inner+0xb0` is non-null.
9. Free `inner+0x48` with operator delete[] when non-null.
10. Tear down the `inner+0x30` member (below).
11. Run the shared-release protocol on `inner+0x28`.
12. Free the inner string at `+0` (pointer `+0`,
    capacity-or-inline-buffer `+0x10`): skipped when the pointer
    equals the address of the `+0x10` slot (inline/empty form), else
    sized delete with size = value at `+0x10` plus 1.
13. Sized delete of the inner object itself, 0xe0 bytes.

Finalize helper `0x5163460` (args: out status record, handle):

- It dereferences the handle to the inner object and reads the flag
  byte at `inner+0x89`.
- Flag set: the out record becomes code 5 (u32 `+0`), sub 0 (u16
  `+4`), and a fresh 33-byte message at `+8` holding
  "Seen error. Skip writing buffer." (32 bytes copied from rodata
  `0x208580` "Seen error. Skip" and `0x209590` " writing buffer.",
  plus a NUL). The out `+8` slot is zeroed before the new pointer is
  stored, so the delete[] emitted after the store frees null only
  (a dead free, same pattern as PR #1964).
- Flag clear: the completion step `0x52b13f0` is called with (out,
  inner, ..., 4); the record is filled by that callee by contract,
  not pinned here.
- The helper's landing pad at `0x5163501` jumps to the cleanup stub
  at `0x5163434` (frees out `+8`, resumes); LSDA mapping not pinned.

Shared-release protocol (one shared object: vtable pointer at `+0`,
count word at `+8`; used for every vector element `+0x8`, the
`+0x30` member's `+0x40`, and the inner `+0x28`):

- Null pointer: no-op.
- Count word exactly `0x100000001`: the count word is zeroed, then
  virtual `+0x10` (dispose) and virtual `+0x18` (destroy) are called
  on the object, in that order, with the vtable reloaded between the
  calls; no decrement happens.
- Otherwise the low 32 bits are decremented by 1 (modulo 2^32). When
  `__libc_single_threaded` (GLOB_DAT slot `0x5777ed8`) is nonzero the
  decrement is a plain 32-bit load/decrement/store; when it is zero
  the decrement is a 32-bit lock xadd. When the old low 32 bits equal
  1, the 76-byte routine `0x4f94a40` is called on the object after the
  decrement.

Handle `+0x48` member teardown (a 0x70-byte polymorphic object):

- If the member is null, skip to step 3.
- Its second virtual function (vtable `+0x8`) is compared against the
  relocated qword at `0x5778388` (value `0x51633e0`). On mismatch the
  second virtual is called on the member and the inline teardown below
  is skipped entirely.
- On match, the inline teardown runs: the member vtable pointer is set
  to `0x5766018` (first virtual at that slot relocates to
  `0x5163410`); the member's `+0x50` field is passed to helper
  `0x5566950` (by contract); then the member is freed with sized
  delete, 0x70 bytes. The function `0x51633e0` itself is this same
  teardown as a standalone deleting destructor, and `0x5163410` is
  its non-deleting form.

Inner `+0x30` member teardown (a 0x70-byte polymorphic object; same
teardown as PR #1964 step 8, re-verified here):

- If the member is null, skip to step 11.
- Its second virtual function (vtable `+0x8`) is compared against the
  relocated qword at `0x5777bd0` (value `0x505d960`). On mismatch the
  second virtual is called on the member and the inline teardown below
  is skipped entirely.
- On match, the inline teardown runs: the member vtable pointer is set
  to `0x575f768` (first virtual at that slot relocates to
  `0x505d8f0`); the member string at `+0x50` (pointer `+0x50`,
  capacity-or-inline-buffer `+0x60`) is freed under the same rule as
  step 12 (skip when the pointer equals the address of the `+0x60`
  slot, else sized delete with size = value at `+0x60` plus 1); the
  member's `+0x40` shared pointer is released by the protocol above;
  the member vtable pointer is set a second time, to `0x5759318`
  (first virtual at that slot relocates to `0x5056c90`); if the
  member's `+0x30` pointer is non-null, its second virtual is called;
  then the member is freed with sized delete, 0x70 bytes. The two
  successive vtable resets are recorded as observed; whether they are
  nested destructor stages is not pinned.

Callers (census only, not modelled): exactly 18 direct call sites, no
tail jumps, no qword references to the window address anywhere in the
file. Both sampled sites free the 0x58-byte handle shell themselves
after the release returns: `0x4fb0e87` in `0x4fb0b80..0x4fb0f7e` (in
a loop over an array of handles) and `0x50eadb0` in
`0x50ea260..0x50ebee8` (a guarded single release inside the WAL flush
per-item handler). The remaining sites are listed in records.json.
