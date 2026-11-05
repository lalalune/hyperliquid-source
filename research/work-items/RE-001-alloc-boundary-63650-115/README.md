# RE-001: pin node #115 allocation boundary (0x5963650) — size guard, alignment dispatch and the 24-byte result contract

Task: RE-001 (#115 function map). Bounded question: what exactly
does the shared allocation boundary behind the buffer-growth
family compute — how does it guard the requested byte size, how
does it choose between its plain and aligned allocator forms for
fresh allocations and reallocations, and what exactly does it
publish into the 24-byte result struct on every exit path?

- Component: node #115 allocation boundary, one whole function
  end to end, extracted from the digest-verified work binary
  (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  window `0x5963650..0x5963739` (233 bytes; FDE .eh_frame offset
  0x3144c4, length 0x34, CIE 0, no LSDA — the CIE augmentation
  is `zR` and the FDE augmentation length is 0, so the routine
  has no landing pads).
- Claim status: observation for the window bounds, the size
  guard, the zero-size shortcut, the dispatch tests and their
  argument tuples, the four GOT slots and their RELATIVE
  addends, every result-struct write (including the one path
  that leaves a word unwritten) and the caller census; inference
  for the names "alignment", "element count" and "element
  width" (they describe the observed roles of the argument
  words — the multiplier roles are symmetric in this body, and
  the alignment role is fixed by the trailing-zero-count use
  and by the failure-pair shape below); unresolved for the
  items listed in records.json (the four allocator callees'
  internals above all).
- Note on evidence text: the raw disassembly excerpt is
  verbatim objdump output. Instruction mnemonics appearing in
  it (including `tzcnt`) are genuine instructions present in
  the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a
  fresh objdump run and the raw binary.
- Relationship to earlier work: the buffer growth packet
  (RE-001-buffer-grow-963a10-115, PR #3342) pins this routine's
  principal caller and records the boundary from the caller's
  side — the result layout and the tag-1 failure hand-off — and
  explicitly leaves this body as its first unknown ("a separate
  question"). The RE-017 ring-growth packet cites the boundary
  from one call site and classifies it `allocate_boundary`
  without entering it; the RE-012 curl-body-helper and
  cli-config packets record the call instruction and one
  caller's argument tuple. No merged work item and no open PR
  pins this body: the address sweep for this packet covered
  all 687 open PR titles and bodies and the full merged
  research corpus (records, READMEs and owners.json pins, all
  notations) — 0x5963650 appears only in the citations above.
  The four allocator callees reached through its GOT slots are
  cited here by slot and entry, not entered, exactly as the
  growth packet cites this routine.

- The window, stated literally. Arguments: rdi = out, a
  24-byte result struct; rsi = the old size as the caller
  counts it; rdx = the old data pointer; rcx = an element
  count; r8 = the alignment; r9 = an element width. The
  routine reads rsi ONLY for zero/non-zero (non-zero selects
  the reallocation family, zero the fresh family), never
  dereferences or null-tests rdx, and returns no value its
  callers use — rax at the return is a leftover store offset
  (8 on the guard path, 0x10 on every other exit).
  1. Size guard. One unsigned `mul` forms the product of
     count and width; the byte size P is its low 64 bits. The
     request fails at once when the mul overflows OR when
     P > (2^63 − alignment) mod 2^64, compared unsigned. On
     this failure the routine writes 1 at out+0x00 and 0 at
     out+0x08, leaves out+0x10 UNWRITTEN, and calls nothing.
  2. Zero size. When the old size is 0 and P is 0 there is no
     call either: the result is 0 at out+0x00, the alignment
     at out+0x08, and 0 at out+0x10.
  3. Dispatch. Let tz be the trailing-zero count of the
     alignment. The plain form is chosen when
     (alignment < 0x11 and alignment <= P) or tz == 0 — the
     second clause is exactly alignment == 1, and alignment 0
     is already taken by the first clause, so tz is never
     evaluated at 0. Otherwise the aligned form is chosen and
     receives tz as its extra argument. Reallocation
     (old size non-zero): plain calls the entry 0x635a7a0
     through GOT slot 0x64df588 with (old pointer, P);
     aligned calls the entry 0x635a790 through GOT slot
     0x64df580 with (old pointer, P, tz) — that entry is an
     11-byte `xor ecx,ecx; jmp 0x6350210` prologue. Fresh
     (old size zero): plain calls 0x6355830 through GOT slot
     0x64df480 with (P); aligned calls 0x63577f0 through GOT
     slot 0x64df590 with (P, tz).
  4. Publication. A non-null allocator return R publishes
     0 at out+0x00, R at out+0x08 and P at out+0x10. A null
     return publishes 1 at out+0x00, the ALIGNMENT at
     out+0x08 and P at out+0x10. The struct is the routine's
     only memory footprint besides its own stack frame.

- Caller contract, from inspected sites. Callers compare the
  dword at out+0x00 with 1; on failure they call the shared
  failure entry 0x141e264 through GOT slot 0x64df498 with
  (out word +0x08, out word +0x10) — so this routine's two
  failure shapes hand the failure entry (0, unwritten) after
  the guard and (alignment, byte size) after a null return,
  matching that entry's rdi==0 dispatch recorded by the
  growth packet. The growth routine's site (0x5963a6f) passes
  its old capacity in elements as the old size, its old data
  pointer, its computed new capacity as the count, its
  forwarded word as the alignment and its element size as the
  width. A row of near-identical per-type growth stubs (e.g.
  FDE 0x5962d20..0x5962d84, width 0x40; the stub at 0x59635e0,
  width 0x1b0) passes alignment 8 the same way. The RE-012
  curl owner's site (0x50de490) passes (out, 0, 1, 8, 1, 1):
  old size 0 selects the fresh family and the old-pointer
  word 1 is never read on that path.

- Verification. The caller census (census.py) scans the
  executable segment for rel32 candidates and confirms each
  with one streaming objdump pass: 732 direct calls in 580
  distinct caller FDEs, 0 tail jumps, no stored qwords, no
  RELATIVE addend naming the routine; a capstone cross-check
  decoding linearly from each candidate's FDE start agrees
  exactly, zero rejections. The semantic model
  (tools/alloc_boundary_63650_115.py) was differentially
  tested against the emulated body under Unicorn: 3,072 cases
  (old-size classes × old-pointer values × 16 count/width
  shapes including exact-overflow and limit-boundary products
  × 16 alignments including 0, non-powers of two, 2^63 and
  2^64−1 × allocator null/non-null) with zero divergence
  across the result struct, the callee choice and arguments,
  the leftover rax, and the write footprint (no writes
  outside the result struct and the stack frame). The
  differential harness is a lane scratch artifact; the
  packet's own checker (verify.py) re-runs the census, the
  excerpts and the model tests.
