# RE-001: map node #94 WAL writer initializer 0x51645d0 with its type-CRC table, construction sites and replace site

Task: RE-001 (#94 function map). Bounded question: how does node #94 build
a fresh WAL writer — what does the initializer move, zero and compute, and
which construction sites use it, including the site that replaces an old
writer?

- Component: node #94 WAL writer initializer, window `0x51645d0..0x516466b`
  (155 bytes, FDE 0x1316cc8, LSDA 0xbd8a26), plus its three direct call
  sites. The compression-type record setup `0x5163ba0` (PR #1958), the
  handle release `0x51641d0` (PR #1966) and the CRC import `0x5421fc0`
  (PR #1848) are used by contract only; their internals are not pinned
  here.
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the window bounds, the move/zero/compute
  steps, the loop bounds and store addresses, the three call sites and
  their argument values, the setup call after the first site, and the
  release-plus-sized-delete sequence at the replace site; inference for
  the WAL-writer attribution (the layout matches PR #1958's writer layout
  field for field) and for the type-CRC table values (computed by the
  model CRC-32C implementation, validated against the published check
  value, not read as stored bytes — the table exists only at runtime
  after this initializer runs); unresolved for the class name, the
  moved qword's meaning, the setters of the setup-site fields, and the
  enclosing functions' wider behavior.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: PR #1958 mapped the writer direction
  (AddRecord `0x5163730`, emitter `0x5163550`, setup `0x5163ba0`) and
  left open whether the type_crc entries are exactly the CRC of the
  single type byte — this initializer answers it: it computes
  type_crc[i] = crc32c(0, &i, 1) for i = 0..9. PR #1966 mapped the
  handle release `0x51641d0` and observed that its callers free the
  0x58-byte shell themselves; the replace site here is exactly such a
  caller (release, then sized delete 0x58). PR #1848 pinned the same
  CRC import at `0x5421fc0` on the reader side. No open WalkCrypto PR
  covers this window (checked this cycle).

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim from
  work/fde94/node-94-fde.tsv.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java), and pytest is not installed, so the pytest-style test
  file runs under plain python3 via its `__main__` runner. The packet
  checker and the tests run against the real binary, not fixtures,
  except for the CRC table values, which the model computes (see the
  claim status above).

## How the initializer works

The initializer takes a destination object, a source slot holding one
qword, a log number, a recycle flag byte, a finalize flag byte and a
compression type byte. It moves the source qword into the destination's
first field and zeroes the source slot, zeroes the block offset, stores
the log number and the recycle flag, computes the ten-entry type-CRC
table by calling the CRC import once per type byte 0..9 with seed 0,
stores the finalize and compression bytes, and zeroes the compressor
and scratch pointers. The destination is 0x58 bytes: both allocating
call sites request exactly 0x58, and the replace site frees exactly
0x58.

## Construction sites

1. Setup site (`0x50bbf5a`, in `0x50bbc40..0x50bc373`): allocates
   0x58 bytes, initializes with the caller's log number, recycle flag
   (nonzero when the enclosing object's +0x400 qword is nonzero),
   finalize byte (+0x4c5) and compression byte (+0x4c6), stores the new
   object in the caller's slot, then immediately calls the
   compression-type setup `0x5163ba0` with the new object — the writer
   is built to be set up.
2. All-zero site (`0x50be17b`, in `0x50bda70..0x50be7eb`): builds the
   writer in place on the stack with every argument zero; no setup
   call follows in the sampled window.
3. Replace site (`0x51f7c20`, in `0x51f5550..0x51f865d`): allocates
   0x58 bytes, initializes with all-zero arguments, stores the new
   object at the enclosing object's +0x130, and when the previous
   +0x130 value is non-null releases it with `0x51641d0` and frees it
   with sized delete 0x58.
