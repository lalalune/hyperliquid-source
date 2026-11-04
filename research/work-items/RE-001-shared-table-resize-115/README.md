# RE-001: map node #115 shared-pointer table replace (0x5f0b420)

Task: RE-001 (#115 function map). Bounded question: what does the
function at 0x5f0b420 do end to end — how does it size, allocate and
install a fresh table of 16-byte shared-pointer entries, and what
happens to the table the object held before?

- Component: node #115 shared-pointer table replace. One whole
  function, extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  `0x5f0b420..0x5f0b5d2` (434 bytes; FDE .eh_frame offset 0x74583c,
  length 0x50, CIE 0x730230; LSDA 0x41495c, decoded: call-site
  table length 10 — [0x64, 0x69) landing pad 0x196, i.e. the
  landing pad at 0x5f0b5b6 covering exactly the operator-new call
  at 0x5f0b484, and [0x1ad, 0x1b2) with no pad covering the
  _Unwind_Resume call).
- Claim status: observation for the window bounds, the sizing
  loop, the allocation size and zero-fill, the install order, the
  entry-zero store, the release-loop instructions, the free sizes,
  the landing pad and its coverage, and the caller census;
  inference for the names "table", "log" and "control block" (they
  describe the observed roles, not proven source names); unresolved
  for the items listed in records.json (which sub-object of the
  caller the table belongs to, the exact C++ spelling).
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them
  (including `endbr64` at the window entry) are genuine
  instructions present in the target binary, not placeholders; the
  packet checker re-verifies sampled instructions byte-for-byte
  against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers this window
  (checked this cycle: open-PR snapshot of 91 open PRs plus a
  repository search for 5f0b420, no hit). The window is distinct
  from the neighbouring hash-table functions (rehash 0x5f0e520,
  find-or-insert 0x5f0e660) — those map a hash table with before-node
  slots, while this window builds a fresh array of 16-byte
  (pointer, control-block) entries sized from hardware
  concurrency.
- The key observation, stated literally: the window zeroes the
  object's array field at entry (0x5f0b431) and only then allocates
  and installs the fresh table, and the "old array" it loads
  afterwards (0x5f0b4b5) is read from that same zeroed field — so
  the load always yields null, the old-entry release loop and the
  sized free that follow it are unreachable from this window, and
  a previous table, if the object ever held one, would leak rather
  than be released. The release loop itself is not invented: its
  instructions are read in full, and the identical loop executes
  for real in the standalone helper 0x5f0a1dc (whole-function
  excerpt in this packet), which the window's landing pad also
  calls. The model therefore keeps the two apart: `replace()`
  follows the window's actual order (zero, size, allocate,
  install, return), and `release_table()` models the release loop
  exactly as written, labelled as the unreachable path here and
  the live path in the helper.
- Sizing, in full: k = 3 and N = 8 when hardware_concurrency()
  returns 8 or less (including 0, the "unknown" value); otherwise
  k is the smallest value >= 4 with 2**k >= the returned count,
  and N = 2**k. The log field (object + 0x08) is set to k before
  allocation. Allocation is 16*N + 8 bytes (an 8-byte count header
  holding N, then N zeroed 16-byte entries); when N >> 59 is
  nonzero the window instead calls operator new with -1, which
  throws — unreachable for a 32-bit hardware_concurrency return,
  but present in the code and modelled as a raising guard.
- Allocation-failure state, also literal: the only landing pad
  covers the operator-new call, and it destroys the object's
  current array via 0x5f0a1dc and resumes unwinding — but the array
  field was already zeroed at entry, so on allocation failure the
  helper is skipped, the object is left with array null and log k,
  and any previous table is lost, not freed.
- Release-loop semantics (as written, and as executed by the
  helper): entries are visited last-to-first; a null control block
  is skipped; a control block whose combined (use, weak) qword
  equals 0x100000001 has the qword zeroed and then receives the
  dispose virtual (+0x10) and the destroy virtual (+0x18) directly;
  otherwise the use count is decremented — plainly when the
  __libc_single_threaded byte (GOT slot 0x64ed290) is nonzero,
  with LOCK XADD otherwise — and an old use count of 1 calls the
  dispose helper 0x5d35070 (dispose virtual, then a weak-count
  decrement, then the destroy virtual when the old weak count was
  1). A zero use count wraps to 2**32 - 1 with no dispose. The
  freed size for a released table is 16*N_old + 8 bytes at the
  header base (old start minus 8); a null table frees nothing,
  and an empty (N_old == 0) table frees just the 8-byte header.
- Verification: run the packet checker from the repository root:
  `python3 research/work-items/RE-001-shared-table-resize-115/verify.py`
  (digest, provenance, manifest, excerpt regeneration, sampled +
  3 self-check instructions byte-for-byte vs fresh objdump and raw
  binary, frames, census, model tests).
