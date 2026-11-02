# RE-001: map node #94 WAL replay orchestrator 0x520e1b0

Task: RE-001 (#94 function map). Bounded question: given a caller out
status struct, a context struct and a pending vector of element
pointers, what exact sequence of replay calls, pending draining,
handler-chain resolution, predicate dispatch, threshold logging,
reserve and record partitioning does node #94's WAL replay
orchestrator run, and what does it write into the out struct and the
pending vector?

- Component: node #94 WAL replay orchestrator, window
  `0x520e1b0..0x520e7e3` (1587 bytes, single FDE 0x131d3ac,
  cie=0x1301ae8, lsda=0xbdce09), plus its exception cleanup function
  `0x520e12e..0x520e1a1` (115 bytes, FDE 0x131d400).
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the argument roles, the status struct
  layout and move rules, the two replay call sites and their argument
  mapping, the pending drain rule, the getter call, the ten-comparison
  handler-chain rule with its first-mismatch and eleventh-link arms,
  the predicate code dispatch (0 = second replay, 1 = proceed, other =
  abort), the threshold rule with its devirtualized known hook, both
  log calls with their verbatim formats, the reserve call, the
  partition comparison and both arms, the teardown and epilogue order,
  the cleanup entry mapping, and the two direct callers; inference for
  the "WAL replay orchestrator" and "archive flow" readings (offsets,
  log strings and the `db/wal_manager.cc` file marker are pinned,
  source-level names are not), for the devirtualization reading of the
  known-hook comparisons, and for the grow helper's move contract (see
  records.json); unresolved for the source-level reason the partition
  retains below-threshold elements, the internals of every callee, the
  chain objects' and elements' types, the context struct's other
  fields, and the out flags u16.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Scope included: the whole orchestrator function, its exception
  cleanup function, its two direct callers (census only), the resolved
  known-hook values, and the call contracts of the caller loop, the
  getter, the parse variants, the log helper, the reserve/grow/destroy
  helpers and the chain handlers. Scope excluded: the internals of
  every callee, the behavior of the callers beyond their call setup,
  and the caller loop itself (its own packet, PR #1929).

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- numpy: 1.26.4 (census scans only)
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; `objdump --dwarf=frames` is not used
  for frames.txt (rows are verbatim from work/fde94/node-94-fde.tsv).

## Answer

`orchestrate(out, ctx, pending)` returns `out`. The phases below run
in order.

1. Out init: out code, flags and message pointer are zeroed without
   freeing a pre-existing message; the caller must pass an empty out.
2. First replay: the caller loop 0x520d3a0 is called with (stack
   status, ctx, ctx+0x148, fresh empty stack records vector, type 1).
   The stack status is moved into out (old message freed).
3. Early return gate: if out code low byte != 0, jump straight to the
   epilogue (phase 11). The handler never runs on this path.
4. Pending drain: each non-null pending element gets its +0x8 virtual
   call; nulls skipped; pending end resets to begin (array retained).
5. Getter: 0x529cde0 fills a string from ctx+0x148.
6. Handler chain: the chain head is ctx+0xa0; links advance through
   +0x48; each link object's +0xe8 hook is compared — link 1 against
   the relocated value 0x50a97b0, links 2..10 against the previous
   link's hook. The first hook that differs is invoked; if all ten
   match, link 11's hook is invoked. The handler receives (result
   struct, getter string) and writes a code byte plus an owning detail
   pointer.
7. Predicate dispatch: code 1 proceeds; code 0 runs the caller loop a
   second time with (stack status, ctx, getter string, pending
   vector, type 0), moves the new status into out, and proceeds only
   if the new out code low byte is 0; any other code, or a nonzero
   out byte after the second replay, frees the detail pointer and
   goes to the epilogue.
8. Threshold: if pending is empty, the threshold is 0 and no level-1
   log is emitted. Otherwise the threshold is the last pending
   element's +0x08 field when its +0x18 slot equals the known hook
   0x5208e00 (whose body is exactly `return arg +0x08`), else the
   result of calling that slot. The level-1 log
   `[%s:82] Latest Archived log: %lu` is emitted with file
   `db/wal_manager.cc` and the threshold.
9. Reserve: helper 0x520a830 is called with (pending, stack records
   count + pending count).
10. Partition: each stack record slot is visited in order. Its value
    is element +0x08 when its +0x18 slot equals the known hook, else
    the slot's call result. Value >= threshold: if the +0x10 slot
    equals the known hook 0x5209bd0, call parse 0x529ca20 when element
    +0x10 != 0 else parse 0x529d060 with (parse-out string, empty
    parse-in string, element +0x08); otherwise call the +0x10 slot
    with (parse-out string, element). Then dispose the parse-in
    string, emit the level-2 log
    `[%s:95] %s already moved to archive` with the parse-out string,
    and dispose the parse-out string. Value < threshold: if pending
    is full, call grow helper 0x520a990 with (pending, slot address),
    which moves the element and zeroes the slot; otherwise append the
    element to pending, zero the slot, and advance pending end.
11. Teardown and epilogue: free the detail pointer if non-null; walk
    the stack records vector calling +0x8 on each non-null element
    (moved slots are null and skipped); free the stack array with
    sized delete; canary check; return out.

## Files

- `records.json` — semantic records only (no per-instruction lists).
- `window.txt`, `cleanup.txt`, `known-18.txt`, `caller-sites.txt` —
  verbatim objdump excerpts, regenerated by `export_excerpts.py`.
- `frames.txt` — verbatim FDE rows for the window, the cleanup
  function and the callees.
- `relocations.txt` — the three RELATIVE resolutions and the PLT
  symbols used.
- `verify.py` — packet checker (see its header).
- `census.py` — reproduces the caller census.
- `MANIFEST.sha256` — hashes of the packet files.
