# RE-001: map node #94 WAL flush driver 0x50ebfb0

Task: RE-001 (#94 function map). Bounded question: given a manager struct,
a result slot, and a third argument, what exact sequence of gates, log
calls, item collection, per-item handler calls, and post-loop phases does
node #94's WAL flush driver run, and what does it write into the result?

- Component: node #94 WAL flush driver, window `0x50ebfb0..0x50ec9d7`
  (2599 bytes, single FDE).
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the gate order, the collection rule, the
  per-item copy/stop rules, the phase order and gating, the log strings
  and their value slots, and the two-caller census; inference for the
  "WAL flush driver" naming and the "manager / item / handler / phase"
  readings (offsets and uses are pinned, source-level names are not);
  unresolved for the internals of the handler and every phase, the entry
  hook, the score's own meaning, and the third log value's own meaning.
- Scope included: the whole driver function, its two direct callers
  (census only), the sweep call site (the sweep itself is mapped in
  #1798), and the phase/handler call contracts. Scope excluded: the
  internals of the handler `0x50ea260` and of phases A/B/C/D/E/F/G, the
  sibling driver `0x50e8f00..0x50e9402`, and the behavior of the two
  callers beyond their call setup.

## Answer

`drive_flush(out, db, arg3)` writes a result struct
(`u32` at +0, `u16` at +4, heap pointer at +8) into `out` and returns
`out`. The struct is not identified as any named library type.

1. Entry: call the entry hook `0x5334d60` on `db + 0x700` (semantics
   not claimed), then zero all three result fields.
2. Gate A: if the byte at `+0x10` of the struct at `db + 0xae0` is
   nonzero, return the zeroed result immediately.
3. Gate B: if `db + 0x4a3` is nonzero, take the sweep path (below);
   otherwise take the main path.
4. Sweep path: call the pending-key erase sweep `0x5160560` on
   `db + 0x1698` (this driver is the sweep's site-3 caller in #1798).
   - Sweep returns 0, or a value different from the WAL number (the
     gate-A struct's first field): re-enter the main path at its entry
     (reset `db + 0x1511` to 0, set the gate-A flag byte to 1).
   - Sweep returns exactly the WAL number and `db + 0x1511` is 0: log
     once at level 2 (`[%s:1621] Unable to release oldest log due to
     uncommitted transaction`, file `db/db_impl/db_impl_write.cc`),
     set `db + 0x1511` to 1, and restart the main body WITHOUT the
     reset and WITHOUT setting the gate-A flag (the restart jumps
     straight to the `0x50e6a90` call).
   - Sweep returns exactly the WAL number and `db + 0x1511` is already
     nonzero: return the current result immediately.
   - Gate A is checked only once, at entry; neither re-entry nor
     restart re-checks it.
5. Main path: reset `db + 0x1511` to 0, set the gate-A flag byte to 1,
   call `0x50e6a90(db)` (its return value is the third main-log value;
   its own semantics are not claimed), then log at level 1:
   `[%s:1638] Flushing all column families with data in WAL number %lu.
   Total log size is %lu while max_total_wal_size is %lu` with the
   slots, in order, (WAL number, `db + 0xc28`, `0x50e6a90` return).
6. Collection (skipped when `db + 0x4c7` is nonzero at this point; then
   phase G runs instead, see below): walk the list whose head is
   `[[db + 0x68] + 0x40] + 0x110`, following `+0x938` links until the
   node equals the head. Skip an item whose byte at `+0x3d` is
   nonzero, without a score call. Otherwise score it with
   `0x4feb700(item, overflow-vector slot)` and skip it when the score
   is unsigned-below the WAL number. Keep the rest in walk order: the
   first 8 go to the inline stack array, further items to the overflow
   vector (grown through `0x4fc75e0` when end equals capacity).
   Total = inline count + overflow count. Then run phase A
   `0x50e9410(db, count slot, overflow vector)`.
7. Phase G (only when `db + 0x4c7` was nonzero at collection time):
   call `0x50e8f00(db, string slot, context, context + 8)` instead of
   the collection loop and phase A, then continue to the context init
   with an empty collection (total 0).
8. Context init (stack struct at `-0x140`): `+0x00` = 0,
   `+0x08` = `0x400000000`, `+0x10` = 0, `+0x18` = 0, `+0x28` = 0,
   `+0x38` = 0, `+0x48` = 0, `+0x50` = `0x100`, `+0x58` = 0,
   `+0x60` = `0x00ffffffffffffff`, `+0x68` = 0, `+0x70` = 0,
   `+0x78` = 0, `+0x80` = 0, `+0xf0` = 0.
9. Phase B (only when `db + 0x17b0` is nonzero): call
   `0x522b960(db + 0xf50, db + 0x700, context)` before the loop.
10. Per-item loop: index `i` from 0 while `i != total`. For `i < 8`
    read the inline slot `i`; for `i >= 8` read
    `overflow_begin[i - 8]` (the bytes compute
    `overflow_begin - 0x40 + i * 8`). Before each item, stop if the
    result's low byte is nonzero. Per item: locked-increment
    `item + 0x38`, call the handler `0x50ea260(result, db, item, arg3,
    context)`, copy the handler result into `out` (`+0` u32, `+4` u16
    with the handler result's u16 field then zeroed, `+8` pointer with
    the previous `out` pointer freed by sized operator delete when
    non-null), then call `0x4ff0bb0(item)`. The loop ends early at the
    first item whose copy leaves the result's low byte nonzero;
    remaining items are not processed.
11. Post-loop chain:
    - Phase C `0x522b770(context, db + 0xf50)` runs only when
      `db + 0x17b0` is nonzero, on both the early-exit and the
      completion entries.
    - If the result's low byte is nonzero after phase C (or when phase
      C is skipped on the early-exit entry), go straight to teardown,
      skipping everything below.
    - If the result's low byte is 0 and `db + 0x4c7` is nonzero: run
      phase D `0x50e69f0(db, string slot, context)`, then phase E
      (`0x5040500`, then `0x503a7f0`, then `0x50e89f0`, in that order),
      then phase F `0x5035e80(db, context)`, then teardown.
    - If the result's low byte is 0 and `db + 0x4c7` is zero: when
      total > 0, run the marking loop (below); when total == 0, skip
      it; then phase E, then phase F, then teardown.
12. Marking loop (only when `db + 0x4c7` is zero, total > 0, and the
    result's low byte is 0): for each collected item in order, set
    byte `+0x905` to 1; if the `s32` at `+0x900` is greater than 0,
    also set byte `+0x8f0` to 1. `db + 0x4c7` is read fresh per item:
    when it is still zero for that item, additionally run
    `0x5040500(db, fresh mini context)` then
    `0x503a7f0(db, mini result)`, free the mini context's `0x18`-byte
    node list, memset its array, reset its counts, and free its
    overflow buffer when non-null. This per-item phase does NOT call
    `0x50e89f0` (unlike phase E).
13. Teardown: destroy the condition variable at `context + 0xc0` only
    when the byte at `context + 0x50` is nonzero (the initial value
    `0x100` leaves that byte 0, so the destructor runs only if a phase
    set it); free the context's heap buffers with sized operator
    delete when non-null; reset the inline count to 0; free the
    overflow vector buffer when non-null (end reset to begin first);
    check the stack canary; return `out`.

## Caller census

Byte-pattern scan over the executable segment (file offsets
`0x1342c80..0x5660250`, vaddr = file offset + `0x1000`) for `e8`
sites whose rel32 lands on `0x50ebfb0`, plus an `e9` tail-jump scan
and a whole-file qword scan for `0x50ebfb0`: exactly 2 direct calls,
0 tail jumps, 0 qword references.

| call site | caller FDE | setup immediately before the call |
| --- | --- | --- |
| 0x4fd2622 | 0x4fd19b0..0x4fd2820 | rdi = [rsp + 0x08] (out), rsi = rbx (db), rdx = [rsp + 0x18] (arg3) |
| 0x50ee6d1 | 0x50ede70..0x50ee840 | rdi = rsp + 0x90 (out), rsi = rbx (db), rdx = r14 (arg3) |

Caller purposes are not claimed. The `0x50ec3cb` site inside this
window is phase D's call, not a call to this window.

## What is not claimed

- The handler's work on any single item beyond its result-struct
  contract, the internals of any phase, the entry hook, the score's
  own meaning, and the third log value's own meaning.
- Source-level names for any db field or context field: only offsets
  and uses are pinned.
- The sibling driver `0x50e8f00..0x50e9402` (a different FDE) beyond
  phase G's call contract.
- The `0x50ec810` total==0 branch that would re-check `db + 0x17b0`
  is unreachable on that path (phase B is entered only when
  `db + 0x17b0` is nonzero); it is recorded as observed control flow,
  not as a live arm.

## Evidence format

This packet follows the semantic-record format: `records.json` holds
semantic records only (no per-instruction mnemonic list). Instruction
detail lives only in the verbatim objdump excerpts (`window.txt`,
`caller-sites.txt`, `caller-site-2.txt`), kept whole-function and
regenerable with `export_excerpts.py`. The checker `verify.py` is
committed in the packet. Mnemonics such as `endbr64` in the excerpts
are genuine instructions present in the target binary, not
placeholders; the checker re-verifies three sampled instructions
byte-for-byte against the raw binary.

## Verification

`verify.py` checks, all against the digest-verified binary:
1. Every excerpt file matches a fresh objdump run (from the repo root,
   with the repo-relative binary path, so the header spelling matches).
2. `records.json` parses and carries the required semantic sections.
3. The log strings in `records.json` match the binary's rodata at the
   lea targets.
4. Three sampled instructions match the raw binary byte-for-byte
   (endbr64 at the window start, the sweep call, the handler call).
5. Both caller sites encode an `e8` call to the window, and the census
   counts (2 direct calls, 0 tail jumps, 0 qword refs) reproduce.
