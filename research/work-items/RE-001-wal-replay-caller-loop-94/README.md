# RE-001: map node #94 WAL replay caller loop 0x520d3a0

Task: RE-001 (#94 function map). Bounded question: given an out status
struct, a context struct, an arg3 value, an out-records vector, and a
file type, what exact sequence of entry-chain resolution, element
filtering, replay-driver calls, second-chain resolution, record
appending, and error handling does node #94's WAL replay caller loop
run, and what does it write into the out struct and the out-records
vector?

- Component: node #94 WAL replay caller loop, window `0x520d3a0..0x520e12e`
  (3518 bytes, single FDE 0063be1c, cie=006205d0).
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the argument roles, the status struct
  layout, the file-list vector layout and dispose rule, all three
  chain-resolution rules (ten comparisons plus fallback), the
  predicate gate, the driver call site and its fail/slot-zero rules,
  both filename-builder call sites, the record layout, the
  reserve/grow append rules, the full type-1 retry sequence including
  the byte-1 swallow rule, the status copy/move rules, the loop-end
  sequence, the common teardown, and the exception cleanup region;
  inference for the "WAL replay caller loop", "file type", "log
  number", and "error callback chain" readings (offsets and uses are
  pinned, source-level names are not); unresolved for the chain
  objects' types and handlers' semantics, the predicate's internals
  and u32 gate meaning, the chain-B second output slot's content
  semantics, the output-vector destroy helpers' internals, the
  runtime path component's content, the file-list producer beyond its
  string elements, and per-iteration filename-string disposal.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Scope included: the whole caller-loop function, its exception
  cleanup region, its three direct callers (census only), and the call
  contracts of the reserve/grow helpers, the predicate, the replay
  driver, the two filename builders, and the string copy helper.
  Scope excluded: the internals of every callee, the behavior of the
  callers beyond their call setup, and the replay driver itself (its
  own packet, PR #1926).

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- numpy: 1.26.4 (census scans only)
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; `objdump --dwarf=frames` for the FDE
  block. An absolute binary path changes objdump's header line and
  breaks excerpt regeneration checks.

## Answer

`caller_loop(out, ctx, arg3, out_records, file_type)` returns `out`.
The phases below run in order.

1. Entry chain: the chain head is the object at context +0xa0; links
   advance through +0x48; each link object's +0xf0 field is compared
   against the runtime value at 0x5778260. Ten nodes are compared;
   the first whose +0xf0 differs wins; if all ten compare equal, the
   next node's handler is called. The handler receives (status
   scratch at rsp+0x70, current link node, arg3, file-list vector
   slot at rsp+0xa0) and writes the entry status plus the file list
   (a vector of strings at rsp+0xa0: begin, end, capacity).
2. Entry failure: if the entry status byte 0 is nonzero, the status
   is copied into out (six header bytes verbatim, message
   string-copied via 0x542efe0) and the file list is torn down; the
   main loop never runs.
3. Reserve: the reserve helper 0x520a830 is called with (out-records
   vector, file-list element count = (end - begin) >> 5). If the
   vector's capacity already covers the count it returns at once.
4. Main loop, per file-list element (stride 0x20): the predicate
   0x529f350 is called with (element, u32 output, u64 output, 0).
   The element is processed only when the predicate returns nonzero
   AND the u32 output is zero; otherwise the loop advances. The u64
   output is the log number.
5. Replay: the replay driver 0x520c120 is called at 0x520d5a9 with
   (driver status scratch at rsp+0x80, context, file type, log
   number, out-pointer slot at rsp+0x60). If the driver status byte
   0 is nonzero, the driver status is copied into out (pointer
   moved) and the file list is torn down; the loop ends. If the
   status byte is zero but the slot value is zero, the driver
   status message pointer is freed and the loop advances; no record
   is appended.
6. Filename and second chain: the type-1 filename builder 0x529ca20
   is called with (filename string at rsp+0xc0, arg3, log number,
   chain-head object's +0x128 field). Then the second chain is
   resolved exactly like the entry chain but on the +0x128 field
   against the runtime value at 0x57781e0, with handler arguments
   (status scratch at rsp+0x90, current link node, filename string,
   second output slot at rsp+0x68). The scratch status is then moved
   into the loop status (u32, u16, pointer; scratch zeroed; the
   previous loop message pointer freed).
7. Second-chain failure: if the loop status byte is nonzero and the
   file type is not 1, the loop status is copied into out (pointer
   moved) and the file list is torn down. If the file type is 1,
   the retry arm (step 9) runs instead.
8. Append: a fresh 0x28-byte record is allocated:
   {tag pointer 0x575bdf0 at +0, log number at +8, file type at
   +16, 16 bytes at +24 from rsp+0x60 (driver slot value, then
   chain-B second output slot value)}. If the out-records vector
   has room, the pointer is stored and the end advances by 8;
   otherwise the reallocating append helper 0x520a990 runs with
   (vector, end pointer, pointer to the record-pointer slot), which
   moves the pointer out of the caller slot (zeroing it) into the
   grown storage; a nonzero leftover in the slot would then have
   its +0x8 destructor called. The loop status message pointer is
   freed and the loop advances.
9. Retry arm (file type 1 only): the filename is rebuilt with the
   type-0 builder 0x529d060 (filename string, arg3, log number).
   The retry chain on +0xe8 against the runtime value at 0x5778258
   runs with (status scratch at rsp+0x90, current link node,
   filename string). If its status byte is nonzero, the retry
   status message pointer and the filename string are freed, the
   loop status is copied into out, and the file list is torn down.
   If zero, the second chain runs again (+0x128, same shape); its
   status is moved into the loop status. If the loop status byte
   is now zero, the record is appended (step 8, with the second
   chain's output slot value). If it is still nonzero, a final
   +0xe8 chain runs; if that chain's status byte is 1, the loop
   status is zeroed, its message pointer and the filename string
   are freed, and the loop advances to the next element (the
   failure is swallowed); otherwise the filename string is freed,
   the loop status is copied into out, and the file list is torn
   down.
10. Loop end: the out-records vector elements are destroyed (range
    step 0x52092a0 and per-slot step 0x52091d0, preceded by the range
    call 0x5209430; helpers' internals not pinned), the entry
    status is copied into out with a string copy of the message,
    the file list is torn down, and the function returns out.
11. Teardown (common exit): the entry status message pointer at
    rsp+0x78 is freed if nonzero; every file-list string element is
    disposed (if its pointer differs from its own +0x10 address,
    operator delete[] runs with (pointer, capacity at +0x10 plus
    1)); the file-list array is freed; the canary at rsp+0xe8 is
    checked; out is returned. Exception cleanup (0x520d31e..0x520d3a0,
    reached from the landing pads at 0x520e0ce..0x520e12e) disposes
    the filename string, frees the status message pointers, destroys
    the file-list vector via 0x4f95600, checks the canary, and
    rethrows via _Unwind_Resume.

## Files

- `window.txt`: whole-function verbatim objdump excerpt.
- `cleanup.txt`: exception cleanup region verbatim excerpt.
- `caller-site.txt`: verbatim excerpts around the three direct call
  sites (0x520e22c, 0x520e4f3, 0x520f60f).
- `frames.txt`: the window FDE block plus direct-callee FDE headers.
- `relocations.txt`: PLT targets, direct call targets, indirect
  call forms, and the caller census.
- `records.json`: semantic records only (no per-instruction list).
- `verify.py`, `export_excerpts.py`: packet checker and excerpt
  regenerator. `MANIFEST.sha256` covers every packet file.
