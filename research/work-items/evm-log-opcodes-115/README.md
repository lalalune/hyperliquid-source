# evm: reconstruct node #115 EVM LOG0..LOG4 opcode handlers and the memory expansion body 0x45244c0

This packet makes the whole node #115 EVM log-emission path reconstructible from byte evidence: all ten LOG0..LOG4
handlers (three opcode tables, two copy families), their gas charge, stack and width refusals, the memory-expansion
call and the real memory-expansion body 0x45244c0 (gas formula, size/cost bookkeeping, zero fill, panic limits), the
Bytes-tagged data copy, the big-endian topic vector and the exact 0x50-byte log record appended to the context. An
independent Rust implementation can now fix the status code of every refusal and its order, the exact gas and
memory-cost arithmetic including the "store the new size and cost before the charge can fail" quirk, every panic site,
the record layout and the allocation order, because a pure-Python reconstruction reproduces the real machine code on
12,000 byte-grounded cases with zero mismatches and 67 of 67 negative controls detected.

- Component ID: evm (HyperEVM execution; opcode handlers of the EVM interpreter)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source copied
- Claim status: observation (addresses, tables, instruction bytes, machine-code comparison) plus inference (field
  and status names, labelled as such below)
- Scope included: LOG0..LOG4 handlers 0x4330700 0x432fdf0 0x432f9a0 0x43309e0 0x43301c0 (tables 0x6485ef8 and
  0x6486c60) and the twin set 0x4f02c40 0x4f03d70 0x4f03460 0x4f038b0 0x4f02f20 (table 0x649eea0), and the memory
  expansion body 0x45244c0 (GOT slot 0x64e6de0). Scope excluded: the interpreter loop that charges static gas and
  dispatches through the tables, the stubbed callees listed under Limits, and every other opcode.

## Reproduce

Working directory: repository root; Python 3 standard library only; the tool never executes the binary and calls no
external program.

```
python3 tools/evm_log_opcodes_115.py --out research/work-items/evm-log-opcodes-115
python3 -m unittest tests.test_evm_log_opcodes_115
cd research/work-items/evm-log-opcodes-115 && sha256sum -c MANIFEST.sha256
python3 tools/artifacts.py verify
```

The tool checks the input SHA-256 first and fails on any other binary. Generation takes about 35 s and about 390 MB of resident memory.
Two generations (different hash seed and time zone) are byte-identical. Output files:

| file | content |
| --- | --- |
| `opcode-tables.tsv` | all 3 x 256 slots of the RELATIVE opcode tables (handler address per opcode), LOG slots marked |
| `got-slots.tsv` | the GOT slots the handlers call through, relocation type, resolved target / import name |
| `sites.tsv` | every rip-relative `lea` target and `call/jmp *slot` site of the 11 functions |
| `decoded-instructions.tsv` | linear decode of the 11 function extents (FDE) with an executed-by-the-cases flag |
| `cases.tsv`, `resize-cases.tsv` | every 4th handler case (2,500) and every 4th direct resize case (500) with the observation digest |
| `outcome-classes.tsv`, `summary.json` | outcome counts per handler and result class, coverage per function |
| `negative-controls.tsv`, `equivalent-mutants.tsv`, `measure.json` | 67 controls with the first detecting case; no equivalent mutants |

## Evidence

Coordinates are virtual addresses of the loaded image (`.text` file offset = VA - section address + section offset).
Function extents come from `.eh_frame` FDEs, never from the symbol table.

- Opcode tables: `0x6485ef8` (A), `0x6486c60` (B) and `0x649eea0` (C) are RELATIVE tables of 256 handler words.
  Slots 0xa0..0xa4 hold the five handlers above in A and B (identical words in both) and a different, same-length
  set in C. The extents are 725, 972, 1094, 1212 and 1337 bytes in both sets.
- GOT slots used (`got-slots.tsv`): 0x64df480 allocator wrapper (0x6355830), 0x64df508 `memcpy` and 0x64df750
  `memset` (GLOB_DAT imports), 0x64df520 / 0x64df870 / 0x64df878 panic, shift-overflow and divide-by-zero panic
  functions, 0x64df498 allocation-error handler, 0x64dfa48 log-vector grow (0x1437200), 0x64e6de0 memory expansion
  (0x45244c0), 0x64df8c0 / 0x64df8c8 the even/odd `Bytes` vtable words (0x64040e8 / 0x64040c0).
- Panic message addresses (lea targets before the panic call, in `sites.tsv`): family AB end-add 0x648f1e8, family C
  0x64af380, base adds 0x64bfc68 / 0x64bfc80 in both, topic-gas multiply 0x6486a98 (AB) / 0x649f740 (C); resize
  0x648f230 (divide), 0x648f1d0 (word limit), 0x64bfcf8 (base add). The tool refuses to run unless every one of these
  addresses and the per-family empty-`Bytes` vtable (0x6485430 / 0x649f6b8) appears as a lea target inside the
  corresponding function.
- Stub contract: the allocator, memcpy, memset, the panics, allocation error, the `Bytes` drop functions (vtable
  word +0x20), the log-vector grow (0x1437200) and the raw vector reserve (0x5be8d40, called by the resize body) are
  not executed; a call to one is replaced by a recorded event with the exact argument registers, and the next
  instruction after a panic is never reached.
- Reconstructed behaviour (observation, from the instruction bytes and confirmed by the comparison):
  1. `cmpb $0,+0x1a8` non-zero returns 0x28 before anything else; fewer than two stack words returns 0x2c.
  2. offset = top word, length = second word; the stack length is reduced by two before the next check. A length
     with any limb above the first returns 0x24. Offset limbs above the first return 0x24 only when length != 0.
  3. Gas: `length*c30` saturating at u64::MAX, plus `topics*c38` where the topic product for LOG2..LOG4 panics on
     overflow (LOG1 adds `c38` directly), then saturating; a balance below the total returns 0x20 and leaves gas
     untouched. The charge precedes the offset check and the memory expansion.
  4. A non-empty slice needs `ceil((offset+length)/32)` words (end saturated at u64::MAX for the count, but the real
     sum overflowing panics after the expansion); more than the current words calls 0x45244c0 whose non-zero return is
     the handler's result (0x21 for memory gas).
  5. The borrow counter in the memory cell (+0x10) is incremented around the copy (and left incremented when the base
     adds panic or the allocation fails). The source is `buffer + frame base + offset`; the copy is a fresh allocation;
     the `Bytes` value is {vtable chosen by pointer parity, ptr, len, ptr|1}. An empty slice is {static vtable,
     ptr 1, len 0, word 0} and skips the offset check, the expansion and the copy.
  6. LOG1..LOG4 then require the topic count on the stack (else the `Bytes` value is released through vtable +0x20
     and 0x2c is returned with the topic words left on the stack), pop the topics, store each as 32 big-endian bytes in
     one allocation of 32*n bytes (capacity n, length n) and push the record; LOG0 uses an empty vector (cap 0, ptr 1).
  7. The record (0x50 bytes at context +0x278, count at +0x280, capacity at +0x270, doubling to a minimum of 4
     through 0x1437200 when full): +0x00 topic cap, +0x08 ptr, +0x10 len, +0x18 data vtable, +0x20 data ptr,
     +0x28 data len, +0x30 data word, +0x38 20-byte executing address, +0x4c four bytes of uninitialised stack padding
     (excluded from the comparison).
  8. Memory expansion 0x45244c0: cost = words*c50 + words*words/c58 (each product saturating, c58 = 0 panics); the
     new word count and cost are stored before the charge is tested; delta = cost - old cost (wrapping); delta above
     the gas returns 0x21 with the new size already stored; words >= 2^59 panics; `words*32 + base` overflow panics
     after the cell flag was set to -1; otherwise the cell length becomes `words*32 + base` (also when shorter), new
     bytes are zeroed, the raw vector reserve is called when the capacity is short, and the cell flag ends at 0.

## Implementation and comparison

`tools/evm_log_opcodes_115.py` contains (a) the concrete x86-64 evaluator used for the machine-code side (a small
interpreter of the instruction subset that appears in these functions, extended here with unsigned `div`), (b) the
independent pure-Python model `log_model` / `resize_model` / `mem_cost`, (c) the harness that builds the host, cell,
context, stack, log vector and heap regions for each case and records all stub events, and (d) the evidence
generators. The Python model is written from the behaviour above, not from the evaluator.

- Cases: 10,000 handler cases (case k uses LOG(k mod 5), family AB when (k div 5) is even and C otherwise, one of 32
  scenario modes: ordinary, wide offset or length, length 0 with a wide offset, offset+length overflow, near-limit
  gas, exact gas edges, zero or huge schedule words, base offsets near 2^64, memory already at 2^59 words, odd
  allocation pointers, shorter or exactly full cells, allocation failure on the first or second allocation,
  static call, missing stack words and missing topics) and 2,000 direct cases for 0x45244c0 (word counts around the
  current size, 2^59, 2^59-1, random 62-bit, one- and two-byte growth). Every case compares status, stack length,
  gas, memory words and cost, cell length, borrow counter, a digest of the whole 64 KiB memory buffer, a digest of
  the allocated heap, the log count and capacity, the record bytes and the ordered stub events.
- Result: 12,000 cases, 0 mismatches. Outcome classes (see `outcome-classes.tsv`): per handler 911-1,134 ok,
  62-87 static refusals, 67-125 stack underflows, 109-132 width refusals, 109-217 out of gas, 182-196 memory out of gas,
  54-152 allocation failures and 230-293 panics; the resize body sees 1,167 ok, 615 memory out of gas and 218 panics.
- Coverage: 2,346 of 2,542 decoded instructions of the 11 functions are executed. The 196 unexecuted instructions
  are the `jmp` that follows a call to a non-returning function (never reached because the stub ends the run) and the
  unwind landing pads after each function's `ud2` (reachable only by unwinding, which is not modelled).
- Negative controls (67, all detected, none equivalent): 32 wrong models (skipped refusal, off-by-one underflow,
  ignored limbs, wrapping product, dropped panic, free topics, `<=` charge, double topic charge, empty slice on the
  copy path, floor word count, ignored base, unrestored borrow counter, untagged data word, swapped vtables, missing
  release, reversed or little-endian topics, wrong capacities, no grow, dropped address, stuck count, no quadratic
  term, clamped delta, late cost store, no word-limit panic, no reserve, no zero fill, kept flag, no shrink),
  32 corrupted code bytes (the first conditional jump, a status immediate and the last status immediate of each
  function, chosen by instruction kind), and 3 corrupted inputs (a changed binary digest, a non-function start
  address, a misaligned handler start). `negative-controls.tsv` lists the first case that exposes each.
- Not implemented: a Rust port. This is a behavioural reconstruction in Python with machine-code comparison.

## Results and limitations

Metrics (denominators in `measure.json` / `summary.json`): cases 12,000 (10,000 + 2,000), mismatches 0,
negative controls 67, detected 67, equivalent 0, executed instructions 2,346 / 2,542.

Inference (not observation): the names "host", "cell", "context", "gas schedule", "Bytes" and the status meanings
(0x28 static call, 0x2c stack underflow, 0x24 value too big, 0x20 out of gas, 0x21 memory out of gas) follow from the
offsets, the values and the matching EVM semantics. The model of the allocator / memcpy / memset / panic /
`Bytes` drop / log-vector grow / raw reserve calls is a recorded stub; their internals are unresolved. The reserve
stub only changes the capacity word (the comparison therefore does not check the post-reserve capacity), and the
grow stub only records the old capacity and doubles it. The harness buffer is 64 KiB, so successful expansions are
kept below it by withholding one unit of gas; the behaviour of larger successful expansions is the same code path
but is not exercised. No component gate is requested.

Next question: the CREATE / CREATE2 handlers (opcodes 0xf0 / 0xf5: 0x4338c10, 0x4339270 and the twins 0x4f07ae0,
0x4f07460) share the memory expansion body and the Bytes copy reconstructed here, and the stubbed raw vector reserve
0x5be8d40 and log-vector grow 0x1437200 are small enough to reconstruct for real.
