# evm: reconstruct node #115 EVM stack, memory, jump and environment opcode handlers (186 handlers, three dispatch tables)

With this packet the behaviour of 186 interpreter handlers of node #115 can be rebuilt in plain Python: POP, PUSH0..PUSH32, DUP1..DUP16, SWAP1..SWAP16, MLOAD, MSTORE, MSTORE8, MSIZE, JUMP, JUMPI, JUMPDEST, PC, STOP, INVALID, an unassigned-opcode stub and sixteen environment opcodes (ADDRESS, ORIGIN, CALLER, CALLVALUE, CODESIZE, RETURNDATASIZE, CALLDATASIZE, COINBASE, TIMESTAMP, NUMBER, GASLIMIT, CHAINID, BASEFEE, GAS and the spec-gated opcodes 0x4a and 0x4b), including every status code (0x24, 0x2a, 0x2b, 0x2c, 0x2d), every panic message pointer, the memory-expansion call contract and the three-way split between the two identical `0x43xxxxx` tables and the `0x4f0xxxx`/`0x50bxxxx`/`0x546cxxx` table. One pure-Python model reproduces the real machine code of all 186 handlers on 11,020 generated states with zero mismatches, and 102 negative controls (99 detected, 3 provably equivalent) show the comparison can fail.

- Component ID: evm
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository HEAD `0781ce04826eeefd89fe336cb8ea073be0c1de30` (no reference-source text was copied)
- Claim status: observation (handler addresses, tables, field offsets, status codes, panic pointers, byte-level agreement with the model); inference (opcode names beyond the table position, the meaning of fields such as "memory object" and "analysis object"); unresolved items are listed under Results and limitations
- Scope included and excluded: the handlers reached through opcode slots 0x00, 0x30, 0x32-0x34, 0x36, 0x38, 0x3d, 0x41-0x43, 0x45, 0x46, 0x48, 0x4a-0x4c, 0x50-0x53, 0x56-0x5b (0x5a = GAS), 0x5f-0x9f of the three RELATIVE tables 0x6485ef8, 0x6486c60 and 0x649eea0. Excluded: the memory expansion body 0x45244c0 (stubbed, covered by the LOG packet), the copy opcodes (CALLDATALOAD, CALLDATACOPY, CODECOPY, RETURNDATACOPY, MCOPY), RETURN/REVERT, GASPRICE, SELFBALANCE, BLOBHASH, PREVRANDAO, BLOCKHASH and the gas, call and storage handlers

## Reproduce

Run from the repository root with a plain Python 3 and no external programs (the binary is never executed):

```
python3 tools/artifacts.py verify
python3 tools/evm_stack_memory_opcodes_115.py --out research/work-items/evm-stack-memory-opcodes-115
python3 -m unittest tests.test_evm_stack_memory_opcodes_115
(cd research/work-items/evm-stack-memory-opcodes-115 && sha256sum -c MANIFEST.sha256)
```

Generation takes about 16 s and about 0.4 GB; the test module takes about 40 s. The tool checks the SHA-256 of `artifacts/node/115/hl-node` first and fails on any other input. Two runs into different folders were compared with `diff -r` and are byte-identical. `measure.json` holds the counts quoted below.

## Evidence

Coordinates are virtual addresses of the ELF; every number below is read from ELF bytes by the tool (`tools/elf_index.py`, `tools/fde_extents.py`, the `.rela.dyn` RELATIVE addends and the code bytes).

- `slots.tsv`: for every modelled opcode the handler address in each of the three tables (`0x6485ef8` and `0x6486c60` hold identical entries for these opcodes; `0x649eea0` has its own copies of the same handlers at different addresses).
- `handlers.tsv`: 186 distinct handler addresses with FDE extent (3 to 312 bytes), SHA-256 prefix of the code bytes, the (table, opcode) slots that point at them and the targets of their indirect calls (memory expansion 0x45244c0, panic helpers 0x1681da0 and 0x1681e40).
- `cases.tsv`: one row per generated state (11,020): handler, tables, opcode, name, input stack length, result (status byte or panic message pointer), stack length afterwards and a digest of the full final state (stack bytes, memory buffer, pc, borrow counter, paid words, expansion events).
- `controls.tsv`: the 102 negative controls and whether each one was detected; `equivalent-mutants.tsv`: the three that are equivalent and why.
- Observed handler contract, identical across the tables unless stated: argument `rdi` = interpreter, `rsi` = host; status in `al`. Stack words are 32 bytes (four little-endian limbs) at the pointer in interpreter +0x28 with the length in +0x30; the limit is 0x400. PUSHn reads n bytes at the pc pointer (+0x118), big-endian, and advances it; PUSH0 is gated by the spec byte (+0x1a9 >= 0x0a, else 0x2b); PUSH1..32 fail with 0x2d when the length is above 0x3ff, PUSH0 when it equals 0x400. DUPn fails with 0x2d when the length is below n or at least 0x400, SWAPn with 0x2c when fewer than n+1 words. JUMP/JUMPI load the destination (all upper limbs must be zero, otherwise it is treated as 2^64-1), compare it with the analysis object's code length (+0x28), test the destination's bit in the jump-destination bitmap (pointer at analysis +0x18) and set the pc pointer to code start (+0x38) + destination, or return 0x2a; JUMPI tests the condition word as a whole and, when it is zero, only pops two words. PC pushes pc - code start - 1 and panics (message pointer 0x6486ac8 in the first two tables, 0x64a9d28 in the third) when they are equal. MSIZE pushes memory length (+0x28 of the memory object) minus the base offset (+0x18) and panics with 0x64bfc50 when that underflows. MLOAD, MSTORE and MSTORE8 round the touched range up to 32-byte words, call the expansion body when the count exceeds +0x170 (arguments interp+0x170, interp, host+0x250), apply the borrow counter in the memory object (+0x10: incremented around MLOAD, set to -1 around MSTORE and MSTORE8), add the base offset with two overflow checks (six distinct panic message pointers, the third table uses 0x64af380 for the MLOAD range check) and move the bytes big-endian. The environment opcodes push one field: 8-byte values, raw 32-byte values, or 20-byte big-endian addresses placed in the low limbs, gated by the spec byte where the handler compares it (RETURNDATASIZE >= 4, CHAINID >= 6, BASEFEE >= 8, 0x4a >= 0x0b, 0x4b >= 0x0e).
- Analysis was complete for the listed handlers: every handler's FDE extent was swept and every instruction decoded before evaluation.

## Implementation and comparison

No Rust path is part of this packet ("not yet implemented"); the reconstruction is `model()` in `tools/evm_stack_memory_opcodes_115.py`, a pure function from (stack bytes, length, pc, memory object, analysis object, host and interpreter bytes) to the complete final state. The tool evaluates the real machine code of each handler with the repository evaluator in `tools/re11_transient_storage115.py` (extended in the tool with bt, por, movmskps and sbb-immediate; the extra decode forms reuse that decoder through a same-shape stand-in opcode) and compares the final state of every case against the model: status byte, stack length, the whole 32 KiB stack region (including words above the length), pc, the 16 KiB memory buffer, borrow counter, paid words, memory length, the ordered list of expansion calls and any panic (message pointer). The memory expansion body is replaced by a stub (success up to 300 words, otherwise fixed failure code 0x30, arguments checked); panics are recorded where they are reached.

States are drawn with `random.Random` seeded by a fixed string per handler (50 per PUSH/DUP/SWAP/environment handler, 180 per JUMP/JUMPI handler, 250 per MLOAD/MSTORE/MSTORE8 handler) and mix boundary values (stack length 0, n, n+1, 0x3ff, 0x400, 0x401, 2^64-1; offsets around the paid-word boundary, near 2^64, with high limbs set; base offsets near 2^64; valid and invalid jump destinations; zero and non-zero conditions with the non-zero bit in each dword).

Negative controls (102): 31 mutants of the model run on both the first-table and the third-table handler (62), 28 single-bit corruptions of one code byte in the handler (third instruction), 10 runs of an opcode's model against another opcode's handler, one corrupted-binary hash check and one unknown-opcode model call. A mutant counts as detected when any generated state disagrees (or the mutated model cannot complete the access the machine performed). Three corruptions hit a `push` of a callee-saved register; in this harness every register holds the same filler value and the matching `pop` restores it, so the change is unobservable. They are listed as equivalent in `equivalent-mutants.tsv` and counted in `measure.json` as `equivalent`.

## Results and limitations

- 186 handlers, 279 table slots, 11,020 cases, 0 mismatches; 102 controls = 99 detected + 3 equivalent + 0 missed (`measure.json`).
- Every status code and every panic exit of MLOAD, MSTORE, MSTORE8, MSIZE and PC is reached by at least one case (see the result column of `cases.tsv`; for example MSTORE8 reaches its second panic exit once).
- The third table's handlers behave like the first tables' handlers apart from the panic message pointers noted above.
- Limits: opcode names come from table position and behaviour, not from symbols; "memory object", "analysis object" and the field offsets are inferred from usage; the stub fixes the expansion body's gas outcome (it is a separate packet); host and interpreter structs other than the touched fields are filled with random bytes; the gas accounting around dispatch, the opcode copy family, RETURN/REVERT and the call/create/storage handlers are not covered; no component gate is requested and none is implied.
- Next question: model the copy opcodes (CALLDATALOAD 0x4333e80, CALLDATACOPY 0x4333c10, CODECOPY 0x43343e0, RETURNDATACOPY 0x4334000, MCOPY 0x4333630) with their memcpy/memset helpers and the RETURN/REVERT helper 0x43354c0.
