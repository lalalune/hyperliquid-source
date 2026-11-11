# evm: reconstruct the node #115 EVM arithmetic, comparison and bitwise opcode handlers (0x01-0x0b, 0x10-0x1e)

This packet lets a Rust port of the HyperEVM interpreter reproduce, from node #115 bytes, what the 26 arithmetic / comparison / bitwise opcodes do to the stack (ADD MUL SUB DIV SDIV MOD SMOD ADDMOD MULMOD EXP SIGNEXTEND LT GT SLT SGT EQ ISZERO AND OR XOR NOT BYTE SHL SHR SAR and the leading-zero count at 0x1e): the exact stack/gas effect, the spec-byte gates (SHL/SHR/SAR from spec 5, 0x1e from spec 13), the three non-zero result codes (0x2c underflow, 0x2b not activated, 0x20 EXP out of gas), and the EXP gas rule (per exponent byte, price read through host+0x250 then +0x18, charged after one word was already popped).  All 52 handler bodies of the two live opcode-table families were executed as real machine code on 10,240 inputs and agree with one pure-Python reconstruction on every case.

- Component ID: evm
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: repository main at the time of writing; no reference-source text was copied (the reference tree was not consulted for behaviour)
- Claim status: observation (handler bytes, table slots, executed behaviour) with explicitly marked inference (fork names for spec bytes, meaning of host+0x250)
- Scope included and excluded: handlers of opcodes 0x01-0x0b and 0x10-0x1e in the RELATIVE opcode tables 0x6485ef8 / 0x6486c60 (family B, handlers 0x43xxxxx) and 0x649eea0 (family C, handlers 0x546xxxx); the real 256-bit division, power and helper bodies they call.  Excluded: opcode 0x00 and unassigned slots (0x0c-0x0f, 0x1f), static per-opcode gas (not charged inside these handlers), the dense-enum tables 0x64414b0 / 0x64421a0 (different slot numbering, other handlers 0x299xxxx), PUSH/DUP/SWAP/memory/storage/call opcodes (other work items).  No Rust port and no progress-gate request.

## Reproduce

Working directory: repository root, Linux x86-64, Python 3 standard library only, no binutils, the binary is never executed.

```
python3 tools/evm_arith_opcodes_115.py --out research/work-items/evm-arith-opcodes-115
python3 -m unittest tests.test_evm_arith_opcodes_115
(cd research/work-items/evm-arith-opcodes-115 && sha256sum -c MANIFEST.sha256)
```

The tool first checks the SHA-256 of the binary, reads relocations, FDE extents, code bytes and the dynamic symbol table directly from the ELF bytes (`tools/elf_index.py`, `tools/fde_extents.py`, and the evaluator already used by `tools/re11_transient_storage115.py`), and writes every file listed below deterministically.  One generation takes about 2.5 minutes and below 400 MB.

## Evidence

Coordinates are virtual addresses of the loaded image.  Table slot = table + 8 * opcode (RELATIVE relocations).

- `handlers.tsv`: for each (family, opcode) the table slot(s), handler entry, FDE end, byte length, stack arity, the spec-gate immediate found by decoding `cmp byte [rdi+0x1a9], imm`, the `mov al, imm` result codes found in the body, the first stack-depth compare, direct/GOT call targets and the SHA-256 of the body.  The two family-B tables hold the same handler at all 26 slots; family C is a separate compile of the same behaviour: 21 of its 26 handlers have the same byte length as the family-B handler, while ADDMOD, MULMOD, EXP, SDIV and SMOD are larger there (for example SDIV 536 against 134 bytes), and both families pass the same cases.
- Calling convention: `rdi` = interpreter (stack base +0x28, stack length +0x30, gas +0x188, spec byte +0x1a9), `rsi` = host (EXP only: `[rsi+0x250]` is a table whose qword at +0x18 is the gas price per exponent byte); result code in `al`.  Binary operations shorten the stack by one and overwrite the new top, ternary ones shorten it by two, ISZERO/NOT/CLZ rewrite the top in place (observed through the byte-exact stack comparison).  The spec-gate test comes before the underflow test, and EXP stores the shortened length before the gas test.
- Callees reached with real code: 0x144dde0 (256-bit division with remainder, used by DIV/MOD/SDIV/SMOD/ADDMOD/MULMOD), 0x43bec00 (modular power for EXP), 0x4331b10, 0x43be000, 0x43bfc80, 0x43c1f50.  Their `memcpy`/`memset` imports are replaced by byte-exact stubs recognised by dynamic symbol name.
- `cases.tsv` (10,240 cases): per case family, opcode, spec byte, stack length, gas, EXP price, the top three words (large words are shown as short hashes), outcome class, result of the machine code (return code, stack length, remaining gas, result word) and whether the reconstruction matched.  The expected stack region, interpreter region, host and price table are compared byte for byte, and the callee-saved registers and rsp must be preserved.
- `outcome-classes.tsv`: counts per opcode and outcome (ok / underflow / not-activated / out-of-gas).
- `summary.json`: per-function executed/total instruction counts for all 60 functions the cases reach; `unexecuted-ranges.tsv` lists the instruction runs the cases did not execute (almost all of them are in the three large helper bodies 0x144dde0, 0x43bfc80 and 0x43c1f50: rarely taken normalisation branches).
- `negative-controls.tsv`, `measure.json`.

Analysis was complete for the 52 handler extents (every byte of every FDE decodes; padding is `int3`) and limited to the executed paths for the callees.

## Implementation and comparison

Not yet implemented in Rust; the reconstruction is `apply_op` / `model` in `tools/evm_arith_opcodes_115.py` (EVM semantics: wrap-around add/sub/mul, division by zero gives zero, SDIV -2^255 / -1 = -2^255, SMOD takes the sign of the dividend, ADDMOD/MULMOD use unbounded intermediates, SIGNEXTEND index >= 31 is the identity, BYTE index >= 32 is zero, shifts >= 256 give zero (SAR the sign mask), 0x1e returns 256 - bit_length) plus the gas/gate/underflow order described above.

Comparison method: a concrete x86-64 evaluator (the one from `re11_transient_storage115.py`, extended in the tool with imul, por/pxor/movmskps/punpcklqdq/orps/andps/andnps, bsr/lzcnt, shrd/shld, 64-bit div, bt/bts, neg r/m8, signed jcc and movq) runs each handler on the same inputs; any unsupported instruction is an error, never a pass.

- Cases: 10,240 = 200 per (family, opcode) except 120 for EXP, deterministic SHA-512 streams.  They are edge-biased: operand pools (0, 1, 2^64 +- 1, 2^255 +- 1, 2^256 - 1), shift counts around 63/64/127/128/255/256, BYTE and SIGNEXTEND indexes around 30..33 and 255/256, moduli 0/1/max, equal operands, the SDIV overflow pair, whole-limb values with random leading zeros, stack lengths below / at / above the arity, spec bytes around each gate, EXP gas at cost -1 / cost / cost +1, EXP prices 0, 1, 10, 50, 2^60 and 2^64 - 1 (the last two overflow the cost multiplication).
- Mismatches: 0 of 10,240.
- Negative controls: 193 made, 193 detected, 0 equivalent.  26 reconstruction mutants (wrong wrap, SDIV special case, SMOD sign, ADDMOD/MULMOD truncation, EXP cost variants, SIGNEXTEND and BYTE index limits, SAR variants, gate thresholds, ISZERO arity, operand swap, ...), 164 single-byte code mutants derived from the decoded handlers (result codes, spec gate +-1, stack-depth compare +-1; each is run only on the cases of the mutated handler), a flipped `.text` byte (input digest refused), an address past `.text`, and the SUB slot pointed at the ADD handler.
- Tests: `tests/test_evm_arith_opcodes_115.py`, 17 tests (digest, table agreement, model edges, real-code runs of ADD/DIV/SDIV/MOD/SMOD/EXP/shifts/CLZ, mutant detection, an unsupported instruction raising).

## Results and limitations

- 10,240 cases, 0 mismatches, 193/193 negative controls detected, 52 handlers, 60 functions executed; generation about 150 s and below 400 MB on the authoring machine.
- Inference, not proven: spec bytes 5 and 13 are the gates for the shift opcodes and for the leading-zero count (their meaning as named forks is not established here); host+0x250 -> +0x18 is the EXP gas price per byte (only its use is observed).
- Not covered: the rarely taken normalisation branches of the three large division helpers (see `unexecuted-ranges.tsv`), opcode slots 0x00, 0x0c-0x0f, 0x1f, and the dense-enum tables.  No gate is requested.

Next question: the same treatment for the dense-enum tables 0x64414b0 / 0x64421a0 (handlers 0x299xxxx), to tie their slot numbering to the EVM opcode numbering and compare their arithmetic handlers with these.
