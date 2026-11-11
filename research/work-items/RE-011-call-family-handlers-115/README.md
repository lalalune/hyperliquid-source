# RE-011: node #115 CALL, CALLCODE, DELEGATECALL and STATICCALL handlers and their range helper, rebuilt and run against the machine code

This packet lets a reimplementation of the HyperEVM interpreter reproduce, from stack words and interpreter fields alone, what the eight CALL-family handler bodies of node #115 do: which status each early exit returns, how the gas word, 160-bit target address and value are decoded, how the shared range helper `0x29998f0` turns four stack words into two checked memory ranges (with the +0x18 input shift, the all-ones empty-range sentinel, the grow requests and the overflow panic), what is passed to the account host, and byte-for-byte what 0xd0-byte call record is boxed and installed as the pending action (including which of its bytes are never written).  A pure-Python model is checked against the real machine code of all eight bodies and the helper on 10,400 generated cases with 0 mismatches, and 55/55 wrong reconstructions, corrupted code bytes and bad inputs are rejected.

- Component ID: `evm` (task row RE-011; the alternate-host handoff of these handlers was mapped, not reconstructed, in RE-021-call-host-115 and RE-021-callframe-input-115).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Source commit / reference commit: repository commit `0781ce04826eeefd89fe336cb8ea073be0c1de30`; the reference tree `references/can1357-hl` was used only to look for names and no code was copied.  Earlier #94 observations were not reused.
- Claim status: relocations, FDE extents, opcode table entries, instruction bytes and the executed behaviour of the real code on the generated inputs are observations.  The field names ("gas", "value", "pending action", "frame scheme"), the meaning of the status bytes and the call-record roles are inferences.  The behaviour of the account host (both targets are stubbed, with their arguments recorded), the grow routine at `0x45244c0`, the allocator and the destructors of a previous pending action are unresolved boundaries.
- Scope included and excluded: handlers `0x299a8f0 0x299b050` (CALL, alternate and ordinary table), `0x299aca0 0x299a1d0` (CALLCODE), `0x299a580 0x2999b00` (DELEGATECALL), `0x299b400 0x2999e70` (STATICCALL) and the shared helper `0x29998f0`.  Excluded: the two host bodies, the grow routine, allocation internals, the driver that selects a table, gas accounting inside the host, and any live state.  No component gate is requested.

## Reproduce

From the repository root with the authenticated node #115 artifact present:

```sh
python3 tools/re11_call_family115.py --out research/work-items/RE-011-call-family-handlers-115
python3 -m unittest tests.test_re11_call_family115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For an independent regeneration run the tool twice into two empty directories with different `PYTHONHASHSEED` and `TZ` values and compare them with `diff -r`; the tool and tests use only the standard library plus `tools/elf_index.py` and `tools/fde_extents.py`, never call a program, never execute the node and never touch the network.  The tool checks the input SHA-256 first and rejects any other file.  Peak resident memory is below 1.5 GB because every case is generated, run and compared one at a time and only counters are kept.  `MANIFEST.sha256` covers every other file in this folder.

## Evidence

Coordinates are ELF virtual addresses before load bias.

| Body VA | Role | Instructions | Executed by the cases |
| --- | --- | ---: | ---: |
| `0x29998f0` | range helper | 135 | 135 |
| `0x2999b00` | DELEGATECALL, ordinary | 176 | 157 |
| `0x2999e70` | STATICCALL, ordinary | 173 | 154 |
| `0x299a1d0` | CALLCODE, ordinary | 187 | 168 |
| `0x299a580` | DELEGATECALL, alternate | 176 | 157 |
| `0x299a8f0` | CALL, alternate table | 185 | 166 |
| `0x299aca0` | CALLCODE, alternate | 187 | 168 |
| `0x299b050` | CALL, ordinary table | 185 | 166 |
| `0x299b400` | STATICCALL, alternate | 173 | 154 |

(The unexecuted instructions are unwinding landing pads and the code after the non-returning allocation-failure and panic calls; `coverage.tsv` lists them as address runs.)

- `constants.json`: FDE extents and SHA-256 of all nine bodies, every direct call, every indirect call with its GOT slot and the relocated target, the eight opcode-table entries read from the RELATIVE relocations of the tables `0x6441210` (alternate) and `0x6441f00` (ordinary), and the interpreter offsets the tool uses.  Each ordinary body is instruction-for-instruction the same as its alternate twin once branch and call displacements are masked, and the only indirect call that differs is GOT `0x64e6e08` (relocated to `0x546c330`) against `0x64e6e00` (relocated to `0x4335cf0`).
- `decoded-instructions.tsv`: every instruction of the nine bodies with its bytes and whether any case executed it.
- `frame-layout.tsv`: the 0xd0-byte call record, offset by offset, with the source of each field.
- `hole-check.json`: the record is run under two different stack fills; exactly the bytes `0x68..0x6f` and `0xcf` change, so those bytes are stack garbage (the compiler never stores them) and are masked in the comparison.

### What the handlers do (inferences checked by execution)

1. DELEGATECALL returns `0x2b` when interpreter +`0x1a9` is 0 and STATICCALL when it is at most 3, before the stack is read.  A stack with fewer words than the handler pops (3 for CALL/CALLCODE, 2 for the others) returns `0x2c` and leaves the length alone.
2. The top word is gas: its low 64 bits if the three upper limbs are zero, otherwise `2^64-1`.  The next word is the target: the low 160 bits as 20 big-endian bytes.  CALL and CALLCODE pop a third word, the value, and only its zero-ness (all 256 bits) is used for the host flag; CALL alone returns `0x27` when bit 0 of +`0x1a8` is set and the value is nonzero (the three words stay popped).
3. The helper needs four more words (`0x2c` otherwise, without a change of length), always pops them, and returns status `0x24` for a length with a nonzero upper limb or an offset with one when the length is nonzero.  A zero length gives the sentinel `2^64-1` for both ends.  Otherwise the end is saturated, `ceil(end/32)` words are compared with the +`0x170` memory size, and a larger request calls the grow routine whose nonzero return is the status.  If offset+length overflows 64 bits after a successful grow the helper panics.  The input range is shifted by +`0x18` (saturating); the output range is not.
4. The host is called with the 20 address bytes, a flag equal to value-nonzero (CALL, CALLCODE only), a second flag (1 for CALL, 0 otherwise) and the gas.  Discriminator 2 in the result returns the first result byte as the status.
5. Otherwise the record (`frame-layout.tsv`) is built and copied into a 0xd0-byte allocation (a null allocation goes to the allocation-failure handler).  The previous pending action is dropped by +`0x110`: `0x38` means none, `0` means a shared owner when the low 32 bits of +`0xb8` are 1 and a boxed object otherwise, anything else calls a destructor through the vtable in +`0xb8`.  Then +`0x149` = 0, +`0xb8` = 1, +`0xc0` = the box, +`0x110` = 0 and the status is 4.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**.  The comparison is between the pure-Python model (`range_model`, `model`, `build_frame` in `tools/re11_call_family115.py`) and the real instruction bytes executed by a small concrete x86-64 evaluator that decodes only the forms present and stops with an error on any other.  Stubs: the grow routine, both host bodies, the allocator, `memcpy`, the deallocator, the shared-owner destructor, the vtable destructor, the allocation-failure handler and the overflow panic; each stub records its arguments and clobbers every caller-saved register.  A case is correct only if the return byte, the event list (grow requests, host arguments, allocation and copy sizes, destructor arguments), the whole 0x200-byte interpreter image, the 0xd0 copied bytes outside the modelled holes, callee-saved registers and the untouched host, object and stack images all agree.

Case generation is deterministic (SHA-512 streams per body) with 1300 cases per body: stack depths around every threshold, range words from small values to values with upper limbs and values that overflow, memory sizes and shifts around the limits, previous pending actions of every kind, host results of every discriminator, grow results with errors, and allocation failure.

| Outcome class | Cases |
| --- | ---: |
| action-queued | 1477 |
| host-error | 300 |
| not-activated | 1508 |
| panic-alloc-error | 39 |
| panic-overflow | 1791 |
| range-too-large | 2315 |
| stack-underflow | 1495 |
| static-with-value | 956 |
| status-0x20 | 171 |
| status-0x21 | 168 |
| status-0x7f | 180 |

Negative controls: 24 model mutants (wrong address encoding, missing shift, swapped schemes, dropped destructor, saturating instead of panicking, and so on), 28 corrupted code bytes (immediates and displacements in the handlers and in the helper) and 3 bad inputs (a flipped `.text` byte, an address past `.text`, an unknown family).  All 55 of 55 are detected.

## Results and limitations

- 10,400 cases, 0 mismatches, hole check match = True, 55/55 negative controls detected (`measure.json`).
- Everything outside the nine bodies is a stub, so nothing here says how the host prices a call or what the grow routine charges; the grow stub returns a chosen status and does not change the memory size, so two requests in one call are both measured against the starting size (the model does the same).
- The generated inputs are synthetic: no live bytecode, state or provider was used.  Rare paths (a vtable destructor on a boxed object) are reached by constructing the interpreter image, not by observing one.
- The uncovered instructions are unwinding pads and the code after non-returning calls; they were not executed.
- No gate is requested.  Next question: reconstruct the alternate account host `0x546c330` and the ordinary host `0x4335cf0` that these handlers call, starting from the record this packet builds.
