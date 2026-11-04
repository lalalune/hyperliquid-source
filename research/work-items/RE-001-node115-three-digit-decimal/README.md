# RE-001: node #115 three-digit decimal value

- Component: function map; serialization/byte parsing lead. Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no source or reference implementation is attributed. All new code is independently authored under the repository MIT license.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. All addresses below are ELF virtual addresses unless marked file offsets.
- Bounded question: what value does the previously unbound function at `0x179b360` compute from its pointer and length inputs?

**Answer.** For a valid readable input when length is 3, the function returns the integer represented by the three ASCII bytes exactly when the first byte is `1` through `9` and the remaining bytes are `0` through `9`; otherwise it returns zero. For any other length it returns zero without reading the pointer. Valid results are therefore 100 through 999, so zero is unambiguous for this local rule. The inputs are the values in RDI and RSI and the result is in EAX; no source-level type or original name is assumed.

## Scope and evidence

The complete unwind range is `[0x179b360, 0x179b3b5)`, file offset `0x179a360`. The FDE is at ELF VA and file offset `0xcd0138`, names CIE `0xca6ed8` (`zR`, pcrel sdata4), and has no LSDA. The body has two returns; neither control-flow path exits the window. Following the FDE extent are the recorded `0xcc` bytes; no code or fallthrough is asserted beyond that padding. The full bytes, SHA-256, CIE/FDE bytes, section coordinates and every instruction in address order are in [records.json](records.json). Instruction descriptions are decoded by strict, exact Python opcode forms, including signed branch displacements, with no external disassembler or normalization masks. The body has no calls, tail calls or indirect dispatch: no callee behavior is required for the rule.

The following counts are generated from the JSON and checked against it by the targeted test:

<!-- counts:start -->
| Metric | Count |
| --- | ---: |
| function_bytes | 85 |
| instructions | 30 |
| return_count | 2 |
| callee_count | 0 |
| rel32_candidates | 1 |
| confirmed_direct_callers | 1 |
| padding_bytes | 11 |
<!-- counts:end -->

The scan considers every byte position in the whole `.text` interval `[0x1419300, 0x63f0a00)` for `e8` and `e9` followed by a signed rel32 displacement resolving to the entry. This is a complete **byte-pattern candidate** census, not a proof of all instruction boundaries or of indirect references. The only candidate, `call` at `0x17989a6`, is confirmed by its exact instruction and adjacent decoded test, conditional branch and stores; its enclosing FDE is `[0x17985c0, 0x1798ad5)`, at `0x108281c`, CIE `0x103d604`, LSDA `0x19fe58`. The call is followed by `test ax,ax`, with zero branching to `0x179869d`; on the immediate nonzero path the caller stores AX and a raw byte 7. This local use does not establish the enclosing function's full behavior or input ownership. The census cannot rule out indirect calls, pointers or code outside `.text`.

## Instruction walk and rule

The exact per-instruction address, bytes and decoding are retained in `records.json` under `function.instructions`. The control-flow and value proof is:

- `0x179b360` compares RSI to 3; the unequal edge goes straight to `xor eax,eax; ret` at `0x179b396`. The equal edge loads all three bytes from RDI, including on invalid byte values.
- `0x179b36d` and `0x179b373` subtract ASCII `0` in 8-bit arithmetic from the second and third bytes. Their unsigned comparisons with 10 reject values outside `0` through `9`, including wraparound values below `0`.
- `0x179b376` computes the low byte of first-byte minus 58. `cmp sil,247; setb sil` marks invalid values: `(first-58) mod 256 >= 247` exactly for ASCII `1` through `9`. The OR of the three invalid flags selects the zero-return block when any is set.
- On the valid edge, byte zero is reduced by ASCII `0`, widened and multiplied by 100; byte one is widened, doubled, multiplied by 5 and narrowed to 8 bits. Its product is at most 90, so the narrowing loses nothing. Byte two is widened and the terms are added. The result is 100 through 999, with no overflow. Both RETs are covered by the recorded instruction walk.

This is an all-input arithmetic argument from the selected instructions, not captured-binary execution. Valid readable memory is required for length 3; faults, invalid pointers and concurrency are outside the rule. No first-party source-path association, original Rust signature, wire protocol, implementation equivalence, complete caller behavior, source build, whole-node coverage, or completion gate is claimed. No imported code, component gate, or catalogue was changed. No captured executable was run.

## Novelty and reproduction

Before selecting this function, the following search produced **no matches** in any listed location; there are no bound callees to check:

```sh
rg -i -n '179b360|24752992' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

From the repository root, with the materialized authenticated artifact and Python 3.10+ (stdlib only):

```sh
python3 tools/node115_three_digit_decimal.py --out research/work-items/RE-001-node115-three-digit-decimal/
python3 -m unittest tests.test_node115_three_digit_decimal -v
python3 research/work-items/RE-001-node115-three-digit-decimal/verify.py
make verify
make catalogue-check
```

The producer checks the full target digest before decoding or writing output, checks ELF mapping, FDE/CIE, padding, exact instruction encodings, direct call target and the full-text candidate census, then regenerates the JSON and manifest byte-identically. It uses a read-only memory map rather than an extra full binary copy. Tests include wrong digest, actual instruction/branch changes, shifted FDE, changed direct-call target, boundaries and all valid triples. The independent high-level model is a statement of the extracted relation, not an execution oracle. These tests do not establish full-node equivalence or run the target. Static scouting used GNU objdump 2.44; it is not a dependency of generation or verification. `make doctor` and initial `make verify` passed locally. Python version observed: 3.13.5, Linux x86-64.

Before this packet, this address had no retained research binding found by the required search. After it, the input/output rule and local call site are bound to the authenticated capture; no Rust implementation or compiled-byte comparison has been made. Next, identify the enclosing caller's source association and trace the value's later use before assigning protocol meaning.
