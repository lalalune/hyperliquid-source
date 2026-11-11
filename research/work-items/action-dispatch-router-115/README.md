# action-dispatch: reconstruct the node #115 action router at 0x2bda7c0

The action router of node #115 can now be rebuilt as an executable model: a tag word selects variant index `tag - 0x86` (tags below `0x86` all fall into the niche variant 20), six trading indices consult a feature-flag slot before a latency timer is armed, each of the 92 arms hands a stack-local 128-byte result slot to one fixed handler with one of four argument shapes (80 arms pass the tag pointer plus 8, one passes the tag pointer itself, 7 load their fourth and fifth arguments by value from the payload, 4 pass none), and the epilogue records the timer pair and copies the 128-byte result to the caller; the model agrees with the router's own bytes, run through a restricted interpreter, on 10,396 cases and 49 of 49 negative controls are detected.

- Component ID: `action-dispatch` (task: validate each handler seed against #115).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (workspace `main` at the time of the run); no external source was copied.
- Claim status: static, byte-grounded reconstruction of one function (the indexed FDE `0x2bda7c0..0x2bdb225`) and the 92 arm bodies up to their direct call; the handlers themselves are stubbed and are not reconstructed here.
- Scope: router prologue, tag-to-index computation, flag gate, timer start, jump table at `0x609f00`, the 92 arm shapes, the join at `0x2bdb167`, timer record, result copy and register restore. Excluded: handler bodies (one is covered by the existing `RE-010-display-name-path-115` packet and others by sibling packets), the clock helper `0x5c842e0` and record helper `0x5c84210` internals, the flag slot's target at `0x64e1028`, the decoder that produces the tag word, and any execution of the binary.

## Reproduce

From the repository root with Python 3.10 or newer and the authenticated target:

```sh
python3 tools/action_router_115.py --out research/work-items/action-dispatch-router-115
python3 -m unittest tests.test_action_router_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The tool checks the input digest first, reads file-backed ELF sections through `tools/elf_index.py`, and uses no other program. `MANIFEST.sha256` hashes every other file in this folder. Generation is deterministic: no clock, randomness or path appears in the output. Investigative disassembly used GNU objdump 2.42; neither its output nor its formatting is an input to the tool or the tests.

## Evidence

The router is the indexed FDE `0x2bda7c0..0x2bdb225`. Observations (every one is exercised by the interpreter):

1. The tag word is loaded from the pointer in `rcx` (`mov (%rcx),%rax`). Two computations follow. The gate computation takes `(tag + 0x7a) & 0xff` when `tag >= 0x86` and `0x14` otherwise. The table computation takes `tag - 0x86` (64-bit) when `tag >= 0x86` and `0x14` otherwise. For the 92 valid tags they agree; the 64-bit form is the jump-table index.
2. The gate: when the byte is at most `0xe` and bit `n` of `0x501d` is set, the code calls the slot at `0x64e1028` with `edi = 0x32` (50). The set bits are indices 0, 2, 3, 4, 12 and 14, which the existing name table identifies as `noop`, `batchModify`, `cancel`, `cancelByCloid`, `modify` and `order`. A zero result skips the timer: `ebp` is loaded with the sentinel `0x3b9aca00` (1,000,000,000) and `r14` is left unset. For every other index the gate is not consulted.
3. Timer start: `edi = 1`, call `0x5c842e0`, `r14 = rax` (seconds), `ebp = edx` (nanoseconds).
4. Dispatch: `movslq` of the 4-byte relative entry at `0x609f00 + 4*index`, added to the table base, indirect jump. Each of the 92 arms loads `rdi = rsp` (the local result slot), `rsi = r13`, `rdx = r12`, and calls one handler. 80 arms first execute `add $8,%r15` and pass `r15` as `rcx`; arm 20 passes `r15` unchanged; 7 arms (indices 18, 22, 28, 35, 61, 65, 78) instead load `rcx` and sometimes `r8` from the payload with `mov disp8(%r15)` in 4- or 8-byte form (offsets and sizes in `arms.tsv`); 4 arms (0, 5, 64, 72) add nothing. All arms jump to the join at `0x2bdb167`; the last arm (index 89) falls through into it. `arms.tsv` lists handler, argument shape and gate membership per index.
5. Epilogue: `cmp $0x3b9aca00,%ebp`; when unequal, call `0x5c842e0` again and call `0x5c84210` with `rsi` pointing at the new (end) pair and `rdx` at the saved start pair. Then 128 bytes are copied from the local slot to `rbx` (the caller's out pointer) and the six callee-saved registers are restored.

`coverage.tsv` records, per instruction address, how many of the 10,396 cases reach it: 707 distinct router and arm instructions in total. `cases-sample.tsv` keeps every 40th case with its call sequence. `controls.tsv` lists every negative control and whether it was detected.

## Implementation and comparison

`tools/action_router_115.py` holds three parts:

- `model()`: the reconstruction. Inputs are the tag word, the flag-slot result, the two clock readings and four pointer values; the output is the ordered call trace (flag query, timer start, handler with `rdi/rsi/rdx/rcx`, timer end, record with end and start) and the 128-byte result.
- `Emu`: an interpreter for the instruction forms present in this function (push/pop, mov, lea, movslq, cmp/sub/add with 8/32-bit immediates, cmovae, bt, movzbl, test, movaps, short and near jumps, rel32 and RIP-relative indirect calls). It stops with an error on any other opcode, any unmapped read and any call target outside the five known stubs, so a damaged byte cannot silently pass. External calls are stubs that record their arguments; handler stubs write a deterministic 128-byte pattern keyed by their address.
- Case generation and controls. 226 tags (all 134 tags below the base plus the 92 table tags) times 46 variants of flag value, clock pair and pointer set give 10,396 cases. Each runs the real bytes and the model and compares the trace, the result copy, `rsp` and the callee-saved registers.

Negative controls (49): 25 model mutants (base off by one in both directions, niche index 19 and 21, gate bound 13, gate bit 15 added, sentinel off by one, flag argument 51, inverted flag, always timed, never timed, swapped record order, skipped second clock read, two swapped handler pairs, one shifted handler, wrong argument shapes for arms 0, 20, 91 and 19, and five wrong load offsets or sizes for arms 18, 22, 28, 35 and 61), 9 mask-bit mutants (six cleared, three set), 10 byte corruptions of the image (mask immediate, gate bound, flag argument, sentinel immediate, a jump-table entry, the base subtraction, the niche immediate, an arm's `add` immediate, the join compare, a store in the record setup) and 5 out-of-domain inputs (tag just past the table, tag `2^40`, tag `2^64-1`, start nanoseconds equal to the sentinel and above it). All 49 are detected.

## Results and limitations

- 10,396 of 10,396 cases agree; 49 of 49 negative controls are detected (`measure.json`). `decode_arm` also re-derives all 92 handler targets, argument shapes and join targets from the arm bytes by fixed patterns, and the tool refuses to run if they differ from the model tables.
- Inferences, kept separate from the observations above: the six gated indices being the order-flow actions is read from the existing name table, not from this router; the stack-local 128-byte slot being an `Option`/result enum is not shown; `0x64e1028` is called a feature-flag slot only because it returns a boolean for the constant 50, and its writer is not traced; `0x5c842e0` is called a clock read because its two outputs are consumed as seconds and nanoseconds.
- The model leaves the behaviour for tags `>= 0x86 + 92` undefined; the jump table has no bound check in the router, so those inputs are outside the domain (a control rejects them). For tags above `0x86 + 255` the gate byte and the table index disagree; this is not exercised.
- Handlers, the decode that produces the tag word and the clock helper are unresolved; this packet does not advance any component gate.

## Next question

Check which handler entries share the display-name handler's leading key-check shape and, where they do, model that shared admission prologue against all of them with the same interpreter.
