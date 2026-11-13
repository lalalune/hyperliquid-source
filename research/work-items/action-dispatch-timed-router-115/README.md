# action-dispatch: reconstruct the node #115 timed action router at 0x55f99b0

The timed action router `0x55f99b0` of node #115 can now be rebuilt as an executable model in which a variant tag word picks one of 92 jump-table arms (`tag - 0x86`, tags below `0x86` taking arm 20), the arms fall into 17 argument shapes, a feature-flag gate decides whether a latency timer wraps the call, an ok/error fold turns each arm's result into a 128-byte slot, and one arm (52) re-enters the router; the model agrees with the router's own bytes, run through an x86-64 interpreter with every external callee stubbed, on 10,260 cases (36,702 recorded calls), and all 60 negative controls are either detected (59) or a documented equivalent mutant (1).

- Component ID: `action-dispatch` (task: validate each handler seed against #115; this packet covers the central dispatch function that calls the handlers).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: repository `a8616af9432b8d8517b2af677880e117b7c28ef3` (workspace `main` at the time of the run); no external source was copied. The interpreter core is the repository-independent x86-64 skeleton that other merged tools already carry, copied into the tool.
- Claim status: static, byte-grounded reconstruction of one function (the indexed FDE `0x55f99b0..0x55faa79`, 4,297 bytes) and its 92 arm bodies up to their direct or indirect call; observations and inferences are separated below. The handlers are stubbed and not reconstructed here.
- Scope: prologue, gate, timer start, tag-to-index computation, jump table at `0x927b08`, the 17 arm shapes, the shared joins at `0x55fa7f8` and `0x55fa862`, the error-word arms, the recursive arm, timer end and record, result copy, register restore. Excluded: handler bodies (see `arms.tsv` for their addresses), the clock helper `0x5c842e0` and record helper `0x5c84210` internals, the targets of the four indirect slots, the decoder that produces the tag word, the landing pad at `0x55faa5e` (never reached by a call that returns normally), and any native execution of the binary.

## Reproduce

From the repository root with Python 3.10 or newer (run with 3.12.3) and the authenticated target:

```sh
python3 tools/action_timed_router_115.py --out research/work-items/action-dispatch-timed-router-115
python3 -m unittest tests.test_action_timed_router_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The tool checks the input digest first, reads file-backed ELF sections through `tools/elf_index.py` and `tools/fde_extents.py`, and uses no other program. `MANIFEST.sha256` hashes every other file in this folder. Generation is deterministic (no clock, randomness, path or dict order reaches the output; the case generator is a fixed-seed integer recurrence plus SHAKE-128 fill) and takes about ten seconds. Investigative disassembly used GNU objdump; neither its output nor its formatting is an input to the tool or the tests.

## Evidence

All addresses are virtual addresses of node #115. Observations, each exercised by the interpreter:

1. Entry: `rdi` is the out pointer (returned in `rax`), `rsi` the context (kept in `r15`), `dl` a force-gate byte, `cl` the variant index byte, `r8` the pointer to the tag word (kept in `r12`), `r9` a pointer to a 20-byte descriptor (kept in `r13`). The frame is `0x118` bytes below six saved registers.
2. Gate: when `dl != 0`, or `cl <= 14` and bit `cl` of `0x501d` is set, the code calls the slot at `0x64e1028` with `edi = 0x32`. A zero result skips the timer: `ebp` is loaded with the sentinel `0x3b9aca00` (1,000,000,000). In every other case the gate is not consulted and the timer runs. Timer start is `edi = 1`, call `0x5c842e0`, `r14` = seconds, `ebp` = nanoseconds.
3. Dispatch: the tag word is loaded from `r8`; `tag - 0x86` is the index when `tag >= 0x86`, otherwise `20` (a `cmovae` after `sub`). The 4-byte relative table at `0x927b08` has 92 usable entries. The 93rd dword resolves to `0x55fa98b`, which is not an instruction start of the linearly decoded function (it lands inside the `lea` of the arm at `0x55fa975`), so the table ends at 92 entries; `summary.json` records this check.
4. Arm shapes (`shapes.tsv`, `arms.tsv`). 52 arms copy the 20-byte descriptor to `[rsp]` and call a handler with `(rsp+0x70, tag+8, rsp, ctx)`; 21 pass `(rsp+0x70, tag+8, desc, ctx)`; 3 call with `(rsp, ctx, desc, tag+8)` and fold through the join at `0x55fa7f8`; 2 (arms 20, 72) copy the descriptor but do not advance the tag pointer; 2 (arms 47, 74) copy the descriptor to `[rsp+0xf0]`. Twelve arms are singletons: 0 (stores ok tag `0xe` only), 5 (no fourth argument), 16 and 41 (two indirect slots, `0x64e7868` and `0x64e6a70`, with ctx offsets `0x3f08`, `0xba0` and the byte at `0xb9a`), 43 (copies a 22-byte window of the tag payload to the stack), 52 (re-enters `0x55f99b0`), 61 (rejects payload word `[tag+0x28] >= 0xccccccccccccccc` with word `0x154`), 62 and 91 (pass the payload word at `+0x28` / `+8` as fourth argument), 63 and 64 (ctx byte `0xb9a == 3` yields word `0x91`; arm 63 otherwise calls the slot `0x64e7870`), 75 (ctx byte `0x42ad == 0` yields word `0x92`).
5. Join `0x55fa7f8`: when the 16-bit word at `[rsp]` equals `0x1a2` the slot byte 0 becomes `0xe`; otherwise 0x70 bytes from `[rsp]` are copied to slot offset `0x10` and byte 0 becomes `0xf`. Error arms write their 16-bit word at slot offset `0x10` and byte 0 `0xf` directly.
6. Arm 52: loads the inner tag pointer from `[tag+0x20]`, computes `cl' = (inner_tag + 0x7a) & 0xff` (or 20 below the base) and calls `0x55f99b0` with `rdx = 0`, so the nested activation consults the gate only through `cl'`; the nested result lands directly in the outer slot.
7. Epilogue `0x55fa862`: when `ebp` is not the sentinel the code calls `0x5c842e0` again, stores the end pair at `[rsp+0x108]` and the start pair at `[rsp+0xf0]`, and calls `0x5c84210` with `(rsp, rsp+0x108, rsp+0xf0)`. Then the 128-byte slot at `rsp+0x70` is copied to the out pointer.
8. The landing pad at `0x55faa5e` drops the slot with `0x5620aa0` and resumes unwinding; the call at `0x55faa73` is the trailing panic path. These six instructions are the only ones in the FDE no case reaches (`coverage.tsv`, 1,007 of 1,013).

`coverage.tsv` records, per instruction, how many of the 10,260 cases reach it. `cases.tsv` keeps every third case with its call count and a result digest. `controls.tsv` lists every negative control and what detected it.

## Implementation and comparison

`tools/action_timed_router_115.py` holds three parts:

- `Model` (pure Python, no interpreter): gate, timer, index, 17 shape routines, joins, recursion, record. Inputs are the tag word, `cl`, `dl`, the flag-slot result, two clock readings, a context byte pair, payload words and the descriptor, all read from a per-case heap image. Output is the ordered call trace (target, argument values normalised to `F+off` / `H+off`, and 32-byte snapshots of every argument that points into the frame) and the 128-byte result.
- `Rig`: runs the real bytes in the interpreter (`Image`, `decode`, `Memory`, `Machine`). The 92 handlers, the clock and record helpers and the indirect slots are stubs that record their argument registers and fill the buffer they receive with a deterministic pattern whose first word is, per call, either `0x1a2` or not; the router itself is not stubbed, so arm 52 recurses through the bytes.
- Controls: 36 model mutants (constants, offsets, polarity, swapped handlers, swapped record arguments) and 24 byte-damage mutants (immediates, compare constants, `cmovae`, push, shared `add $8` sites) patched into the router bytes.

The case generator draws 110 cases per arm (tags `0x86..0xe1`) plus 140 for tags below the base, with random `cl`, `dl`, flag result, clock pairs (including a start pair equal to the sentinel), ctx bytes (`0xb9a` over 0, 1, 2, 3, 4, 255, `0x42ad` over 0, 1, 0x55), payload edges around `0xccccccccccccccc`, nested tags and ok-bit patterns. Each case is a fresh machine state; nothing is accumulated.

The 93rd table dword is not an arm: when it was first modelled as arm 92 the interpreter showed a 32-bit `lea` (truncated stack address) at `0x55fa98b`, which is how the table end was found; the check is kept in the tool and recorded in `summary.json`.

## Results and limitations

Metrics (`summary.json`, `measure.json`): 10,260 cases, 0 disagreements, 36,702 recorded calls, 17 shapes, 92 arms, 1,007 of 1,013 instructions covered; 60 negative controls, 59 detected, 1 equivalent (`equivalent-mutants.tsv`: raising the gate index limit from 14 to 15 changes nothing because mask bit 15 is clear), 0 missed. The detection suite is 863 cases (every 31st case plus all cases of arms 52, 61, 63, 64, 75).

Limits: the handlers (including those covered by sibling packets) and the targets of the four indirect slots are stubbed, so nothing here says what any arm computes; the interpreter implements only the instruction forms this function and its arms use; the clock helper's real behaviour is outside scope; the tag decoder that produces the tag word is not covered, so tags `>= 0xe2` (out of table) are not modelled. The packet claims no component gate.

Next question: the dispatcher's caller, which builds the tag pointer and descriptor from a decoded action, and the sibling timed router at `0x2bda7c0` already have packets; the unreconstructed link is the exact condition under which a caller passes `dl != 0` (force gate) and how `cl` is derived at the call sites.
