# transport: reconstruct node #115 write-all poll shell 0x5ab3a50 and compression-gate poll shell 0x5ab6ce0

- Component ID: transport (Network transport: TCP framing, LZ4, channels, rate limits and reconnects)
- Target release and full SHA-256: node #115, 105,896,032 bytes, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main at the time of the run; no reference source was copied
- Claim status: observation (decoded bytes, jump tables, executed-instruction counts) plus inference (the names and the roles of the callees, which are modelled, not reconstructed)
- Scope included and excluded: the two complete async poll state machines `0x5ab3a50` (305 bytes, FDE-bounded) and `0x5ab6ce0` (267 bytes, FDE-bounded). Excluded: the callees `0x5cdfa50`, `0x4ece740`, `0x5ab5be0`, `0x5a59590`, the exception landing pads and the GOT-slot panic/error constructors, which are modelled as black boxes; the compressor and the wire format; any gate in `research/progress.json`.

This packet makes it possible to re-implement two transport poll shells exactly, as executable Python, and to
state their full decision tables: the write-all shell is a cursor loop that adds the payload length to a shared byte
counter on first poll, treats "no progress" as a 9-byte io-error of kind `0x25`, and parks in state 3 when the
inner writer is pending; the gate shell computes the compression-eligibility flag `n >= 0x401 AND
((field32 - 4000) mod 65536) < 65534` for a *second* monomorphisation of the sender (the first, `0x2b7a290`, was
already published by other packets) and stores it at `+0x308`. 13,500 generated cases (6,000 per function plus 1,500 landing-pad entries) match
the interpreter run over the real bytes exactly, and 47 negative controls are all detected.

## Reproduce

Run from the repository root with a standard-library Python 3 (no binutils, no network, the binary is never executed):

```
python3 tools/transport_poll_shells_115.py --out research/work-items/transport-poll-shells-115
python3 -m unittest tests.test_transport_poll_shells_115
(cd research/work-items/transport-poll-shells-115 && sha256sum -c MANIFEST.sha256)
```

The tool authenticates size and SHA-256 of `artifacts/node/115/hl-node` first, takes the function extents from the
`.eh_frame` FDEs through `tools/fde_extents.py` and the section map through `tools/elf_index.py`, and writes
`instructions.tsv`, `state-table.tsv`, `cases-sample.tsv`, `outcome-classes.tsv`, `controls.tsv`, `summary.json`
and `measure.json`. Output is byte-identical across runs (fixed xorshift seed, no clock, no paths).

## Evidence

Coordinates are ELF virtual addresses (resolved to file bytes through the section headers by the tool). Both functions end in `int3` padding up to the next unwind start (checked from bytes).

- `0x5ab3a50`, 84 instructions: prologue pushes r15, r14, r12, rbx, rax. The state byte at `+0x40` indexes a
  four-entry signed-relative jump table at `0x939fd8` (targets in `state-table.tsv`): state 0 = first poll,
  1 = "resumed after return" panic, 2 = "resumed after panic" panic, 3 = re-poll.
  First poll: `owner = *(base)`, `counter = *(owner+0x60)`, `*(counter+0x10) += *(base+0x10)` (a `lock add`), then
  `[base+0x18..0x28) = [base..base+0x10)`, `len = *(base+0x10)` stored at `+0x28` and `+0x38`, `pos = 0` at `+0x30`.
  Loop: `len < pos` -> slice-index panic (`0x64df848`, location `0x64bad88`); `len == pos` -> state 1, return
  `(0, pos)`; otherwise call `0x5cdfa50(stream=*(base+0x18), cx, &base+0x20)`. Bit 0 of the returned flag = pending
  -> state 3, return `(2, rdx)`. A non-zero error in rdx -> `0x4ece740(err)`, state 1, return `(1, converted)`.
  Zero error: re-read len/pos (slice panic again if `len < pos`); if the remaining count is unchanged the shell builds
  the constant error `GOT[0x64e0750](0x25, 0x94d48e, 9)` and converts it; otherwise it loops.
- `0x5ab6ce0`, 65 instructions, four-entry jump table at `0x93a0f8`: state 0 copies the captured arguments to
  `+0x28..+0x50`, stores `n` at `+0x48`, the eligibility flag at `+0x308` and clears `+0x309`; state 3 re-polls;
  states 1/2 panic. The inner poll `0x5ab5be0(base+0x28)` returning bit 0 set -> state 3, return `(1, rdx)`;
  otherwise the inner object is dropped (`0x5a59590`), state 1, return `(rax, rdx)` unchanged.
- Exception landing pads (`0x5ab3b5d`, `0x5ab3b69`, `0x5ab3b75`, `0x5ab6db9`, `0x5ab6dcb`) are entered directly with
  rax = exception object: each stores state byte 2 (`+0x40` / `+0x310`) and calls `_Unwind_Resume(rax)`; the last
  gate pad first drops the inner object at `base+0x28`. Which throwing call reaches which pad is not decoded from
  the LSDA. Never executed: the `ud2` after the slice-panic call and the `call *0x64df4c0` at `0x5ab6de5`, both
  after noreturn calls (count 0 in `instructions.tsv`).

## Implementation and comparison

`tools/transport_poll_shells_115.py` contains (1) a decoder and interpreter for the x86-64 subset the two bodies
use (push/pop, mov/lea/movzx/movslq, add/sub/cmp/xor/and/test, jmp/jcc, call, indirect call/jump, setcc, movups,
movsd, `lock add`), executing the real file bytes with a sparse mapped memory (unmapped access is a fault),
shared-callee black-box models and call logging, and (2) `write_all_poll` / `gate_poll`, the plain-Python
reconstruction. A case is accepted only if the interpreter and the reconstruction agree on end kind (return or
which noreturn panic), `rax`, `rdx`, every mapped memory byte, the ordered callee call log with its argument
registers, and the callee-saved/stack ABI. Generated inputs cover all four states, edge lengths and positions,
`pos > len`, wrapped cursor advances, pending/error/no-progress/progress scripts, and the gate boundaries
(`0x400/0x401`, low-16-bit field values 3998/3999, 3997/4000, high-16-bit garbage).

Negative controls (47; `controls.tsv`): 21 reconstruction mutants (wrong counter, wrong pending state, wrong error
kind/message, wrong progress test, wrong threshold/bound/width, `and` -> `or`, missing drop/clear/copy ...), 18
single-byte corruptions of the real function bytes (branch senses, immediates, displacement, state bytes, `lock add`
-> `sub`), 4 out-of-domain state bytes, 2 corrupted binaries (flipped bit, truncated), an entry off an instruction
boundary and a case with missing mapped memory.

## Results and limitations

Cases 13,500 (6,000 per function, 300 per landing pad), mismatches 0; negative controls 47, detected 47
(`measure.json`). Executed instructions: write-all 83/84, gate 64/65 (`summary.json`). Limits: the five callees and the three GOT slots are
modelled by their observable contract, so nothing here establishes what `0x5cdfa50` or `0x5ab5be0` do internally;
the names (`write-all`, `gate`) and the meaning of the `0x90` context field are inferences (the same predicate was
already observed in the sender at `0x2b7a290`); behaviour for state bytes above 3 (a jump into unrelated bytes) is
out of domain; the LSDA call-site table is not decoded. No progress gate is requested.

Next question: reconstruct `0x5ab5be0` (the inner poll that the gate shell drives) and the cursor writer `0x5cdfa50`
so the two black-box models above can be replaced by checked code.
