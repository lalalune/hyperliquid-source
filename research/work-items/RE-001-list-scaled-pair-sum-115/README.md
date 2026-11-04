# RE-001: node #115 list scaled-pair sum 0x5f13090

Task: RE-001. Bounded question: what does the 111-byte function at
0x5f13090 compute over an intrusive list, given that each element
contributes through the scaled pair total at 0x5f09a50?

## Source binary and commands

- Binary: `work/hl-node-115.bin`, node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (matches `provenance/artifacts.json`, path
  `artifacts/node/115/hl-node`).
- Main excerpt, verbatim as objdump emitted it:
  `objdump -d --start-address=0x5f13090 --stop-address=0x5f130ff work/hl-node-115.bin`
- Frames: `objdump --dwarf=frames work/hl-node-115.bin`, FDE at
  .eh_frame offset `0x35903c` (length `0x48`, CIE 0, no LSDA, no
  landing pad). The excerpt file holds the whole function; no
  instruction was edited, reordered or replaced. Mnemonics such as
  `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- Regenerate with `export_excerpts.py`; check with `verify.py`
  (digest, provenance, manifest, excerpt regeneration, sampled
  instructions byte-for-byte against a fresh objdump run and the
  raw binary, frames, census, model tests).

## Semantics, stated literally

Arguments: rdi = list header, rsi and rdx = pass-through arguments
forwarded unchanged to every callee call.

List layout, as the window uses it: the header's qword at + 0x00
is the first node; each node's qword at + 0x00 is the next node;
each node's qword at + 0x10 is its payload. The list ends when a
node's next pointer equals the header address itself.

1. First node: rbx = qword at header + 0x00. If it equals the
   header, the list is empty: both accumulators are zeroed
   (0x5f130f8) and the window returns (0, 0).
2. Otherwise the header is saved (r13), the pass-through arguments
   are saved (r14 = rsi, r15 = rdx), and both accumulators start
   at 0 (r12 = scaled sum, rbp = clamped sum).
3. Loop body (0x5f130c0): rdi = qword at node + 0x10 (the payload);
   rsi and rdx are restored from r14/r15; the window calls
   0x5f09a50 (the scaled pair total mapped by the neighbouring
   packet) with (payload, rsi, rdx). That callee returns a pair:
   rax = scaled value, rdx = clamped total.
4. After the call, rbx = qword at node + 0x00 (the next node);
   the scaled sum adds rax and the clamped sum adds rdx, both in
   64-bit wrapping arithmetic (0x5f130d2, 0x5f130d5).
5. If the next node equals the header, the loop ends; otherwise
   the body repeats from step 3 with the next node.
6. Return: rax = scaled sum, rdx = clamped sum (0x5f130e1,
   0x5f130e4).

So the observable behavior is a complete pipeline, not a
fragment: a whole-list walk whose per-element contribution is
itself a complete mapped behavior (two gated virtual
contributions, clamped and scaled), with both of the callee's
return components accumulated separately across the list. The
Python model in `tools/list_scaled_pair_sum_115.py` implements
exactly steps 1-6, taking the per-element callee by contract,
and `tests/test_list_scaled_pair_sum_115.py` covers the empty
list, single and multiple nodes, pass-through forwarding, call
order, wrapping sums on both components, zero contributions and
packet checks.

## Callers / consumers

`census.py` finds 3 direct calls of 0x5f13090, no tail jumps,
no whole-file qword hit and no RELATIVE slot (see `records.json`).
Each site was confirmed as a real `e8` call in objdump output
disassembled from its containing FDE start:

- 0x5d64291 inside function 0x5d64100..0x5d6434d
- 0x5d646f2 and 0x5d64a7c inside function 0x5d643b0..0x5d64ce1

Both containing functions also call 0x5f09a50 directly. The
callers' own internals were not read this cycle, so only their
call sites are claimed, not their purposes.

## Unknowns, recorded separately from observations

- What the list elements are, and what the pass-through rsi/rdx
  arguments mean, is not established by this window alone; the
  model takes the per-element callee as a contract callable and
  forwards the arguments unchanged.
- The window never names the callee's internal gates; it only
  calls 0x5f09a50 and accumulates both of its results. The
  callee's own semantics are the neighbouring packet's claim,
  not this window's.
- List well-formedness is assumed, not guarded: a null next
  pointer would fault on the next iteration's payload load, and
  a list whose chain never reaches the header would not
  terminate. The model therefore requires a header-terminated
  chain and treats a missing terminator as an error.
- The window has no stack canary, no PLT call and no GOT load;
  its only call is the direct call to 0x5f09a50.
