# action-wire: choice/weight struct writers, node #115

Component: `action-wire`. This answers the explicit next question in
`action-wire-gov-vote-codec-115`; that packet covered unit-enum names and left
these three enclosing struct serializers outside scope. It does not claim a
consensus gate or a reconstructed integer writer.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Independent static analysis;
no reference implementation, captured-instruction execution or live traffic.

## Observations

Three actual FDE ranges are `0x241cb90..0x241cfa8`, `0x3c31a70..0x3c31e88`, and
`0x4d974e0..0x4d978f8`. Each has 1,048 bytes and 265 decoded instructions.
The exports retain complete bytes, FDE/CIE records, all direct calls and branch
targets. Every non-call byte and instruction offset is identical across all
three bodies; the only normalization masks the four rel32 bytes of each CALL.
This establishes local clone structure, not equivalence of their callees.

For the first body, entry RDI is the output record, RSI the source record and
RDX the buffer descriptor. The buffer has capacity at +0, storage at +8,
length at +0x10 and a mode byte at +0x1b. Source qword +0 goes to the weight
callee and source byte +8 selects a choice. The exact relevant instructions
are pinned in `spec.json` and listed in `disassembly.txt`.

- At `0x241cb9d..0x241cbbe`, the emitted header is the low byte of
  `((mode XOR 1) << 4) OR 0x82`. Mode 0 gives `0x92` (two-element array),
  mode 1 gives `0x82` (two-entry map).
- `0x241cbcd` tests mode against zero. Any nonzero mode writes
  `a6 63 68 6f 69 63 65` (the fixstr `choice`).
- The chain at `0x241cc0d..0x241cc14` maps choice 0 to `a3 yes`, 1 to
  `a2 no`, and every other byte to `a7 abstain`. The latter is observed
  fallback behavior, not validation of unknown enum discriminants.
- `0x241cc50`, `0x241cc9a` and `0x241cce1` test mode against exactly 1.
  Only that value emits `a6 77 65 69 67 68 74` (`weight`). Thus mode 2
  cannot be treated as ordinary map mode: its header is `0xb2`, it includes
  `choice`, and it omits the `weight` key.
- `0x241cd21..0x241cd2f` loads the source qword and calls `0x25e9f10`
  with RDI pointing to stack result storage, RSI the buffer and RDX that qword.
  The corresponding calls in the clones target `0x3d51450` and `0x57cfd20`.
- Stack result qword 2 produces output qword `0x8000000000000004`.
  Other values produce `0x8000000000000000` and copy the two stack result
  words to output +8/+0x10. Payload slots are not written on the qword-2 arm.
  Semantic success/error names are left to the integer-writer contract.

There are eleven other calls per body, to `0x231e050`, `0x43bd910` and
`0x5963a10`, respectively. Their local setup passes required growth lengths
1, 2, 3, 6 or 7 with alignment arguments 1, then reloads buffer fields and
rejoins the corresponding store. Calling these reserve helpers is an inference;
their allocation/failure behavior is not recovered here.

## Reproduction and limits

With Python, Capstone 5.0.6 and pyelftools 0.32 installed:

```sh
python3 research/work-items/action-wire-vote-choice-weight-struct-115/verify.py
```

`--write` regenerates the two exports. Full target identity is checked first.
The extractor requires actual FDE extents, complete linear decoding, exact
instruction pins and internal direct-branch instruction boundaries. Eighteen
operand/branch-byte mutations are rejected with the full-image digest guard
disabled, so the controls reach the operand checks.

The independent conditional model checks all 65,536 byte-mode/choice pairs,
five result discriminants and clone equality under the stated mask. It does
not execute the target or prove all paths feasible. Buffer capacity/length
validity, successful helper returns, stable source/buffer objects and sufficient
storage are assumptions of the normal-return interpretation. Aliasing,
allocation, unwinding, integer encodings and whole-component behavior remain
open. No progress gate changes.

Next question: recover the qword weight writers' width-selection, byte order,
reserve contracts and result representation; then join them to this prefix.
