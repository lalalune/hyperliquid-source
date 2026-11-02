# RE-001: BlockCache chain lookup at 0x514e550 (node #94)

Bounded question: what does node #94 function 0x514e550 do with its
outer argument — which fixed key does it search, how do its eight
inline chain trials and its walker delegation decide the result, and
which callers consume it?

## Composed rule

- Head = [[outer + 0x788] + 0x620]; the head is dereferenced without
  a null check.
- Key = the stack string `BlockCache` (10 bytes, SSO: pointer
  rsp + 0x10, length 10, NUL at rsp + 0x1a).
- For trial 1..8 over nodes n0..n7: handler = [vtable(n) + 0x38]; if
  the handler differs from the sentinel 0x4f8da10, the handler is
  called with (node, key) and its return value is the result.
- Otherwise the helper 0x52f5290 is tried on (node, key): it scans the
  node's 48-byte records from [node + 0x8] to [node + 0x10), matching
  the record key string by length then bytes, and returns the matching
  record's +0x20 first qword, or 0 on a miss. A nonzero hit is the
  result.
- On a helper miss before the eighth trial, the walk steps to the
  next node via vtable slot +0x88; a null next node returns 0.
- On a helper miss at the eighth trial, the window delegates to the
  walker 0x514ba10 with the current node; the walker steps to the
  next node first and repeats the same handler/helper rule without
  bound, returning 0 when it reaches a null node.
- Every return path disposes the stack key string (`_M_dispose`, a
  no-op for this SSO string) and checks the stack canary at
  rsp + 0x28 (`__stack_chk_fail` on mismatch). The landing-pad entry
  at 0x514e7ca disposes the same string and resumes unwinding.

This item fills the gap the RE-001-chain-walk-dispatch-94 packet left
open explicitly: that packet bound the walker 0x514ba10, the helper
0x52f5290 and the sentinel 0x4f8da10, and recorded that "the enclosing
0x514e550 function's own iterations are not modelled". The walker,
helper and sentinel are cited here as callees only, not re-claimed;
the new claim is the enclosing window's own eight trials, its
delegation, its key, and its four callers.

## Callers (consumers only)

Direct-call census over the whole .text (plus a tail-jump scan and a
whole-file qword scan, both empty): exactly four call sites —
0x514e7e8 (enclosing 0x514e7e0..0x514e864, excerpted as
caller.objdump.txt), 0x514e878 (enclosing 0x514e870..0x514e8f4),
0x514e908 (enclosing 0x514e900..0x514e994) and 0x515336c (enclosing
0x5152f10..0x515348e). Their wider semantics are not modelled here.

## Evidence notes

- The raw disassembly excerpts in this packet are verbatim objdump
  output for whole functions (plus int3 padding to the next FDE),
  produced by `export_excerpts.py --binary work/hl-node-94.bin`.
  Instruction text such as `endbr64` in those excerpts is genuine
  instruction text present in the target binary, not a placeholder.
- The packet JSON (`records.json`) carries semantic records only —
  branch site/target pairs, carve ranges with SHA-256, caller/key
  domains and record layouts. Instruction-level detail lives only in
  the raw excerpt text files.
- Target binding: node #94 binary, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), size 91774280. Work copy
  `work/hl-node-94.bin` verified against that digest.
- Run the checker with
  `python3 research/work-items/RE-001-blockcache-chain-lookup-94/verify.py --binary work/hl-node-94.bin`.
- Environment limits: this VM has no cargo/rustc, no git-lfs and no
  Ghidra/Java, so no Rust reconstruction or live execution of the
  target is claimed; the model is validated against the binary bytes
  and the packet checker, not by running the node.

## Unknowns

- The source-level identity of the outer object, the chain nodes, the
  handlers and the record payloads.
- What a handler result or a helper hit means to the four callers;
  both are returned verbatim, not interpreted.
- The behavior when the head node is null: the binary dereferences it
  without a guard, so no return value is claimed for that case.
