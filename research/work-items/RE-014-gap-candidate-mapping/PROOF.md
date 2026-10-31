# Bounded static correspondence argument

This argument concerns two selected code intervals, not original function
identity or runtime equivalence. The input artifacts and complete comparison
denominator are recorded in README and REPORT.

1. **Admission.** Each input is read into one immutable `bytes` object. Its
   complete length and SHA-256 must equal the maintained target identity.
   Layout parsing, the full exact-body search, raw FDE/CIE reads and every
   native-view slice use this same object. A concurrent source change either
   yields the expected authenticated object or fails admission; no later
   read can substitute another target view. This does not require an atomic
   filesystem snapshot or claim that the source path stays unchanged.
2. **Coordinates and uniqueness.** The #94 start/end VAs have one file-backed
   section mapping. That offset/length must have exactly one section and one
   PT_LOAD mapping, both executable and agreeing on the linked VA. The full
   selected bytes must occur exactly once in the entire #115 bytes object.
   The located interval independently passes the same coordinate checks.
   No prefix, FDE-start heuristic, proximity or diagnostic path supplies the
   pairing. Uniqueness applies to this exact byte pattern, not all possible
   equivalent implementations or incoming callers.
3. **Raw equality.** The compared objects are the entire 1,149- and 1,269-byte
   spans. Any raw mismatch fails. No relocation, immediate, register, memory
   displacement, opcode or branch field is masked or rewritten.
4. **Native binding.** GNU decodes only owned tiny raw views at their separate
   linked addresses. Every reported instruction has the exact admitted bytes
   and contiguous address/width; the selected body is fully consumed. The
   recorded denominator is 285 plus 324 rows per target. This is trusted
   installed GNU decoding checked against bytes and independently reviewed,
   not a general proof of any arbitrary native provider's semantics.
5. **Branch-coordinate comparison.** For every Jcc/JMP, its actual rel8/rel32
   opcode determines the expected mnemonic and signed displacement. The
   destination is `instruction_start + width + signed_displacement`. The
   displayed destination must equal that result and land on a selected
   instruction start. Only then is this displayed linked destination replaced
   by `destination - candidate_start`. The encoding is still compared raw.
   All other mnemonic and scalar/memory operand strings compare exactly.
6. **Local CFG.** Successor records follow the decoded conditional/unconditional
   branch and fallthrough rules; the only accepted return form is terminal
   `C3`. Both bodies have one reachable RET, all rows reachable, nine local
   block leaders and six direct local branches. All 12 branch pairs and all
   609 complete comparison records agree. There are no CALL or RIP/EIP-relative
   operands in the selected records. Thus no linked code/data relocation is
   silently discarded by this comparison; runtime pointer values remain
   outside it. The original code may still be unreachable from program entry.
7. **Unwind separation.** All raw FDE records are parsed separately for each
   admitted artifact; no interval intersects either selected body. The raw
   preceding/following FDE and referenced CIE records remain distinct evidence
   per target. In particular, the following FDE-sized regions have different
   lengths and are not added to this correspondence. Gap census observations
   already owned by #373 are credited context, not a new denominator.

These observations establish exact byte and decoded local-coordinate
correspondence for the recorded two intervals. They do not prove that either
interval has the same source name, callers, data, CPU support, input domain,
process state or externally visible effect in both programs. Earlier #94
conditional-contract arguments are credited but are not automatically promoted
to measured #115 behavior. A separate caller/context proof would be required.
