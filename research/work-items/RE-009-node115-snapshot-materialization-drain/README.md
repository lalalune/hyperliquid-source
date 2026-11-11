# RE-009 · Snapshot materialization continuation

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The loader handoff packet records the contextual call at `0x3c12946`. This candidate verifies callee body `[0x420b900,0x420b9be)`. The caller passes its R12-relative subobject at +0xed8.

When the callee's object word +0x40 is nonzero, it requires a nonzero word +0x30 before calling `0x3926e50` with the +0x30/+0x38 pair and a stack output. Otherwise, for a zero +0x40, it clears only the output words at stack offsets 0 and 0x10 in that region. It passes the local region to `0x3ce1720`, and calls `0x392ea10` on the selected nonzero result. The later loop repeats while the object word at +0x18 is unsigned greater than +0x48, reloading both after each iteration. Its per-iteration output is inspected at stack +0x18 and the corresponding nonzero path invokes `0x392ea10` using stack +0x28. The two invocations use different result offsets. No helper mutation, termination bound, data type, or real I/O is assumed.

Run `python3 research/work-items/RE-009-node115-snapshot-materialization-drain/verify.py` from the root. Local replay checks the FDE, all body and contextual bytes and a changed-displacement control. Pre-submission diff refresh and repository checks remain pending.
