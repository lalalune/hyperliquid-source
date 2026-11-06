# RE-009 · Checkpoint row cleanup iteration

The Node #115 checkpoint caller has two direct edges to the same cleanup routine at `0x1537df0`, from `0x1540d45` and `0x1540d6d`. The local cleanup window around the first edge subsequently calls `_Unwind_Resume`. The evidence does not classify all incoming exception paths or identify the indirect callback's implementation.

The cleanup calls `0x153b6d0` into a stack scratch record. A zero first word stops iteration. Otherwise it uses the scratch index at +0x10 to locate a 32-byte row. A zero row first word skips the callback and continues. A nonzero first word invokes the indirect slot at `0x64df4a0` with row +8, row +0 and zero as the first three arguments. This establishes the row cleanup stride and skip condition for this routine. It leaves ownership, callback semantics and checkpoint runtime compatibility open.

From the repository root run `python3 research/work-items/RE-009-node115-checkpoint-cleanup-rows/verify.py`. The verifier checks the pinned Node #115 digest, exact function extent, instruction bytes, both direct edges and changed-displacement controls. It does not execute the image.
