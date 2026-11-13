# Node #115: 24-byte raw-map short-sort dispatch and insertion

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This extends the distinct 24-byte raw-map sorter into its short-run helper; it is not the 20-byte tracker-key helper.

On the selected nonzero-flag branch with remaining length below its run threshold, `0x4f97594..0x4f975c3` passes at most 32 entries to slot `0x64eb8d0`, whose pinned `R_X86_64_RELATIVE` relocation points to `0x4eb7f40`. That helper forwards lengths below 33 to `0x5414750`. There lengths below two return; otherwise a scratch capacity below `length + 16` takes the failure branch.

For lengths 2–7, `0x541493b..0x5414a21` copies one 24-byte record per half into scratch and inserts subsequent records in the first half. It compares the first qword as an unsigned integer and shifts a preceding entry only when the new key is strictly less; equality does not trigger that shift. All three qwords move together. Under valid buffers and the selected branch's preconditions, equal first-qword keys preserve their relative order within this insertion loop. The helper continues into the second half and merge, which are outside this claim.

The flag provenance, 8–32 path, complete sorter stability, failure semantics and runtime bindings remain open. Run `python3 research/work-items/RE-017-node115-raw-map-short-sort/verify.py` to verify target digest, anchors, direct-call and mutation controls without target execution. `windows.txt` records the windows and relocation.
