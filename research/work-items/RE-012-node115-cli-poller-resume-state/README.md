# RE-012: selected CLI poller return and resume states

Target Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Component: node runtime. `RE-008-output-flags-origin-115` records the two tag-2/tag-3 setup paths and their shared poller; [#6771](https://github.com/lalalune/hyperliquid-source/pull/6771) records selected normal and unwind state writes, while [#6772](https://github.com/lalalune/hyperliquid-source/pull/6772) conditionally links command tags to these paths. This packet maps the two poller return/resume paths.

For tag 2, the existing packet's selected setup reaches `0x2ae461d`, which passes parent `+0x220` to poller `0x2aeaef0`. When its returned AL is nonzero, `0x2ae4630..0x2ae4634` sets AL=1, CL=4 and jumps directly to `0x2ae5e5d`. That common block stores CL into the parent's entry byte `+0x21a` and returns AL. The entry table at `0x6040e4` maps byte 4 back to `0x2ae461d`.

For tag 3, the selected setup reaches `0x2ae5482`, again passing parent `+0x220` to `0x2aeaef0`. A nonzero AL selects `0x2ae5495..0x2ae5499`, which sets AL=1, CL=3 and reaches the same store-and-return block. Entry byte 3 maps to `0x2ae5482`. Thus, if the same parent and saved poller fields are re-entered unchanged, these two paths return to the corresponding poll call; they do not redispatch the command tag. Zero-return branches and cleanup are separate and excluded.

This is a conditional static control-flow relation. Pending/resume terminology is an inference from the return and re-entry shape, not proof of runtime scheduling, fairness, command completion or validator behavior. Aliasing, concurrency, unwind and unselected table cases remain open; no captured target executes and no completion gate changes.

Run `python3 research/work-items/RE-012-node115-cli-poller-resume-state/verify.py` for digest, selected instruction anchors, relative table entries, branch targets and mutation controls. `windows.txt` contains static disassembly.
