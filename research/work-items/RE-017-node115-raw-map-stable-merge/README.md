# Node #115: selected stable merge of 24-byte raw-map runs

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence extending separately traced run discovery and descending-run reversal.

On the selected merge path with adjacent nonempty sorted runs and sufficient scratch, `0x4f97939..0x4f97973` copies the shorter run to scratch using `24*min(left,right)` bytes. The pinned relocation for slot `0x64df508` names `memcpy@GLIBC_2.14`. If the right run is shorter, `0x4f97990..0x4f979e8` merges backward: it compares unsigned qword keys and, on equal keys, selects the scratch right record first for the later output position. If the left run is no longer than the right, `0x4f979ed..0x4f97a4b` merges forward: equal keys select the scratch left record first. Both loops copy the entire 24-byte record.

Under valid disjoint buffers, normal import behavior and sorted input runs, these tie choices preserve left-before-right order across the selected merge. This does not establish the full sorter, scratch-failure behavior, invalid input behavior, runtime import binding or actual production reachability.

Run `python3 research/work-items/RE-017-node115-raw-map-stable-merge/verify.py` to authenticate target bytes and check anchored instructions with mutation controls. The disassembly and relocation are in `windows.txt`; no target execution occurs.
