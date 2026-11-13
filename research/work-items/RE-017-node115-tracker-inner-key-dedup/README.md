# Node #115 tracker inner key builder: adjacent duplicates

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static, selected-path analysis only.

The separately traced `0x5349140` collects 20-byte entries, performs stable bytewise sorting for lengths 2–20, and calls `0x4ca9730` with a contiguous iterator. In the tag-2 iterator path, `0x4ca988d..0x4ca98b7` reads one 20-byte value and advances the cursor by 20. `0x4ca98f9..0x4ca99d7` reads subsequent entries as lookahead, compares the first 16 bytes and remaining four bytes, and loops while both portions match. A different lookahead is retained for the next iteration; end of input clears the lookahead flag.

For the selected builder path with a current leaf count below 11, `0x4ca99ef..0x4ca99fb` branches to `0x4ca9850`, where exactly one 20-byte entry is stored for the run and the external count increments once. Thus, under valid contiguous buffers and normal operation, adjacent identical entries collapse to one on this bounded no-full-leaf path. Together with the separately traced small-input sort, equal 20-byte values become adjacent for 2–20 entries; this does not prove full-tree behavior or the >=21 sort path. It also does not assign a protocol meaning to the bytes, prove their runtime reachability, or establish full reconstruction.

Run `python3 research/work-items/RE-017-node115-tracker-inner-key-dedup/verify.py` for target digest, instruction and direct-call anchors with mutation controls, without target execution. `windows.txt` records disassembly.
