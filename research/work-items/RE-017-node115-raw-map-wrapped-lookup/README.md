# Node #115: wrapped 24-byte raw-map lookup

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence; complements the previously submitted nonwrapped lookup.

`0x4dbe379` calls `0x57f95d0` on the flat representation. Assume a valid ring with capacity C, head H<C, count L where C-H<L<=C, and strictly increasing unsigned qword keys in logical order. Let N=C-H and M=L-N. At `0x57f95fb..0x57f961d` the helper compares the key at physical slot zero with the requested key. Equality returns flag zero with logical index N; a larger slot-zero key selects the first physical segment; a smaller key selects the second.

The selected segment is searched in 24-byte strides using unsigned key comparison (`0x57f9630..0x57f966d` and `0x57f9694..0x57f96d3`). Under the stated ordering, the result is flag zero and the logical matching index, or flag one and the logical insertion index if absent; the second-segment index is offset by N. The caller tests the flag in deciding its insertion or rebuild path. Invalid metadata, duplicates, concurrent mutation and actual runtime reachability are outside scope.

Run `python3 research/work-items/RE-017-node115-raw-map-wrapped-lookup/verify.py` to authenticate the target, validate instruction/call anchors and reject anchor mutations without execution. See `windows.txt` for the disassembly.
