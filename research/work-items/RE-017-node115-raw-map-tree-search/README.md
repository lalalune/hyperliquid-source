# Node #115 raw-map tree search and absent-key descriptor

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static analysis under valid tree-layout assumptions.

The tree representation's path at `0x4dbe53e` reads root pointer and height. For each node, `0x4dbe54b..0x4dbe59f` scans count 64-bit keys at +0x08 in increasing slot order, comparing the sought key as unsigned. Equal key jumps to the value replacement path. A smaller sought key stops the scan; if all keys are smaller, the selected index is count. Associated value addresses advance in 12-byte steps.

For a non-equal key, `0x4dbe5b3..0x4dbe5c1` decrements the remaining level count and, while it does not underflow, follows child pointer `node + 0xe8 + 8*index`. On the absent-key path, `0x4dbe5c5..0x4dbe5f8` builds a descriptor containing the tree header pointer, sought key, current node, zero flag, and selected index, then calls `0x51ef9a0` with the supplied value. A null root takes the corresponding empty-node descriptor path. We do not infer the insertion helper's balancing, ordering guarantees, malformed-tree behavior, or real input reachability.

Run `python3 research/work-items/RE-017-node115-raw-map-tree-search/verify.py` for digest-bound instruction/call checks and anchor mutation controls without executing the target. `windows.txt` contains the exact disassembly.
