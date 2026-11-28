# RE-009 — Node #115 quantity tree-to-ring row handoff

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [quantities ring-map packet](../RE-009-quantities-ring-map-115/) leaves the reverse conversion outside its reconstruction.

The remove path calls `0x5b929a0` at `0x4ddc13a`. The converter reads size at iterator input +0x40 and allocates 24 bytes per row, using pointer 8 for zero allocation. The selected materialization loop calls `0x51da3a0`. For each non-null returned node and index, it reads the key at node +0xb8 + 8*index and the 16-byte value at node +16*index. It appends key first and value second, advancing the output by 24 bytes. The resulting flat descriptor contains capacity, buffer pointer and emitted row count.

After the converter returns, the selected caller separately drains the original iterator to a null result, then installs the new ring descriptor with head zero. The packet establishes row materialization and the ring store for this call path. It leaves the iterator's internal traversal and the full conditions selecting all reverse-conversion call paths open.

Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-tree-ring-handoff/verify.py` from the repository root to verify static byte windows and selected edges.
