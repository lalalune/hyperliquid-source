# Node #115 tracker prefix: first unmatched 20-byte key

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; selected static analysis of FDE `0x5b75fb0..0x5b766f2`.

A separately traced path builds a tree from selected 20-byte entries. At `0x5377569..0x53775f8`, a floating value at tracker +0x40 is compared with zero; zero takes a skip branch, while nonzero and unordered values follow the other branch, which also tests an input count. Under its normal nonempty path, `0x537773d` calls `0x5b75fb0` with an iterator descriptor and an associated tree pointer.

The callee obtains a 20-byte candidate, scans tree-node 20-byte slots via the pinned `memcmp@GLIBC_2.2.5` relocation at `0x64dfb50`, and follows a child based on the comparison. A matched candidate loops to the next candidate (`0x5b76092..0x5b76097`). If all candidates match and iteration ends, it returns an empty vector (`0x5b760c8..0x5b760dc`). For the first unmatched candidate, `0x5b760e9..0x5b7613f` requests an 80-byte allocation, stores that 20-byte candidate as the first vector element, and sets the vector length to one. Allocation failure and later iteration are outside this bounded finding.

The caller converts the returned vector length and input count to floating values and performs further arithmetic and a comparison at `0x5377747..0x537778b`. We do not infer a protocol name, floating-point meaning, remaining-vector completeness, input validity, runtime binding or live execution.

Run `python3 research/work-items/RE-017-node115-tracker-key-difference/verify.py` to check the target digest, anchored instructions and direct calls, with mutation controls. The exact disassembly and import relocation are in `windows.txt`.
