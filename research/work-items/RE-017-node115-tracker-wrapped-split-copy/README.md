# Node #115 tracker: wrapped threshold split copy

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This extends the separately traced wrapped threshold index, under valid ring and nonaliasing assumptions.

In `0x4de55d0`, the flat ring has capacity C, head H<C, length L with C-H<L<=C, and 80-byte records. Let N=C-H and let i be the index returned by the threshold search. The helper computes L-i and requests a new buffer of `80*(L-i)` bytes (`0x4de568a..0x4de56e0`). With 0<=i<N and successful allocation, `0x4de595f..0x4de59c7` requests a copy of `80*(N-i)` bytes from physical slot H+i to the new buffer, followed by a copy of `80*(L-N)` bytes from physical slot zero immediately after the first part. The alternate i>=N branch requests a single copy from the second physical segment. Both call slot `0x64df508`, identified by the pinned ELF dynamic relocation as `memcpy@GLIBC_2.14`; actual runtime binding is not established.

After those copy requests, `0x4de59eb..0x4de5a27` stores original length i and returns a descriptor whose head is zero and length L-i. This preserves logical suffix order if the import behaves as named and the stated metadata and allocation assumptions hold. Failures, alternate tree representation, key provenance and downstream use remain outside scope.

Run `python3 research/work-items/RE-017-node115-tracker-wrapped-split-copy/verify.py` to check the target digest, instruction and direct-call anchors, and anchor mutations without target execution. Disassembly and relocation appear in `windows.txt`.
