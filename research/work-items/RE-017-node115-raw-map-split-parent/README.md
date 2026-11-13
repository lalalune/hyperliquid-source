# Node #115 raw-map split: insertion into a nonfull parent

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The FDE for this code is `0x4c3f280..0x4c3fde6`; the analysis is static and conditional.

After a leaf split with a non-null parent, `0x4c3f5da..0x4c3f5fc` reads the old child's parent slot and the parent's 16-bit key count n. If n < 11 it enters `0x4c3fa98`. Assuming a valid parent and child slot j <= n, when j<n it requests overlapping moves of `8*(n-j)` key bytes, `12*(n-j)` value bytes, and `8*(n-j)` child-pointer bytes one slot to the right. The append path bypasses those moves. It places the saved separator key and 12-byte value at slot j, links the newly split child at child slot j+1, and stores parent count n+1 (`0x4c3fb91..0x4c3fbb1`).

The loop at `0x4c3fbf0..0x4c3fc7f` writes the parent pointer and slot index into child nodes from j+1 through n+1, including moved child pointers. The four-at-a-time unrolled part has equivalent parent/index writes. All three move calls use slot `0x64df568`, whose `R_X86_64_GLOB_DAT` relocation names `memmove@GLIBC_2.2.5` in the pinned ELF. This identifies the import, not runtime binding or behavior for malformed pointers. Full-parent splitting and runtime behavior remain outside scope.

Run `python3 research/work-items/RE-017-node115-raw-map-split-parent/verify.py` to authenticate the target, check instruction anchors, and reject anchor mutations without target execution. The objdump windows are recorded in `windows.txt`.
