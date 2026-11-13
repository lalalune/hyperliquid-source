# Node #115 tracker: tree threshold split at one leaf

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is conditional static evidence for the tree representation, separate from the flat-ring split.

`0x4de55e7..0x4de5642` recognizes the sentinel representation and, when its count and root are nonzero, calls `0x4ca4580` with the tree header and threshold pointer before invoking a separate count-adjustment helper. The split helper requests a 0x380-byte node, initializes its parent and count fields, and for zero header height follows the selected leaf-only path without allocating internal nodes.

For a valid leaf with n ascending unsigned qword keys and 0<=i<n, where i is the first slot whose key is >= the threshold, `0x4ca4680..0x4ca46ca` finds i, stores i as the old leaf count, and stores n-i in the new leaf count. `0x4ca46d2..0x4ca4704` requests copies of `8*(n-i)` key bytes and `72*(n-i)` value bytes from the old suffix to the new leaf. The indirect slot `0x64df508` has the pinned dynamic relocation `memcpy@GLIBC_2.14`. For a zero-height tree the branch at `0x4ca470a` bypasses internal-child copying.

This does not establish final root cleanup, count-adjustment semantics, behavior when i=n, allocation failures, imported-function runtime binding, malformed trees, or actual checkpoint execution.

Run `python3 research/work-items/RE-017-node115-tracker-tree-threshold-split/verify.py` to authenticate the target and check byte anchors and direct calls with mutation controls. The disassembly and relocation are recorded in `windows.txt`.
