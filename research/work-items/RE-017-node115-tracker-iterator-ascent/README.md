# Node #115 tracker demotion iterator: parent ascent

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This complements the separately traced initial descent and is limited to valid tree pointers and selected normal returns.

When a tag-1 iterator's current slot is at or beyond the current node count, `0x51e3494..0x51e34e6` loads the parent pointer at node +0 and the old node's parent-slot index at +0x378. If the parent exists, it requests cleanup through slot `0x64df4a0` with size 0x380 for a depth-zero node and 0x3e0 for a nonzero-depth node, increments the depth, and continues ascending when the old parent-slot index is >= parent count. A null parent follows a separate termination branch.

When an ancestor has a key at the recovered slot, `0x51e34e8..0x51e34f2` resumes the nonempty return path. It returns the ancestor node, accumulated depth and recovered slot in the output triple (`0x51e3551..0x51e3559`). The next iterator state descends through the child immediately after that slot and then child-zero pointers (`0x51e330f..0x51e3354`, with an eight-step unrolled continuation). The builder call `0x5b8eae6` consumes the returned node/slot. This describes selected static control flow, not the runtime cleanup binding, full traversal proof, malformed tree behavior, or production reachability.

Run `python3 research/work-items/RE-017-node115-tracker-iterator-ascent/verify.py` to authenticate the target, check byte/direct-call anchors, and reject mutations without executing it. Disassembly is in `windows.txt`.
