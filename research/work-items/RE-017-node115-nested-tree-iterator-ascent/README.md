# Node #115 nested 20-byte iterator: parent ascent

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence extending the separately traced initial tree descent and key projection.

For tag 1 and nonzero remaining count, `0x513b200..0x513b235` decrements the count and checks the current node's 16-bit count at +0x3fe. When the current slot is exhausted, `0x513b300..0x513b320` follows the node's parent pointer and reads the old child's parent-slot index at +0x3fc. It increments the saved depth and repeats while that index is at or beyond the parent's count. A null parent takes a distinct termination branch.

On finding an ancestor slot, `0x513b322..0x513b3e4` returns pointers to its 20-byte and 72-byte arrays at `node+0x320+20*slot` and `node+0x08+72*slot` respectively. For the next iterator state it starts at child `slot+1` and follows child-zero links for the remaining descent; the unrolled loop handles groups of eight. The tracker builder `0x5b7b95f` consumes the 20-byte pointer. These claims assume consistent tree links, valid heights and normal returns; no complete runtime equivalence, key meaning, malformed-tree behavior or cleanup semantics is asserted.

Run `python3 research/work-items/RE-017-node115-nested-tree-iterator-ascent/verify.py` to authenticate target bytes and check instruction/direct-call anchors with mutation controls; no target execution is performed. `windows.txt` gives the selected disassembly.
