# RE-017 · Linked-page cleanup reached by replay

The replay worker calls `0x52489e0` at `0x5a6f88e`. A separate tagged-handle wrapper tail-jumps into the same function at `0x5a45769`. This packet studies the callee's selected zero-element path. A null first word returns without traversal. When the descriptor's +0x10 word is zero and its +0 word is nonzero, the +8 word determines how far to follow +0x90 links. The loop first follows the low three bits one step at a time, then processes the remaining steps in groups of eight. The reached node starts a second walk that reads links at +0 and uses the shared indirect slot with sizes `0x90` and `0xf0`.

The two link offsets therefore serve distinct stages on this path. In the +0 walk, a null first link uses `0x90` for the reached node. With a nonnull first link, the first loop call uses `0x90`, and subsequent loop calls use `0xf0) while the local decrement remains nonzero and does not borrow. This describes valid finite chains only. The nonzero-element path, callback internals and semantic node types remain open.

From the root run `python3 research/work-items/RE-017-node115-replay-linked-page-cleanup/verify.py`. It checks the pinned ELF digest, complete contiguous body, direct call with corruption control, and the additional tail edge.
