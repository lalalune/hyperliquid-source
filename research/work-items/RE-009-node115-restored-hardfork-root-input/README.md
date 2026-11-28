# RE-009 node #115 hardfork tracker reset before state-root capture

The compact state-root visitor captures the restored hardfork tracker as a boolean child and an optional digest child. On selected restore paths the startup state clears the boolean and presence tag. The later clone and root visitor then skip the old digest bytes. This determines which input to use when reconstructing the first root for a state that took one of those paths.

Target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source baseline is `2da45cb0a761cff6b478e40421699857d87a94df`. All addresses are ELF virtual addresses.

The [source handoff](../RE-017-abci-loader-handoff-115/README.md) and [frozen restore](../RE-017-local-state-restore-115/README.md) packets found the two 16-bit stores. The [root-slot map](../RE-008-abci-hash-slots-115/README.md) identified the tracker inputs and left their visitor bodies open. This packet identifies the affected field boundaries, follows the clone's absence branch and resolves the visitor and both root children for the ABCI tracker's optional digest.

| Step | Selected observed path |
| --- | --- |
| Materialize | Calls at `0x3c2efd0` and `0x3c2efe6` copy two 184-byte records from historical offsets `+0x2278` and `+0x2330` to compact state offsets `+0x3d98` and `+0x3e50`. |
| Reset | The local startup function `0x3c12800` on its selected successful height-match continuation writes the 16-bit value zero at `+0x3e28` and `+0x3ee0`. The separately selected frozen-state reset in `0x2cc1120` writes the same two words. Each write covers tracker `+0x90/+0x91`, leaving the next 32 bytes outside its store range. The linked loader packets specify the rest of the guards for these continuations. |
| Clone | `0x55f1a42` loads the ABCI tracker's boolean. When source `+0x3ee1` is zero, `0x55f1a52` skips both digest loads at source `+0x3ee2/+0x3ef2` and stages tag 0. The outgoing copy preserves the two staged flags at tracker `+0x90/+0x91`; this does not assign semantic meaning to memory in the absent payload area. |
| Capture | Compact build `0x4e34ce0` supplies state `+0x3e50` as root slot 57. Its visitor `0x5ad07c0` passes tracker `+0x90` via descriptor `0x64bc550` to `0x5ad0940`. This creates separate child visits for the boolean and optional field. |
| Optional root input | The child visitor `0x4d3eac0` takes `tracker+0x91`. Tag 1 enters the path that visits the payload. For zero it skips that path and visits the second child through `0x64df538` at the static qword `0x459348`, whose eight bytes are zero. Under the [ordinary qword buffering contract](../RE-009-node115-root-qword-child/README.md), this supplies eight zero bytes to that leaf. The boolean visit is separate and uses the byte writer `0x1419d40`. |

Run this command from the repository root. It checks the original instruction bytes and relocations, the static zero qword, slot offsets and ordered stage copies, and three deliberately changed byte controls.

```sh
python3 -B research/work-items/RE-009-node115-restored-hardfork-root-input/verify.py
```

The attached disassembly was collected with LLVM objdump 23.1.4 using `-d --x86-asm-syntax=intel --start-address=START --stop-address=END artifacts/node/115/hl-node`. Start from an instruction address in `windows.txt` to inspect a selected span. See the [offline run](offline-log.txt).

The composition assumes ordinary successful helper calls, stable selected owners and no intervening writes to these fields. Reset bypasses, the first tracker's nested root visitor, the expanded layout, and authority or equality of any real checkpoint or replay root remain open. No captured binary was executed.
