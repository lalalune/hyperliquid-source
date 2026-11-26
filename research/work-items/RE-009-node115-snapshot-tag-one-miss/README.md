# RE-009: selected snapshot tag-1 lookup-miss handoff

Target Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. [#7120](https://github.com/lalalune/hyperliquid-source/pull/7120) follows the snapshot worker's tag-1 first consumer to slot `0x64e5a60 -> 0x3c087b0` and leaves the callee open. This packet covers two selected local miss routes and their return to that consumer. [#7122](https://github.com/lalalune/hyperliquid-source/pull/7122) conditionally supplies the initial `(1,0)` item, but no real state is assumed.

For a valid tag-1 in-range input, the caller passes `state+0xd8` in RSI and a qword loaded from a 32-byte-stride entry in RDX. At `0x3c087c2..0x3c087c9`, the callee reads `[RSI+0x10]`; zero branches directly to `0x3c08855`. If that word is one, it reads the pointer at `[RSI+8]`, compares the incoming qword with the pointed object's word `+8`, and the unequal branch also reaches `0x3c08855`. Both paths set AL=2 and write only that byte to result `+8` before normal return; they do not write result qword `+0` on these local routes.

The selected caller reloads result byte `+8` at `0x2c6f100`; its unsigned `>=2` branch goes to `0x2c6f149`, passing the original entry index to `0x46aa470`. Thus the selected fallback does not consume the inactive result qword or use the saturating arithmetic described in #7120. The singleton matching path, multi-entry lookup, other result tags, helper internals and all error/unwind behavior remain outside scope.

The join assumes valid input pointers, the stated tag-1 and in-range caller path, normal call/return, unchanged memory, and the ABI preservation of the saved index. It does not establish actual checkpoint data, runtime reachability, the source meaning of the tag or the returned object's behavior. No target binary executes and no component gate changes.

Run `python3 research/work-items/RE-009-node115-snapshot-tag-one-miss/verify.py` to authenticate the target, selected spans, relative call/branch targets and in-memory mutations. `offline-log.txt` records the static check; `windows.txt` retains disassembly.
