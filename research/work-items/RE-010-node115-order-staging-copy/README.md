# RE-010 · Node #115 order processing stages owned row and option buffers

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[#4116](https://github.com/lalalune/hyperliquid-source/pull/4116) recovers the upstream order-array layout and wrapper admission. This separate packet recovers the ownership handoff inside the downstream function at `0x59d6660`, which the first packet left as a boundary.

The function obtains count and pointer from payload offsets 16 and 8. It checks count against `0x249249249249249`, the floor of the signed 64-bit maximum divided by 56, before taking the normal allocation path. Count zero selects pointer value 8 without allocating row storage. A nonzero byte size goes through the allocation slot at `0x64df480` and branches separately on a null result. In the copy loop, the source and destination advance by 56 bytes. Explicit stores copy bytes 0 through 54 of each row and omit byte 55. These writes support treating the omitted byte as layout padding for this path.

Payload word `+0x18` uses the signed minimum sentinel. The nonsentinel path separately sizes a second copy at 32 bytes per element using count `+0x28` and pointer `+0x20`. It checks the shift and signed-size bound, uses pointer value 8 at zero size and invokes the copy slot at `0x64df508` when copying. The sentinel path bypasses that second allocation.

The staged row buffer has count, pointer and count at stack offsets `+0x58`, `+0x60` and `+0x68`. Call site `0x59d6849` passes the address at `+0x58` to `0x55650b0`. Its returned words are then packed into the wrapper output. The copies are temporary preparation; this packet does not equate them to committed order-book writes.

Run `python3 research/work-items/RE-010-node115-order-staging-copy/verify.py` from the repository root. The verifier checks the pinned ELF, byte ranges, branch targets, indirect slot references and final direct edge. It rejects altered row size, a row destination offset and the downstream call displacement.
