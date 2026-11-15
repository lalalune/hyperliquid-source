# Node #115 nested 20-byte keys: large-sort scratch allocation

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static analysis extending the separately documented 2–20-entry key sort.

For n>=21 collected 20-byte keys, `0x5349299..0x53492a4` calls slot `0x64e4e08`, whose pinned `R_X86_64_RELATIVE` relocation addend identifies `0x36e2eb0`. The resolved helper computes `K=max(ceil(n/2),min(n,400000))` at `0x36e2ecd..0x36e2eec`. If K<205 it selects a stack buffer with capacity 204 records; otherwise it checks multiplication overflow and requests `20*K` bytes. It then calls `0x3e4aa90` with the input, length, scratch pointer and capacity; the flag argument is set exactly when n<65. The selected heap allocation is freed after a normal return.

For the caller's n>=21 path, n=204 selects stack and n=205 selects heap. This does not prove sorting correctness or stability, runtime relocation binding, allocation success, oversized inputs, or live reachability.

Run `python3 research/work-items/RE-017-node115-tracker-key-large-sort-scratch/verify.py` to authenticate target bytes, check instruction and direct-call anchors, and reject mutations without target execution. `windows.txt` contains disassembly and the relocation.
