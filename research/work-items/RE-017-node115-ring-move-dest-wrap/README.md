# Node #115: 24-byte ring movement with wrapped destination

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. FDE `0x58127f0..0x5812ac5`. This extends the separately traced nonwrapped move, and describes static copy requests only.

Assume capacity C>0, source slot s, destination slot d, count n with 0<=s,d<C, n>0, s+n<=C and d+n>C. Let k=C-d and r=n-k. The source is contiguous while the destination wraps, so d>s and r>0. The helper branches on whether d-s<n.

* If d-s<n, `0x58128ed..0x5812937` first requests a move of r records from source s+k to destination 0, then k records from source s to destination d.
* If d-s>=n, `0x5812a27..0x5812a6a` requests the same two moves in the opposite order.

Record-to-byte scaling is 24. Both calls use slot `0x64df568`, whose pinned ELF relocation names `memmove@GLIBC_2.2.5`; runtime binding and invalid/aliased metadata are not proven. The two orders are material because they protect overlapping source data in their respective cases. This does not claim behavior when the source also wraps, production reachability or full node equivalence.

Run `python3 research/work-items/RE-017-node115-ring-move-dest-wrap/verify.py` to authenticate the target, check anchored instructions and reject mutations without executing target code. `windows.txt` captures the selected disassembly and relocation.
