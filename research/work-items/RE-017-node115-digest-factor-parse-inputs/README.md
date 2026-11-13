# Node #115: selected factor input and success-gated parse

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This traces the two input triples and selected helper preceding the factor normalization in #6750.

The selected branch `0x538d228..0x538d27d` copies three qwords from incoming object `+0x08/+0x10/+0x18` into a local descriptor and checks the third qword is below 101. It saves the byte at incoming `+0x38` as the later selector. A call through slot `0x64e6af0` targets `0x421e4e0` in the pinned `R_X86_64_RELATIVE` relocation. The caller requires result tag `0x1a2` and saves the qword at result `+8` for the first normalization input.

After that selected success it repeats the less-than-101 check for the qword at incoming `+0x30`, and invokes the same slot using the three words at incoming `+0x20/+0x28/+0x30`. It again requires tag `0x1a2` and passes result `+8` as the second binary64 input. Either failed check or non-success result diverts before the factor writer call. The initial two length checks and helper result guards are observations on this path; no assumption that malformed pointers are safe is made.

At `0x421e4e0`, the first qword of the descriptor is not used before the selected inner call: descriptor `+8` and `+0x10` become its input pointer/length. The slot `0x64e4e60` resolves to `0x43099f0`. Only tag `0x1a2` reaches the second slot `0x64e4e68`, whose pinned relocation resolves to `0x5c44b40`; only its return value 1 writes `xmm0` to result `+8` and success tag `0x1a2`. Other results follow error handling. This packet does not infer text encoding, accepted numeric grammar, helper ABI semantics beyond these selected instructions, configuration authority or live reachability.

The selector-3 write and normalization remain conditional as documented in #6749/#6750; no claim of canonicality, replay success or a component gate is made. Run `python3 research/work-items/RE-017-node115-digest-factor-parse-inputs/verify.py` for target digest, instruction anchors, direct-call and mutations without execution. Disassembly and relocations are in `windows.txt`.
