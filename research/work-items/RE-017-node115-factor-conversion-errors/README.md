# Node #115: selected factor converter error propagation

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The factor-input packet #6751 records selected success guards and #6753 records outer failure exits; this packet follows the conversion wrapper `0x421e4e0` itself.

The wrapper passes descriptor pointer and length (`+8/+0x10`) through the pinned first slot `0x64e4e60`. If its returned word is not `0x1a2`, `0x421e55e..0x421e5c9` copies the tag and returned payload into the output and returns without calling the second slot. If the first tag is `0x1a2`, it passes the 16-byte value from the first result to slot `0x64e4e68`. When that conversion returns 1, it stores `xmm0` at output `+8`, sets tag `0x1a2`, and calls `0x42320d0` on its temporary before returning. On the selected non-1 result, it writes `0xaf` into the temporary tag and copies the temporary fields to the output at `0x421e5ca..0x421e62f`. The packet does not claim meanings for tags or unwritten bytes.

The pinned ELF relocations resolve the slots to `0x43099f0` and `0x5c44b40`. At the two producer call sites, non-`0x1a2` results take the separate outer propagation paths documented by #6753. These are static normal-return observations; parser grammar, conversion panic paths, ownership of any error payload, source pointer validity, actual runtime binding and protocol-level effect remain open. No captured binary is executed and no completion gate advances.

Run `python3 research/work-items/RE-017-node115-factor-conversion-errors/verify.py` to verify digest, selected instruction anchors and mutation controls. Static disassembly and relocations are in `windows.txt`.
