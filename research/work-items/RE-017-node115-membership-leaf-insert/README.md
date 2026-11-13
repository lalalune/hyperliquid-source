# Node #115: selected nonfull membership leaf insertion

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the nonfull selected insertion helper left open in #6759; it complements the separate removal path in #6760.

The selected absent-key path passes a location and 20-byte value to `0x4c39500` at `0x51d2c4f`. At `0x4c39517..0x4c39525` the callee reads the leaf count and selects the fast arm only when N < 11. With valid insertion index `0 <= i <= N`, `0x4c3952b..0x4c39566` shifts the suffix right by 20 bytes through pinned slot `0x64df568` when i < N. Its byte length is `20*(N-i)`, so no call is made for append at i=N. The ELF relocation identifies that slot as `memmove@GLIBC_2.2.5`.

At `0x4c39579..0x4c3959a` the code copies the full 20-byte key at slot i and stores leaf count N+1. The selected caller increments the owning count once after helper return. This assumes valid tree/index state, disjoint input key storage and ordinary `memmove` behavior. The full-node split, balancing, allocator failures, unchecked malformed indices and key authority remain open.

Run `python3 research/work-items/RE-017-node115-membership-leaf-insert/verify.py` for target digest, instruction anchors, direct call and mutation controls without target execution. Static disassembly and import relocation are in `windows.txt`; no component gate changes.
