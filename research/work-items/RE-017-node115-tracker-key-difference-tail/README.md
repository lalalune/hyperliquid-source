# Node #115 tracker: remaining 20-byte key differences

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; FDE `0x5b75fb0..0x5b766f2`. This follows the separately traced first unmatched key; only valid tree and successful-allocation paths are analyzed.

After seeding the output vector with the first absent 20-byte key, `0x5b76148..0x5b761cd` obtains the remaining candidate count and iterator state. For each subsequent candidate, `0x5b76370..0x5b764ac` retrieves a 20-byte key and searches the comparison tree. The indirect 20-byte comparison uses slot `0x64dfb50`, whose pinned ELF relocation names `memcmp@GLIBC_2.2.5`. A match at `0x5b764c0` advances to the next candidate without appending. Reaching the absent path at `0x5b765c0..0x5b76621` stages the 20-byte candidate, grows the vector if full, and reaches the append block at `0x5b76190..0x5b761b8`; iteration ends by returning the vector descriptor.

Consequently, for finite well-formed sets A and B with a complete candidate iterator, ordinary memcmp binding and successful allocation, the vector consists of the 20-byte candidates in A absent from B, in iterator order. Together with the separately traced caller, its length supplies the numerator of the bounded `1 - m/n` arithmetic. This is not a proof of live reachability, cryptographic meaning, ordering of malformed trees, failure behavior or target equivalence.

Run `python3 research/work-items/RE-017-node115-tracker-key-difference-tail/verify.py` for authenticated target anchors and mutation controls without target execution; see `windows.txt` for disassembly and relocation.
