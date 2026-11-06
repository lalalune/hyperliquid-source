# RE-017 · Segmented replay queue probe

Target Linux x86-64 Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The replay receive helper calls 0x581a100 at 0x5ab6f81 and 0x5ab6fba. This packet maps the selected probe from segment selection to its returned status.

The probe masks the reader index at descriptor +16 down to a multiple of 32 and compares the result with the current segment's base word at +0x200. If the bases differ, it follows the link at +0x208, stores each non-null segment as the current pointer and checks its base. A null link returns tag 2. A separate path can perform segment maintenance before the final slot test; that path's concurrent behavior is outside this claim.

In the final slot test, the 32-bit bit-test instruction uses the low five bits of the reader index to test the segment word at +0x210. With the selected bit set, the helper reads a 16-byte row at segment base plus 16 times that slot, writes it to output +8, stores tag zero, and advances the reader index by one. With the bit clear, it derives tag 1 from bit 33 set, or tag 2 from bit 33 clear, without advancing that index on the selected arm. These tags precede the enclosing receiver's own result mapping.

Run `python3 research/work-items/RE-017-node115-replay-segmented-probe/verify.py` from the repository root to replay the authenticated extent, caller edges and selected byte windows. The synthetic cases cover each slot, both flags and word-sized boundary indexes. This evidence assumes valid segment and descriptor pointers and does not establish producer ordering or the effects of interleaved segment maintenance.
