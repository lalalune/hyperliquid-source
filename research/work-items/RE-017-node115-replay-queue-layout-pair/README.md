# RE-017 · Replay queue consumer layout pair

The replay worker calls `0x581b8c0` at `0x5a6f5c9` and `0x581c340` at `0x5a6f679`. The functions use identical 32-slot reservation arithmetic but different segment layout offsets. The first loads the segment base at +0x300, uses a link at +0x308 and publishes a flag at +0x310. The second uses +0x100, +0x108 and +0x110 respectively. Allocation and release sizes also differ by 0x200 (0x320 versus 0x120). A shared slot count therefore cannot justify using one concrete layout at both call sites.

The verifier reads the pinned Node #115 image and compares both full FDE-bounded bodies against the byte exports. It verifies both direct call displacements and rejects a one-byte mutation to each. It counts identical-position instruction rows before any normalization. It leaves the payload type and concurrency guarantees open.

Run `python3 research/work-items/RE-017-node115-replay-queue-layout-pair/verify.py` from the repository root.
