# RE-006 — Node #115 book level descriptor address

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The [ring append packet](../RE-006-node115-book-ring-append/) records calls at `0x591190b` and `0x5911bab` that take an already produced descriptor. Their targets `0x4da5f90` and `0x4da7010` share the selected instructions byte for byte. When the descriptor's dword at +0 is 1, the +0x18 word is the index. A nonzero +8 base returns base plus 128 times that index. With a zero +8 base, the +0x10 word points to a ring descriptor.

In the ring case the logical index must be below the ring length at +0x18. The helper adds the ring head at +0x10 and conditionally subtracts the capacity at +0. The return is the ring buffer at +8 plus 136 times the wrapped index plus 8. The two address formulas therefore correspond to distinct input representations. The alternate descriptor tags, failed index check and insertion helper remain outside this packet.

Run `PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-level-address/verify.py` from the repository root. Verification reads the pinned ELF, checks the selected windows, compares the twins and checks the ring arithmetic against rotated slot lists.
