# RE-006 — Node #115 book level tree-hit descriptor

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The ring append owners call `0x4dc42f0` and `0x4dc52b0` before passing the resulting descriptor to their level address helpers. This packet covers the producer's selected tree-hit path. The twin scan and descriptor stores have identical instructions in these windows.

The initial node comes from the owner at +8, with height at +0x10. Each node supplies its 16-bit key count at +0x5e2. The first signed key is at +0x588, and the scan advances eight bytes at a time while the sought key is greater. Equality yields the zero-based position. On an unsuccessful node scan, the first larger key's position or the key count selects the child from +0x5e8, provided another level remains.

The tree-hit result writes tag 1 at +0, the matching node base at +8, the owner-pointer slot address at +0x10, the matched index at +0x18 and the same owner-pointer slot address at +0x20. This establishes where the address helper receives its nonzero base and index. The fixture covers signed key order and insertion offsets at a single node. Tree misses, flat representations and conversion stay outside scope.

Run `PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-level-tree-hit/verify.py` from the repository root. It reads the binary and compares the selected instructions, caller targets, twin windows and scan arithmetic.
