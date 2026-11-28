# RE-006 — Node #115 book level cached-row selection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The [ring append](../RE-006-node115-book-ring-append/) and [level removal](../RE-006-node115-book-level-removal/) packets identify calls to `0x518e690`. This packet traces how that shared operation selects its cached-row branch. The input in RDI is the level and RDX points to the row-store descriptor.

When level dword +0x20 is 1, the helper reads the cached index from level +0x28 and compares it unsigned with the store bound at +0x10. If in range, it reads a dword tag at `[store+8] + 0x110 * index`. A tag other than 2 takes the branch at `0x518ec00`, carrying the row pointer. An out-of-range index or an in-range row with tag 2 clears the qword at level +0x20. Other initial level tags skip this check and write.

The clear and skip paths converge at the level ring length read at +0x48. Zero returns immediately; nonzero continues at `0x518e6eb`. This covers the entry-stage decision and clear only. Cached-row processing and iteration over a nonempty ring remain outside scope.

Run `PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-level-cache/verify.py` from the repository root. It reads static bytes and checks the listed call sites, branches and an arithmetic decision table.
