# RE-010 — Node #115 ENV79 decoder caller result variants

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [ENV79 matcher packet](../RE-010-env79-variant-matchers-115/) establishes the variant identifiers. This packet follows their success results through both direct callers at `0x14be170` and `0x14be647`.

Both callers invoke `0x14b3080` with EDX=1. When byte zero of its result is 9, byte one selects a signed-relative table row. The first caller's table is at `0x463f48`. All 79 rows lead to a word store of `(variant << 8) | 9` to the caller's output.

The second caller's table is at `0x464084`. Each row first calls `0x14ceae0` on the original input state. It checks the secondary result's first byte for 9. If equal, it emits the same word as the corresponding first-caller arm. All non-9 secondary results branch to a shared continuation at `0x14bf104`. This identifies the difference in the two success paths. The secondary decoder's full input semantics, the callers of these wrappers and any enclosing config field name remain open.

Run `PYTHONPATH=tools python3 research/work-items/RE-010-node115-env79-decoder-caller-results/verify.py`. It reads the pinned ELF and verifies both dispatch sites and every row's output store and secondary helper edge.
