# RE-009 — Node #115 quantity internal-node split

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The vacant-insertion helper `0x4c5b580` branches on parent key count at `0x4c5b8e6`. This packet covers the full-parent case. The leaf split and insertion into a nonfull parent are covered separately in #7667 and #7672.

The full parent chooses the same separator indices as the leaf split, but allocates a 376-byte internal sibling. It copies key and value suffixes and transfers the child-pointer suffix starting at old child index separator + 1. The child-pointer count is one greater than the number of keys moved. The transferred children receive the sibling pointer as parent and are reindexed from zero.

When propagation reaches the top, the code at `0x4c5bc78` allocates a new 376-byte root, installs the old root as child zero and publishes the old height plus one. It inserts the promoted key and value and links the split sibling at child one, updating both children's back-links. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-internal-split/verify.py`.

A previously retained disassembly row ended inside an instruction; that incomplete row was removed. The retained excerpts are partial, and the synthetic cases do not execute the target.
