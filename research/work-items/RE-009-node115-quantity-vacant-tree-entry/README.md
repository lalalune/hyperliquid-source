# RE-009 — Node #115 vacant quantity-tree entry

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The tree arm of the quantity upsert at `0x4dd6150` calls vacant insertion at `0x4dd653c`. The ring-map and removal packet (#6217) leaves this path unresolved.

When the entry's node pointer is absent, `0x51f21d0` allocates a 280-byte leaf, initializes its parent and count to zero, and publishes it with height zero. Keys are qwords at leaf offset +0xb8 and values occupy 16 bytes per slot at the leaf base. The first insertion writes key and value at slot zero. When a leaf exists and has space, `0x4c5b580` uses the supplied insertion index. For interior insertion it moves the suffix one slot right in each array, with separate lengths of eight and sixteen bytes per shifted entry. Both paths increment the leaf count. The wrapper increments the tree entry count and returns the node, height, slot index and tree pointer.

The packet covers ordinary vacant insertion with room, including initial leaf allocation. Full-node propagation and existing key replacement are outside its scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-vacant-tree-entry/verify.py`.
