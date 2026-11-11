# RE-012: node 115 gossip tree leaf range

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the tree delegate left open by [#5084](https://github.com/lalalune/hyperliquid-source/pull/5084); #5089 describes a separate ring representation. The dual storage update in #2041 does not establish that its runtime object is the one observed here.

## Selected zero-height tree

For an input range `A <= B`, raw range flag zero, the tree representation selected by the `INT64_MIN` first word, a non-null root, height zero, and strictly increasing unsigned node keys, `0x4dce320` calls `0x4d39ef0` and subsequently sets the outer result tag to 2. The delegate loads the node's u16 key count at `+0x112` and compares unsigned qword keys at `+0xb8 + 8*i`.

The selected lower scan stops at the first key >= A. The selected upper scan begins at that index and stops immediately after an equal B, or before the first key > B. Thus for strictly increasing keys the selected indices are `lower_bound(A)` and `upper_bound(B)`; keys equal to either endpoint are included. This is a conditional fact about this zero-height path, not a claim about duplicate keys, interior-node traversal, every flag, the actual high-level source type, or runtime order.

If the selected indices differ, the delegate stores the same node pointer at result offsets `+0` and `+0x18`, zero at `+8` and `+0x20`, and the two indices at `+0x10` and `+0x28` respectively. If no key lies in range, its zero-height empty exit stores null at `+0` and `+0x18`; inactive fields are not claimed. The caller places this 48-byte delegate output at its own `+8`. Valid root/key storage, no concurrent mutation and non-overflowing in-bounds node access are assumptions; no runtime reachability, consumer behavior or execution is asserted.

## Static verification

`PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-tree-leaf-range/verify.py` authenticates the pinned target, both complete unwind-described function bodies, specific instruction bytes and selected table entries. Synthetic sorted unique qword lists compare a separate mathematical bound reference with the selected scan description; mutation controls demonstrate instruction/table pin sensitivity. These arithmetic checks do not execute or emulate captured instructions. The multi-level search and any original ABI details remain open.
