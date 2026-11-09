# RE-012: node 115 selected connection tree mark

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet studies the write-side sibling `0x4fac470`, which [#5102](https://github.com/lalalune/hyperliquid-source/pull/5102) explicitly leaves outside its counting-helper scope. Existing gossip peer-snapshot work studies a read-side wrapper and clone operations, not the selected state change here. The related four-byte ordered key comparison and tree layout were previously characterized by #2302 and #5102; #2302 explicitly excludes this lookup caller. This packet's added question is the matched record's mutation and its conditions.

## Selected tree path

After an earlier separately locked call to `0x4e40010` and its normal release, the function obtains another object's write-style 0-to-8 lock and inspects the qword at object `+0x18`. When it is `0x8000000000000000`, object `+0x20` is used as the root pointer and `+0x28` as a depth-like descent counter. A null root follows the second unlock path without the selected byte store.

In a non-null node, a u16 at `+0xe6` bounds an ordered search over four-byte keys at `+0xb8 + 4*i`. The input key is the original 32-bit argument. Both the input and stored four-byte words are byte-swapped before their unsigned comparison. With a valid stable tree sorted under that comparison, an equal key at slot i writes the single byte `1` at `node + 16*i + 8`; it then takes the second unlock path. A mismatch scans or follows the selected child at `node + 0xe8 + 8*i` while the depth counter permits; exhausting that path reaches the unlock path without this byte store. For the search described here, `i` and each child index must be within the valid node allocation and normal non-overflowing bounds.

This statement does not claim that the earlier helper has no writes, that the two locked objects are identical, a source-level key or flag meaning, the non-tree path, insertion or deletion behavior, concurrency safety, failure effects, or live connection behavior. It assumes valid pointers and tree ordering, no interfering mutation and normally returning calls; only this one selected store is identified.

## Static verification

`PYTHONPATH=tools python research/work-items/RE-012-node115-connection-tree-mark/verify.py` authenticates the target and complete function FDE, selected instruction pins, and direct call, then checks corruption controls and representative byte-order/search examples. The synthetic cases do not execute or emulate captured instructions.
