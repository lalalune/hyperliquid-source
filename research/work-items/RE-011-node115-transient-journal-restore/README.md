# RE-011: selected restoration of a transient-storage journal value

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Partial static evidence for [EVM issue #3918](https://github.com/lalalune/hyperliquid-source/issues/3918). [PR #4356](https://github.com/lalalune/hyperliquid-source/pull/4356) maps writer `0x2972390`'s tag `0x0a` record; the [earlier frame rollback packet](../RE-021-blake2b-lookup-115/README.md) maps the reverse walk and identifies the tag-10 arm but leaves its two map paths as boundaries. This packet connects their address/key/previous-value bytes to **one selected existing-key restore path**. Both earlier findings are credited as context, and this packet independently pins the selected writer and consumer instructions.

The writer's `0x58`-byte entry carries tag `0x0a` at `+0`, address bytes at `+1..+0x14`, 32 key bytes at `+0x18..+0x37`, and the saved previous value at `+0x38..+0x57`. The rollback helper `0x29710e0` compares its saved/current journal lengths, resets the current length, and traverses the removed suffix backwards in `0x58`-byte steps. A tag `0x0c` stops the walk; other selected records are copied into a stack record and passed through relocation slot `0x64e6d68` → `0x5be3400`. The helper's third argument is the context object at rollback input `+0xf0`.

The dispatch table at `0x942248` maps tag 10 to `0x5be372b`. That arm reads the same address, key and saved-value offsets. A null third argument returns without the selected map work. With a nonnull context, a zero saved value calls `0x5be3340` with the selected address and key; this packet does **not** claim that helper's complete effects. A nonzero saved value instead stages that value and calls `0x5be1e70` using the selected address. On its observed address-match arm, that helper returns a zero first word and a bucket pointer. The dispatcher subtracts `0x28` from the bucket pointer, then calls `0x5be1fd0` with the staged 32-byte key and saved value.

Inside `0x5be1fd0`, the selected matching-key arm compares both 16-byte halves of the key with a 32-byte bucket key. On equality, `0x5be2118..0x5be2125` copies the staged saved value into the matching bucket's 32-byte value field. Thus, **if the writer and rollback refer to the same journal and map context**, the entry survives until this walk without a preceding stop marker, the address and inner key match existing entries, and the listed helpers return normally, this branch writes the recorded previous value back to that bucket. These are conditional static observations, not proof of complete transaction rollback or a runtime trace.

Outer/inner insertion and missing-key alternatives, the zero-value helper's full behavior, corrupt tags, allocator failures, aliasing, concurrent mutation, all journal variants and transaction-level durability are not established. No EVM component gate is advanced.

## Reproduce

```sh
PYTHONPATH=tools python3 research/work-items/RE-011-node115-transient-journal-restore/verify.py
```

Capstone 5.0.7 and the authenticated target are required. The static verifier checks five complete indexed FDEs and decoded partitions, 193 selected instruction spans, 112 instruction pins, ten selected edges, the tag-10 table entry, a RELATIVE relocation and seven corruption controls. Counts are scoped evidence, not component coverage. No captured instruction is executed or emulated.
