# RE-009 #115 named user EVM State raw subtree comparison

Compare the complete raw slot 34 at checkpoint height H. Read named `exchange.user_to_evm_state` and the independent raw ABCI reference under separate SHA-256 pins. Rehash the complete ordered reference before comparing the extracted subtrees.

The Exchange writer at `0x54812ea` passes `+0x3ff8` to `0x5676020`, then `0x5287460` emits stored Address/value pairs. Addresses are 20-byte arrays or lowercase `0x` strings in the selected serializer forms. Named row writer `0x55fd910` reads two qwords, a bool and a Time. It omits zero for `g` and `t`, false for `b` and the epoch marker for `T`. The compact encoding's epoch predicate combines year 1970, ordinal 1, zero seconds within the day and zero nanos. The projection materializes these values before hashing each stream.

| Raw path | Contents in checkpoint row order |
|---|---|
| `[34,0]` | Concatenated 20-byte keys |
| `[34,1,0]` | `g` at row `+0x0` as LE64 |
| `[34,1,1]` | `t` at row `+0x8` as LE64 |
| `[34,1,2]` | `b` at row `+0x1c` as one byte |
| `[34,1,3]` | `T` at row `+0x10` as little-endian signed epoch seconds followed by a little-endian unsigned nanos dword |
| `[34,2]` | The collection length as LE64 |

Raw collection visitor `0x4d9fda0` binds the key and value descriptors ahead of the independent length. All values target the same value branch under `0x4e1bea0`. Its row method `0x3d27bd0` issues four child methods in the order listed. Empty input bypasses key/value visits and has only a length leaf. The names identify checkpoint fields without assuming their higher-level meanings.

Use the pinned helpers from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404), [#7368](https://github.com/lalalune/hyperliquid-source/pull/7368) and [#7352](https://github.com/lalalune/hyperliquid-source/pull/7352) in the layout specified by `compare_user_state.py`. Run `python -B research/work-items/RE-009-node115-rmp-user-evm-state-root/verify.py --helpers PATH --rustc PATH` from the checkout root. The verifier authenticates the target ELF without executing it and checks synthetic empty, mixed defaulted/populated rows, wrong stream bytes and raw-order differences. No real checkpoint or observed reference root was supplied.
