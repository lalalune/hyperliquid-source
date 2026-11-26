# Startup admitted-path ordering beyond the short-sort boundary

Target: node/115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, size 105896032. Static ELF/FDE inspection; no captured executable execution or emulation.

## Scope and reuse

This advances the startup discovery path tracked by #3927. #4322 and `src/node115-startup-admission` establish admission from supplied enumeration results and already-joined path bytes. #4339 / `RE-012-node115-startup-sort-buffer` establishes the scratch-buffer contract at `0x152d390`, but stops before the long sorting body. `RE-017-node115-replica-discovery-order` establishes the 2–20-row short order and a bounded downstream single-leaf case; its evidence does not establish long ordering or general container traversal.

This packet closes the long sorting helper family and connects its logical result to an opt-in `node115-startup-sorted-admission::admit_sorted_listing` API. The existing `admit_listing` preserves encounter order exactly as before. This contribution does not reconstruct path joining, the subsequent tree builder, or general checkpoint selection. In particular, it does not extrapolate a last-five rule beyond the prior single-leaf evidence.

## Actual caller binding

Directory collector `0x15b58c0` receives the admitted row vector from `0x153f470`; vector count at stack+0x18 becomes R14 (`0x15b5907`), and row base at stack+0x10 becomes R15 (`0x15b5911`). For count >=21, `0x15b59ac`/`0x15b59af` pass that same base/count to the slot at `0x64e0e58`, resolved to `0x152d390`. The non-directory collector `0x15b59e0` has the equivalent chain through `0x1540a40`, `0x15b5a27`/`0x15b5a31`, and call `0x15b5ad2`. The buffer wrapper passes the same vector to `0x14f3640` at `0x152d452`.

The prior admission boundary remains explicit. The mapper `0x150bad0` takes the successful UTF-8 conversion's pointer/length at stack+0x50/+0x58, allocates and copies exactly those bytes (`0x150bc0e`–`0x150bc31`), and stores capacity/pointer/length at output+0/+8/+0x10 (`0x150bc3f`–`0x150bc46`). Directory filtering copies those three words into 24-byte rows (`0x153f588`–`0x153f58f` and `0x153f694`–`0x153f6a2`), preserving the string object rather than deriving a numeric height or filename fragment. The sort comparator reads the row pointer at +8 and length at +0x10. The source adapter still requires the previously documented supplied, already-joined bytes: the mapper's earlier path-construction helper is outside this packet, so this is not proof of a particular live filesystem root or join policy.

## Closed sorting family

The selected ordinary path consists of these five sorting functions, with `memcmp` and `memcpy` import bindings checked against ELF relocation symbols:

| Entry | Role and order-relevant behavior |
| --- | --- |
| `0x14f3640` | Detect runs, reverse strictly descending runs, schedule and merge runs, dispatch unsorted spans to `0x14d8680`. |
| `0x14d8680` | Stable partition into scratch, recursively sort partitions, or fall back to `0x14f3640` when its depth budget is exhausted; lengths <=32 go to the small helper. |
| `0x14c9e80` | Sort two small halves using strict insertion after four-row seeds, then merge from both ends. |
| `0x14c5b50` | Sort four rows by stable pair selection and extrema/middle selection. |
| `0x15501f0` | Select a pivot from existing rows, recursively for larger samples; it does not transform the compared strings. |

Every comparator uses the unsigned byte `memcmp` result over the minimum of two lengths; when equal, it uses the signed length difference. For valid allocated strings whose lengths fit isize, this is ascending lexicographic byte order, with shorter prefixes first. There is no decimal parse, locale comparison, Unicode normalization, or path-component comparison. The capacity word is not a comparison key.

The tie/order argument follows the data movement, not just comparator similarity:

* Run detection in `0x14f3640` extends a nondecreasing run across equality. A descending run stops on equality (`0x14f390b`) and only that strictly descending run is reversed. Reversal therefore does not reverse equal elements.
* Forward merge compares right to left and chooses the left row on equality (`0x14f3ce3`). Backward merge chooses the right row on equality (`0x14f3c4b`), placing it later. Both preserve encounter order among equal bytes.
* `0x14d8680` partitions rows in encounter order. The low partition is written forward and the high partition backward; the high region is copied back in reverse address order (`0x14d8a10`–`0x14d8a6d`), restoring its encounter order. The pivot is copied at its own encounter point. The equal-pivot optimization uses the corresponding non-strict partition, with the same forward/backward storage and restoration. Recursive calls and the depth fallback preserve this property under their smaller-run contracts.
* Small-half insertion moves a row only for strict less-than (`0x14ca043`, `0x14ca15a`). The two-ended small merge selects left on forward equality and right on backward equality. The four-row seed uses strict conditional selections with the same stable extrema/center order. `check_order_model.py` separately checks a hand-reconstructed selector on all 256 assignments from four ordered byte strings, retaining original row IDs to make equal-key order observable. Changing its final equality decision is rejected in 100 cases.

These are static reconstruction arguments under the caller's valid memory/scratch premises and ordinary successful returns. They are not a machine-checked proof of every control-flow invariant or native runtime observations. The Rust adapter deliberately uses the standard stable slice sort to implement the established logical sequence result; it does not reproduce the target's scratch layout, adaptive scheduling, pivot choices, or allocation behavior.

## Validation

```sh
python3 research/work-items/RE-012-node115-startup-path-long-sort/verify.py --target artifacts/node/115/hl-node
python3 research/work-items/RE-012-node115-startup-path-long-sort/check_order_model.py
cargo test --manifest-path src/node115-startup-sorted-admission/Cargo.toml
```

Use Capstone 5.0.7 and pyelftools 0.32 for the static verifier. It verifies FDE boundaries, retained instruction bytes, selected semantic witnesses, relocation/import bindings, and eight negative controls. Source tests cover admission/ordering at sizes 20, 21, 32, 33, 64, 65, 170, 171, and 4097, plus duplicates, UTF-8 bytes, prefix/numeric lexical differences, rejected entries, and input errors. Those sizes exercise the logical API around native boundaries; running the source standard-library sort is not dynamic coverage of the native algorithm's branches.

No existing full-scope component gate is promoted. Live directory reads, path construction, allocator failure, panic/unwind, binary ABI identity, tree construction/deduplication, and checkpoint validity or choice remain outside this change.
