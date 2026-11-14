# Post-broadcast target collection on node #115

Bounded advance of backlog **HL115-093**: recover the target stream prepared
inside `0x2d34fc0`, before its unresolved per-target cancellation operation.
Target SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
This is original static ELF analysis; no captured program execution/emulation.

## Prior boundary

[#2241](https://github.com/lalalune/hyperliquid-source/pull/2241), packet
`RE-001-node115-books-selected-broadcast`, proves selected/all-book dispatch
and the optional post step, but explicitly excludes `0x2d34fc0` effects.
This packet starts inside that helper. Its new result is the actual two-map
selection, two record layouts, filter predicate, ordered duplicate-preserving
collection and cancellation argument stream. It does not reclaim dispatcher
row selection or claim complete book cancellation.

## Recovered selection

The original helper initializes one empty vector, then looks up the same
20-byte key in owner `+0x18` and `+0x38`, in that order. A miss in the first map
continues to the second. Successful lookups supply these inner collections:

| Map | Flat/ring stride | Identifier | Filtered qword | Collector |
| --- | --- | --- | --- | --- |
| owner+0x18 | 112 bytes | row+0 | row+8 | 0x233c7d0 |
| owner+0x38 | 96 bytes | row+0 | row+0x18 | 0x233c2d0 |

Both collectors append to the **same** vector. They test the low 32 bits of
the raw filter discriminator: exactly 1 requires equality between the row's
specified qword and the full 64-bit filter value. Every other low-word value
bypasses that comparison. No extra interpretation of this tag as an asset,
DEX, side or operation name is assumed.

Flat/ring traversal visits the live suffix beginning at the normalized head,
then the wrapped prefix. It preserves collected order and duplicate IDs across
and within both collections. No sort, deduplication or validation against an
order arena occurs in this helper. In particular, the second collection tests
`row+0x18`, not the first collection's `row+8`.

After **both** collections finish, the original loop walks the vector by eight
bytes and calls `0x2d32de0(owner, key, id, &raw_reason, original_r8, original_r9)`.
The raw reason word is initialized to `0x8000000000000000`, incremented once
before the loop, and copied for each call: `0x8000000000000001`. It is deliberately
left unnamed. An empty vector results in no such call. The existing caller at
`0x22f213b` can reach this post step even after an empty book broadcast; the
post-step gate is separate from the book row count.

## Source domain and downstream boundary

`src/node115-post-broadcast-targets` projects the outer maps as logical maps of
full 20-byte keys, while decoding actual byte offsets in 112/96-byte row arrays.
It returns the exact ordered cancellation argument stream, not completed
mutations. Valid flat/ring snapshots, stable source memory and successful
allocation are premises. Invalid snapshots are reported as source domain
errors, without pretending to reproduce native behavior on corrupt pointers.
Empty rings need no valid head; nonempty rings require length <= capacity and
head < twice capacity, matching the selected one-wrap normalization.

Tree-valued inner collections stop explicitly before their unclosed iterator
helpers (`0x238ffe0`/`0x2385d50`). A stop includes IDs already collected, but no
cancellation has yet occurred. Native outer-map traversal/allocator ABI,
`0x23e33b0` effects and the body of `0x2d32de0` remain unclosed. There is no
callback that substitutes invented cancellation behavior. Backlog HL115-093
and the component's full-scope gates remain open.

## Validation

```sh
python3 research/work-items/RE-001-node115-post-broadcast-targets/verify.py --target /path/to/original/hl-node
cargo test --offline --manifest-path src/node115-post-broadcast-targets/Cargo.toml
cargo test --offline --release --manifest-path src/node115-post-broadcast-targets/Cargo.toml
cargo clippy --offline --manifest-path src/node115-post-broadcast-targets/Cargo.toml -- -D warnings
```

Use Capstone 5.0.7 and pyelftools 0.32. Four original windows bind 2,273 bytes /
566 instructions, 46 facts and 39 in-memory changed-byte controls. Controls
cover map/record offsets, discriminator width/value, call arguments, vector
order, appended lengths and raw reason construction. These checks validate
static evidence, not native runtime equivalence.

Source tests cover every capacity 1..7, head 0..2*capacity (exclusive) and live length
0..capacity with five distinct raw tags, plus both row formats, wrong-offset
decoys, wrap order, duplicates, one-bit-distinct keys, empty/missing first maps,
second-map-only output, forwarding, and tree/domain boundaries. Expected ring
ordering uses a separate modular-index oracle. The mixed-layout fixture yields
`[40,30,40]`, demonstrating preservation of the cross-collection duplicate.
