# RE-006: the node #94 spot order insert from gates to rest

This packet maps the whole spot insert `0x26e81c0`, every gate, the walk of the opposite book, each fill, the removal rows and the rest of the order, with its statuses and failure arms, so a reconstruction can write the spot matching loop from bytes instead of from the reference's sketch, which differs in six rules listed below.

- Component ID: RE-006 (book state transitions), the spot insert path
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference sketch is `l1/book/book/impl_insert_order.rs`; it was a lead only and differs from the bytes as listed.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants: the body of `0x26e81c0` up to its unwind pads at `0x26ebb70`. Real bytes with no mutants: local drop glue `0x277bac0`, map drop `0x28a8ac0`, user map insert `0x2879d60` and leaf insert `0x1ad9950`. Stubbed at the edge, each with its arguments logged: every other callee, listed under Edges. Excluded: the bodies of the edges, including fee and settlement (`0x232d840`, `0x372b9d0`), and the other five insert bodies. #47 and #235 name the two bodies `0x430d610` and `0x26ebdc0`; neither reads this one, and both leave the maker walk open. `0x26e81c0` appears in other packets only as a caller row or inventory row.

## Reproduce

From the repository root:

```
python3 tools/spot_order_insert.py --out research/work-items/RE-006-spot-order-insert-94
python3 -m unittest tests.test_spot_order_insert
```

The tool takes about 260 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `cases.tsv`, `mutations.tsv`. Addresses are ELF virtual addresses. The function end comes from `.eh_frame`. Offsets written `rbx+n` are in the order record the function receives by pointer.

## Evidence

### Call shape

`rdi` result, `rsi` book, `rdx` order record, `ecx` and `r8d` two words passed to the fill legs, `r9` exchange side state, first stack word the row sink. Three direct callers (`callers` in `evidence.json`): `0x26cc730`, `0x26e5760`, `0x2700390`.

Why this is the spot body (inference from these observations): the row table at state `+0x1f8` has stride `0x20`, its bound panics at `spot_meta.rs:565`, its first two words are the two tokens of a pair (each paid or received by side below), and the fill cap reads a per token balance tree. Of the six insert bodies by FDE size, only this one calls leg `0x232d840` (`copies`).

### Entry gates, in order

| # | Test | Outcome |
| --- | --- | --- |
| 1 | `asset` = book `+0xb0` below row count | panic `spot_meta.rs:565` |
| 2 | second token of the row is in tree state `+0x2e0` with byte 0 | else status `0x...17`, third word = the token |
| 3 | best opposite price against the limit, time in force table `0x3ed590` | 0: crossing gives `0x...06` with two payload words from `0x23978c0`, `0x2396d50`. 1, 3, 4: no cross gives `0x...08`. 2: nothing |
| 4 | `rbx+0x90` nonzero | `0x372f930` for the taker, status `0x...05`. Size tag `rbx+0` zero with this byte zero panics `assertion failed: reduce_only` |
| 5 | limit <= 10^15, limit % tick `0x230b590` == 0 | else status `0x...00` |
| 6 | class `0x3728670` of the first token: 2 | passes. 1: status `0x...14`. Else mid `0x32780d0`, gate `0x26f4280`, any word but `0x...18` is returned with both payload words |
| 7 | `rbx+0xa8` zero | oid = state `+0x38`, which adds 1 and stays at `u64::MAX` |

Crossing is inclusive, and it reads the first key of the opposite tree: bids `+0x80` for a sell, asks `+0x98` for a buy. An empty tree, or root with length 0, does not cross.

### Walk of the opposite book

The tree is never changed during the walk. Every removal waits for the end.

```
for level in opposite tree in key order:
    px = |key|
    stop when px is worse than the limit (equal goes on)
    when row second token == 0 and row first token is in state +0x2e0:
        gap = px / anchor(0x375fb50) - 1, negated for a sell
        gap > 0.2 or NaN: band stop
    for slot from level head along +0x10/+0x18:
        panic impl_insert_order.rs:517 on a bad index or a vacant slot
        remaining == 0: end
        taker == maker, or both pass 0x37e4fb0: skip row reason 9, note user
        slot +0xb0 nonzero: 0x372f930(maker), skip row reason 10, note user
        else fill
```

Reason bytes 9 and 10 are `selfTradeCanceled` and `reduceOnlyCanceled` in the status name table of #1058. Skip rows hold the slot `+0xd8` oid and user. `note user` adds the oid to a user map that the result returns.

### One fill

1. `size` = min(slot `+0xc8`, remaining). Maker size 0 passes to the next link with no call.
2. `0x372f020` twice, maker then taker, with scale 10^9. Maker block is slot `+0x68` for `0x28` bytes, taker block is `rbx+0x48`.
3. Token paid = row word `[!side]`. Free = total - hold, 0 when hold is larger, 0 for no row (`0x371b3a0` entry, tree `+0x10`).
4. Buy cap = free / px, floor. Sell cap = `0x32813d0(free, token)`.
5. Cap below size: cap 0 ends the walk with remaining 0, and with no fill yet the result is status `0x...12`. Otherwise size = remaining = cap, and the walk stops after this fill.
6. Legs `0x232d840` for buyer then seller. A sell has the maker as buyer. Each writes `0xf8` bytes. Tag 2, or notional above `2^63 - 2`, panics at `impl_insert_order.rs:768`.
7. `0x375e300` converts. Tag not 1, or `0x371b140` false, leaves this fill undone and **goes to the next level, not the next order**. Remaining is unchanged.
8. Settle `0x372b9d0`, then read px and size back from the record, so settle can change them.
9. Maker size minus size through `0x232e6e0`, which also gets book `+0xd0`, remaining down, total up, maker at 0 adds removal row kind 0, book `+0x78` = px, a `0x228` fill row.

### End of the walk

| How it ended | Effect |
| --- | --- |
| Limit reached, or levels used up | Taker row kind 1 only for given oid and tif 1, 3, 4 |
| Remaining 0 | Order may no longer rest. Given oid: taker row kind 1, and a second one for tif 1, 3, 4 |
| Band stop, no fill | Status `0x...13`, nothing applied |
| Band stop, fills | Order may no longer rest, given oid clears its relation tag through `0x26e7f30`, and also the order that tag 1 names |
| Cap 0, no fill | Status `0x...12` |

Then, always in this order: `0x27e7230` collects, each removal row runs `0x26e4620` then for kind 0 `0x26de3d0` with reason 1, each skip row runs `0x26de280` with its reason, the set is dropped.

No rest allowed and no fill: status `0x...08`. No rest allowed with fills: status row.

### Rest

`0x372f800` false: no fills gives `0x...13`, fills clear the relation and give a status row. Reserve `0x372d8f0` not `0x...18`: a given oid runs collect and `0x26e4620` once more, no fills returns the word with both payload words, fills give a status row. A word without the top bit acts as a buffer capacity: with fills, the payload pointer is freed with that size.

Otherwise the level comes from `0x25a7640` with bids `+0x80` key `-px`, asks `+0x98` key `+px`. The record takes the old tail as previous, next none, reduce byte 0, and goes through `0x232c410`, which returns the slot. Head is set only when absent, old tail gets next (panic `:445` on a bad tail), tail is set. Then oid map `0x27ca640`, client id map `0x342aa50` when `rbx+0x91` is set, user state `0x25a7a40` + `0x285cc70`, tracker `0x327b210`.

Status row: `0x26e10b0` builds the record, `0x24fb550` pushes row kind 3 inner 2, unless `rbx+0x70` is 9. That is the hold arm of the row kind 3 in #1058.

Result: fills Vec, user map, oid at `+0x30`, 17 client id bytes at `+0x38`, and byte `+0x49` set only when the order rested with a fresh oid. An error has `1 << 63` in word 0 and the status in word 1.

### Differences from the reference sketch

| Reference | Bytes of this body |
| --- | --- |
| `0x...17` means duplicate oid | No oid lookup. It is the second token test against state `+0x2e0` |
| Removes each filled maker inside the loop | Rows, applied after the walk. The tree stays whole during the walk |
| Filled maker event code 5 | Reason 1. A reason 5 arm exists for kind 2, and no write of kind 2 exists in this body |
| Fill size min of two sizes | Also capped by free balance, which can stop the walk |
| `price_level_allowed` from flags | 20% band on an anchor, only for second token 0 with first token listed |
| Failed match returns or breaks the level loop | Failed convert or settle test goes on with the next level |

### Dead arms in this body

Two user walks at `0x26eaca9..0x26eb774` never run here. The flag at `rsp+0x180` has one write before its read at `0x26ea018`, the zero at `0x26e8a3f`, and the map root at `rsp+0x1f8` has only the zero at `0x26e8a4f` (`dead_arm_words`). Their writers exist in the shape of the code, so a sibling body may use them. This is a reading of direct writes in the function. No address of these words leaves the function before the read.

### Edges

Stubs check their pointers, sizes and text, and log their arguments. Slot targets are in `slots` in `evidence.json`.

Refresh `0x372f930`, class `0x3728670`, tick `0x230b590`, mid `0x32780d0`, gate `0x26f4280`, `0x23978c0`, `0x2396d50`, anchor `0x375fb50`, predicate `0x37e4fb0`, fee class `0x372f020`, balance entry `0x371b3a0`, amount `0x32813d0`, convert `0x375e300`, `0x371b140`, settle `0x372b9d0`, leg `0x232d840`, size writer `0x232e6e0`, collect `0x27e7230`, `0x26e4620`, `0x26de3d0`, `0x26de280`, `0x28ad210`, `0x372f800`, `0x372d8f0`, `0x25a7640`, `0x232c410`, `0x27ca640`, `0x342aa50`, `0x25a7a40`, `0x285cc70`, `0x327b210`, `0x26e10b0`, `0x24fb550`, `0x26e7f30`, and four Vec grow helpers.

## Implementation and comparison

Not yet implemented in Rust. The comparison here is between the real bytes, run in the tool's evaluator with edges stubbed, and a separately written specification in the same tool. Both give the ordered edge calls, the result and the changed book words, and a test needs all three equal.

| Metric | Value |
| --- | --- |
| Cases | 405 |
| Mismatches | 0 |
| Instructions stepped | 549,658 |
| Stepped / total: spot insert body `0x26e81c0` | 2030 / 2857 |
| Stepped / total: user map leaf insert, run with no mutants `0x1ad9950` | 85 / 795 |
| Stepped / total: drop glue of the local result, run with no mutants `0x277bac0` | 92 / 175 |
| Stepped / total: user map insert wrapper, run with no mutants `0x2879d60` | 74 / 99 |
| Stepped / total: user map drop, run with no mutants `0x28a8ac0` | 23 / 33 |
| Mutants killed / survived / unreached | 659 / 38 / 264 |

Every surviving mutant has a reason in `mutations.tsv`, and they fall into a few classes: cleanup flags read only by unwind pads, stale or padding words, the feeders of the dead user walks, repeated bounds, a mask of a byte that is added back, and unrolled B-tree descents that need nine levels. Two first passes found real harness gaps (filler keys equal to the searched key, a dangling `8` pointer of an empty Vec, exact copy sizes, the status record tail, tree heights up to 4 and chains up to 16) and those now kill. The unreached rows are almost all the dead walks at `0x26eaca9..0x26eb774`. These reasons come from reading each site. Only one survivor was probed by a new case.

Negative controls in `tests/test_spot_order_insert.py`: wrong digest, a short file, a mid-function start, an address outside every mapping, a `.bss` address, wrong pin bytes, flipped branches at the quote gate, the limit stop and the buyer order, and a changed manifest digest.

## Results and limitations

- All cases agree on the ordered edge calls, results and book words.
- Fake state only. Rows and balances are chosen for the branches, not taken from a chain.
- Edge bodies are not read here, so names for them are from other packets or inference: `0x372f930` as refresh of a user, `0x37e4fb0` as a user class test, `rbx+0x90` as reduce only from its assert text. Status words have no names here beyond the reference labels, which this packet shows can be wrong.
- Inference: `rbx+0x90` set always ends at status 5, so a spot order with that byte never rests or trades. A slot with `+0xb0` set takes the reason 10 arm; this body itself writes 0 there.
- The two words in `ecx` and `r8d` are passed to the legs unread here.
- The other five bodies were not run. Their fills use other helpers, so nothing here extends to perp without a read.

No progress gate is requested.

Next question: the two dead user walks read the `r` Vec of book user states: which insert body sets the flag at `rsp+0x180`, and what does that walk cancel?
