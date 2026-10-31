# RE-004: gossip priority bid gates and IPv4 parser in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the order of the tests, the serde keys, the status text and the slot target; inference for the action name on this handler and for the meaning of the words; unresolved items are listed under limits
- Scope included and excluded: included are the handler `0x2727bc0`, the charge wrapper `0x2206560` and the parser `0x1573af0`, run as real bytes. Stubs here: the info helper `0x3987cb0`, the two error drops `0x277eba0` and `0x3c1ada0`, the price (slot `0x57739b8`), the user lookup (slot `0x5773170`) and the charge core `0x26c79d0`. Excluded: the caller that decodes the action, the two other copies of this handler (their addresses are listed by a dispatch packet), the price function, and the charge core.

## Reproduce

```
python3 tools/gossip_bid_gates.py --out research/work-items/RE-004-gossip-bid-gates-94
python3 -m unittest tests.test_gossip_bid_gates
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about a minute.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). FDE extents are exact: `0x2727bc0..0x2727f2a` (190 instructions), `0x2206560..0x22065f5` (42), `0x1573af0..0x1573ec2` (278). Each of the first two has one direct call (`direct-calls.tsv`). The parser has 36.

Handler arguments: `rdi` output, `rsi` state `S`, `rdx` user (20 bytes), `rcx` IPv4 word (see below), `r8` slot id, `r9` limit flag, stack word gas limit. `.rodata` holds `slotIdipmaxGas` and `struct GossipPriorityBidAction with 3 elements` (`rodata-text.tsv`).

`S` fields read here:

| Offset | Bytes read here |
|---|---|
| `+0x0` dword, `+0x8`, `+0x28`, `+0x8f2` byte | inputs of the info helper, called only when the dword is 1 |
| `+0x60` | passed to the price function |
| `+0x80` | passed to the user lookup |
| `+0x3610`, `+0x3618`, `+0x3620` | `Vec` of auctions: word, pointer, length, stride `0x50` |

Auction fields, stride `0x50`: `+0x30` the key of the balance tree in step 6, called `token` below; `+0x40` key `cw`, `+0x45` key `pw` (`winner-fields.tsv`, from the `lea 0x40(%rbx),%rcx` and `add $0x45,%rbx` bytes before each key). Both go through the helper at `0x2970dd0`, which prints `null` when the first byte is 2 (`winner-null.tsv`).

Status text comes from the Display table `0x59a8d0` (`status-text.tsv`):

| Tag | Text |
|---|---|
| `0x181` | Gossip priority gas auction disabled |
| `0x182` | Invalid gossip priority gas auction slot |
| `0x178` | Gas fee is greater than the maximum fee set by user |
| `0x179` | Insufficient gas at current auction price. |

Order of the tests:

1. If the low dword of `S+0` is 1, the info helper fills a block of `0x20` bytes; otherwise the block is zero.
2. `xor %eax,%eax; cmp S+0x3610,%rax; jo` is true only for the word `2^63`: `0x181`. So the list is an `Option` with the capacity word as its niche. Words beside `2^63` pass in the runs.
3. `slot >= length` (unsigned): `0x182`. Auction `A = pointer + slot * 0x50`.
4. Price from slot `0x57739b8`, whose RELATIVE target is `0x325ccb0` (`slots.tsv`). An error is copied out whole (`0x60` bytes).
5. Bit 0 of the flag and `price > limit` (unsigned): `0x178` with `(price, token, 0)`. `price == limit` passes. The other flag bits are ignored.
6. Balance row: user lookup, then a B-tree keyed by the token `A+0x30` as u64, compared unsigned, node keys at `+0x8` and values of `0x18` bytes at `+0x60`. Value `+0` is `total`, `+8` is `hold`. No tree, an empty tree or no row gives `(0, 0)`.
7. `hold + price` wraps, or is above `total`: `0x179` with `(price, token, 0)`. Equal passes.
8. `0x2206560` calls `0x26c79d0` with `S`, the user, `(price, token, 0)`, the info block, zero, `A` and the closure `0x22155a0`. An error is copied out whole.
9. On success, and only then: `A+0x40` takes the low 4 bytes of the IPv4 word and `A+0x44` its next byte. Status `0x186`.

`price-pieces.tsv`: for fixed rows, the price splits into pieces whose two ends walk the same rows with the same status. With `total = 1000`, `hold = 100`: `0..=900` passes, `901..=2^64-101` refuses by the compare, and `2^64-100..` refuses by the wrap branch. With no row, price 0 passes.

The IPv4 word in the caller's use is `a<<8 | b<<16 | c<<24 | d<<32`, so five bytes `0, a, b, c, d` land at `+0x40`. The handler takes this word as given.

Parser `0x1573af0`. Input: a slice `(ptr, len)` by reference. Output: `rax = 1 | a<<8 | b<<16 | c<<24 | d<<32`, with the slice moved past the last digit. On failure the low byte is 0 and the slice is put back. Four octets separated by `.`, each one to three digits, value below 256, and a digit string of two or more that starts with `0` is refused. A fourth digit is refused. Text after the last digit stays in the slice for the caller.

`parser-octets.tsv`: every string of 1, 2 and 3 digits in each of the 4 positions, 4440 runs, and exactly 256 are accepted per position (10, 90, 156). `evidence.json`: every byte value at each place of `123.123.123.123` (3840 runs, 586 accepted), plus 165 chosen strings. Digits sit past the slice end in each run, so a read past `len` changes the result.

Reference compare. `gossipPriority` appears in a comment in `l1/exchange/impl_execute_action.rs`, and `gossipPriorityAuctionStatus` in the info server. No rule for the bid is there: this packet has no reference counterpart to check.

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the status, all fixture bytes and the event list of each handler run, and `spec_parse` for the parser.

## Results and limitations

- 103 named cases and 600 generated cases: 0 mismatches, comparing fixture bytes, stub arguments and event order, over real B-tree nodes up to height 2 with stale keys in unused slots.
- All rows of the three functions are reached (`evidence.json`).
- 249 byte edits on reached rows: 232 killed, 17 survived, each with a recorded reason (`mutations.tsv`). All survivors are in the parser; the handler and the wrapper have none. An unedited image must pass under the same step limit first.

Limits:

- `gossipPriorityBid` on this handler is an inference: it rests on the argument shape, the status text and the `slotId`, `ip`, `maxGas` keys. Which caller fills the arguments was not read in this packet, so the limit flag as `maxGas` being set, and `r8` as `slotId`, are inferences too.
- The caller's own bounds on those inputs are not covered, and neither are the two other copies of the handler.
- `total` and `hold` are labels for value words `+0` and `+8`, and `token` for the key; only the rule on them is observed.
- `cw` as the current bidder is an inference from the keys and this store. `pw` is not written here. The first stored byte being 0 is observed; that it selects IPv4 is an inference, since only value 2 was traced, in the serializer.
- The price is a stub, so only its use is pinned; its rule is the subject of another packet. The price word can be 0 in these runs; whether the real function can return 0 was not traced here.
- The charge core is a stub, so nothing here shows what it debits, or whether a later bid replaces an earlier one at a higher price.
- The parser is run over the strings above, not over all strings of up to 15 bytes.
- For tags `0x178` and `0x179`, bytes past the three payload words are stale stack bytes and are left out of the compare.
- The info block contents are a marked fixture; `0x3987cb0` is another packet's subject.

Next question: which function moves `cw` to `pw` when a slot rolls, and does the charge core refund the previous bidder of the slot?
