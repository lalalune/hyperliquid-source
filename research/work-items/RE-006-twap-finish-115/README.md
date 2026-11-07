# RE-006: node #115 TWAP finish step, from taking the order out of the tracker to the pushed status event

This packet rebuilds, and proves on the bytes of node #115, what happens to a TWAP order that the advance step has decided is finished: the tracker removes the order from the user's order ring (and removes the user record itself once that ring is empty), the status builder is chosen from the record tag, the asset's market is found by dividing the asset id by 10000 (perp only), and a 0xc0-byte defined prefix of a tag-4 event (`0x2b8` bytes perp, `0x2c8` bytes spot) is pushed on the output vector, which grows when full. A Rust node can now take the removal rule, the empty-user rule, the error and reason-freeing rule, the market bound and the event layout from one checked specification instead of from the node #94 reading or from a stubbed callee.

- Component ID: orderbook (work item RE-006)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace commit `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; no node #94 packet is used, every address, offset and rule below is read from node #115 bytes
- Claim status: observation for every row the evaluator ran against the bytes; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: the four finish callees `0x5a17dd0`, `0x5a18190` (perp) and `0x5a18550`, `0x5a18840` (spot) from the first byte to the return, and the two take functions they call, `0x5a10250` (perp) and `0x5a10560` (spot), all run as real code, every instruction of the take functions included (170 of 170), with both the ring arm and the tree arm of the user search; the vector push and the grow decision; the reason-string free; the market bound check and its failure
- Scope excluded: the precheck `0x5a11b80` / `0x5a11970`, the order removal `0x4ddfa30` / `0x4dde450`, the user removal `0x4dddf70` / `0x4ddfdc0`, the user ring search `0x57f4ac0` of the ring arm, the four status builders `0x5181da0`, `0x5182b60`, `0x51821b0`, `0x5182640`, the drops `0x5a4a6f0`, `0x44e0810`, `0x5248950` (all stubbed, arguments checked); the unwind landing pads `0x5a3e1d0`, `0x5a40ae0`; the Rust allocator and expect-failure slots
- Related work: the advance step that calls these bodies is the open node #115 `RE-006-twap-advance-115` packet, which stubs the finish callee; this packet runs what it stubbed. The slice step before it is the open `RE-006-twap-slice-115` packet. This packet shares their evaluator head, nothing else.

## Reproduce

Run from the repository root with Python 3 and the standard library; the shared `tools/elf_index.py` and `tools/fde_extents.py` parse the ELF. No external program runs, the binary is never executed, and nothing touches a network. The tool refuses any other digest. One full run takes under a minute and stays below 400 MB.

```
python3 tools/twap_finish_115.py --out research/work-items/RE-006-twap-finish-115 --sample 3
python3 -m unittest tests.test_twap_finish_115
```

The committed files were produced with 3000 random cases per finish copy, every third case written to `cases.tsv`, and at most 60 branch flips per representative copy. `MANIFEST.sha256` lists every file in this folder except itself.

## Evidence

Coordinates are ELF virtual addresses in `.text` and `.rela.dyn`; function bounds are FDE bounds from the shared parser (`copies.tsv`). Every table is generated from the bytes or from a run of the real instructions.

### Observations: the call shape

`callees.tsv` lists, per finish copy, the take function, the precheck, the order removal, the user removal and the two status builders. `copies.tsv` gives bytes, instructions and the instructions the cases actually stepped: each perp finish 955 bytes (173 instructions, 151 stepped), each spot finish 750 bytes (137, 123), each take function 779 bytes (170, 170). The two perp finish copies differ in exactly two instructions: the market buffer and count offsets (`+0x7c8`/`+0x7d0` against `+0x1338`/`+0x1340`). The two spot finish copies have the same instruction shapes, and the perp and spot take functions differ only in three call targets (`copy_differences.tsv`, 6 rows). Imported functions (`free`, `memcpy`) have no relative relocation, so the harness gives their import slots synthetic targets; Rust runtime slots with relative addends are resolved through `.rela.dyn`.

### Observations: the take rule (`0x5a10250`, `0x5a10560`)

1. Arguments: output slot, tracker, 20-byte user key, order id. The key is copied, then the precheck runs on the tracker and the key. If the byte at result `+8` is not 2 the take returns at once with a zero 16-byte head and the 0x58 precheck bytes copied behind it (tag word at `+8` is 0, so the finish treats it as the alternative record).
2. Otherwise the user ring at `tracker + 0x18` (capacity, buffer, head, length; 0x38-byte records) is searched. A capacity word of `0x8000000000000000` selects the tree arm: `tracker + 0x20` is the root node (a null root is the error), `tracker + 0x28` the height; a node holds 32-byte order-ring values at `node + 0x20 * i`, 20-byte keys at `node + 0x168 + 0x14 * i`, its key count as a u16 at `+0x246` and child pointers at `+0x248 + 8 * i`. Each key is compared with the user key (20-byte compare, sign of the result), larger user keys step on, an equal key is the value, a smaller key or the end of the node descends through child `i` while the height counter has not run out, and a leaf without a match is the error `0xd4`. In the ring arm an absent user, or a logical position at or past the length, is the error `0xd4` (result tag 1). The record is `buffer + physical * 0x38` where physical is position plus head, minus the capacity when not below it.
3. The order removal gets the record's order ring (`record + 0x18`) and the order id. A returned body whose byte `+0x22` is 2 means no order and is the same error `0xd4`.
4. Otherwise, if the order ring length (`ring + 0x18`) is now zero the user removal runs and its first result word decides the clean-up: `0x8000000000000000` calls the tree drop, `0` and `0x8000000000000001` free nothing, anything else frees `word * 0x70` bytes at the returned pointer.
5. In both arms the value found is the order ring that the removal and the emptiness test use. The result is tag 0, word `+8` equal to 1, then the 0x68-byte order body at `+0x10`.

### Observations: the finish rule (`0x5a17dd0`, `0x5a18190`, `0x5a18550`, `0x5a18840`)

1. The take runs first. Result tag 1 (the error): the error value is dropped, then the reason string at the fourth argument is freed when its signed capacity is above zero. The usual argument word is `0x8000000000000002`, which is negative, so it is never freed.
2. Otherwise the record body sits at result `+0x10` and the tag word at `+8`. Perp reads the asset id from the first body word when the tag's low bit is set and from the third word otherwise, and divides by 10000 with the multiply-and-shift constant `0x346dc5d63886594b` (checked equal to integer division by the unit tests). An index at or above the market count in the outer object (`+0x7c8`/`+0x7d0` or `+0x1338`/`+0x1340`) is an expect failure with the message of `0x2b` bytes. A good index gives the market at `buffer + index * 0x510`.
3. Spot has no market lookup; the book pointer `outer + 0x90` goes to the builder, and the tag selects `0x5182640` when it equals 1 and `0x51821b0` otherwise. Perp selects `0x5182b60` when the low bit is set and `0x5181da0` otherwise, after dropping the temporary word `0x156` (perp only).
4. The status builder gets the record body and the market or book and returns 0x78 bytes. Those 0x78 bytes plus the 24-byte reason string become 0x90 bytes copied behind the event tag 4. The event then holds the order id at `+0x98`, the 12-byte moment from `outer + 0x60` at `+0xa0` and the user key at `+0xac`; the first `0xc0` bytes are defined, the rest of the 0x2b8 / 0x2c8 bytes is stack content.
5. The output vector (capacity, buffer, length) grows through a vector-grow call when length equals capacity, then the whole event is copied to `buffer + length * size` and the length is increased.

### How it was run

The harness fills the tracker ring, the user buffer, the order ring header, the outer object and the vector with position-dependent filler, so a wrong offset shows. Stub calls are recorded in order with their arguments (the stubs are told nothing beyond what the stubbed function would have been given); the status builders are stubs that return a hash of the name, record and market argument so a wrong builder, record or market shows in the event bytes. The specification `spec_finish` is separate code that predicts the whole ordered event list, the pushed event prefix, the vector and the order ring length. 12168 cases (4 copies x (42 named + 3000 random), about one random case in five with the users in tree form of height 0 or 1) all match. `outcomes.tsv` counts the outcomes per copy.

## Implementation and comparison

Rust implementation: not yet implemented. The comparison model is `spec_finish` in `tools/twap_finish_115.py`; the status builders, precheck, removals and drops are stubbed with the stated contracts, so the packet proves the control flow, field offsets, ring arithmetic and event layout of the bodies listed under scope, not those callees.

Negative controls (72 counted, 72 detected):
- 20 wrong specifications (`variants.tsv`): asset id read from the other word, market index divided by 1000, accepted index equal to the count, reason freed for any nonzero capacity, reason freed at zero capacity, user removed with orders left, user never removed, no-user marker frees a buffer, event tag 5, user before order id in the event, no temporary drop, builders swapped, other error code, 0x68 freed element size, no vector grow, precheck after the search, position past the length accepted, no wrap of the physical slot, spot book at a different offset, tree search stepping the wrong way. Each disagrees with the bytes on at least 66 cases.
- 39 conditional-branch flips on the bytes of the representative perp and spot finish and take functions, all reached by the cases, all detected (`mutants.tsv`; no survivors).
- 4 structural refusals (wrong digest, address outside every FDE, not an FDE start, inside another body) and 9 byte pins (divisor constant, strides, event sizes, temporary word, copy 2 offsets) that each fail on a one-byte corruption.

## Results and limitations

- 12168 cases, 0 mismatches on the first full run (the first run with the tree arm included); 72 of 72 negative controls detected.
- New against what the advance packet could say: the finish callee removes the order from the user's ring and deletes the user record when the ring empties; the perp finish panics (expect) when the asset's market index is not below the count and the spot finish has no such bound; the reason string is freed only on the error path and only for a positive capacity; the event layout is the one above.
- Limits: the tree arm is run only on synthetic trees of height 0 and 1 (one root, or a root with leaves), not deeper ones or ones with split nodes at full width beyond 11 keys; the status builders, precheck, order removal, user removal and drops are stubs with checked arguments, so the float computation of the status record, the order removal inside the ring and the precheck's reasons are not proven; the unwind landing pads are not run; generated rings are small (capacity at most `0x50`), so the 64-user promotion is not exercised here. The 0x78-byte builder output is a stub value; the tool does not claim its content. The packet does not claim the orderbook gate or any component gate.
- Next question: the four status builders (`0x5181da0` 1,029 bytes, `0x5182b60` 1,202, `0x51821b0` 1,167, `0x5182640` 1,304; leaf functions with SSE arithmetic over a power-of-ten table), then the precheck `0x5a11b80` / `0x5a11970`, the order removal `0x4ddfa30` / `0x4dde450` and the user removal `0x4dddf70` / `0x4ddfdc0`.
