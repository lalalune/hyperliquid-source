# RE-006: one order modify from the wire entry to the status: check, old order lookup, removal, insert, relink or child cancel

This packet gives a reconstruction the full body of an order modify on node #94 in all three execute instances: the check of the new order comes first, the old order is found by oid or through the client id map, a removal with reason 2 is flushed before the insert, a resting replacement inherits the old parent, peer and surviving children, and a failed insert cancels the children with the old order already gone. The reference says the old order is never found by client id and takes the peer from the insert result, and both are wrong, so `apply_modify` can now be written from tables instead of from that text.

- Component ID: RE-006 (book state transitions), the modify path from the wire entry to the per entry status
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are bodies `0x271c490`, `0x4d1c1c0`, `0x4d1dff0`, single wrappers `0x22be760`, `0x4c83210`, `0x4c83110`, batch closures `0x24be320`, `0x47f88a0`, `0x47f7c40`, book views `0x24fb450`, `0x24fb4e0`, `0x43297e0`, `0x445e150`, `0x445e1e0`, retains `0x25182c0`, `0x2517c10`, attach `0x26e3d40` and list clone `0x4847460`. Real bytes with no mutants: relink `0x43073d0`, attach `0x43032b0` and child cancels `0x4303040`, `0x43031e0`, `0x4302f70`, `0x4303110`, which are pinned by #108. Stubbed at the edge: resolver `0x3c0cc70` (#72), map lookup `0x342a430` (#983), check functions `0x21f7c40`, `0x21f8520` and copies, order lookups `0x26e54d0`, `0x26e7f30`, `0x43075d0`, `0x430d380`, removals `0x26df430`, `0x26de3d0` and copies, child removals `0x26de150`, `0x26de280` and copies, flushes, inserts `0x26c9cf0`, `0x26d0e50`, `0x4ca8510`, `0x4ca9710`, `0x445e270`, `0x445e9f0`, row conversions `0x2333f50`, `0x2333c40`, `0x4322660`, `0x4322350`, self checks `0x42fd530`, `0x42fc790`, allocator, memcpy. Excluded: the bodies of those stubs, the tree edits inside a removal or an insert, and the JSON writer of the result.

## Reproduce

From the repository root:

```
python3 tools/order_modify_path.py --out research/work-items/RE-006-order-modify-path-94
python3 -m unittest tests.test_order_modify_path
```

The tool takes about 50 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### Path map

| Step | First | Second | Third |
| --- | --- | --- | --- |
| Dispatch caller of the wrapper | `0x2759240` | `0x4d84170` | `0x4d83050` |
| Single wrapper | `0x22be760` | `0x4c83210` | `0x4c83110` |
| Batch closure | `0x24be320` | `0x47f88a0` | `0x47f7c40` |
| Body | `0x271c490` | `0x4d1c1c0` | `0x4d1dff0` |
| Check, perp and spot | `0x21f7c40`, `0x21f8520` | `0x4c18260`, `0x4c17b10` | `0x4c18b40`, `0x4c19420` |
| Removal, perp and spot | `0x26df430`, `0x26de3d0` | `0x42f97f0`, `0x42f8840` | `0x42fa880`, `0x42f7890` |
| Insert, perp and spot | `0x26c9cf0`, `0x26d0e50` | `0x4ca8510`, `0x445e270` | `0x4ca9710`, `0x445e9f0` |
| Relink | inline, `0x25182c0`, `0x2517c10`, `0x26e3d40` | `0x43073d0` | `0x43073d0` |
| Child cancel | inline loop over `0x26de150`, `0x26de280` | `0x4303040`, `0x43031e0` | `0x4302f70`, `0x4303110` |

#393 names the three dispatch functions as execute instances 0, 2 and 1. The second and third bodies are equal once call and rip displacements are masked, except 10 rows naming a state field (`copies`); the third state fields are listed there. The first body has another size, 6987 against 7715 bytes (`pairs_of_other_size`), so it is compared by running one specification on all three. Each body has two sites of slot `0x5774aa0` and two callers: its wrapper and its closure (`call_sites.tsv`).

### Wire entry and compact order

| Field | Offset in the 0x50 byte entry |
| --- | --- |
| Key byte | `+0x00` |
| Client id of the old order | `+0x01`, 16 bytes |
| Oid of the old order | `+0x08` |
| Order block | `+0x18`, 0x38 bytes |
| Asset dword | `+0x38` (order `+0x20`) |
| Client id tag of the new order | `+0x3c` |
| Client id of the new order | `+0x3d`, 16 bytes |
| Two final bytes | `+0x4d`, `+0x4e` |

The single wrapper rebuilds the order block: a tag equal to 1 stays 1 with its 16 bytes, any other tag becomes 0 and the bytes are not copied. The batch closures copy the 0x38 bytes as they are, so a tag of 2 reaches the check unchanged. The wrapper returns byte `0xd` on `0x186`, else byte `0xe` with the 0x60 status bytes at `+0x08`. Batch closures store each 0x60 byte status in entry order and free the staged list with its capacity. The first closure writes into a shared result buffer after its start index; the other two allocate `n * 0x60` themselves.

### One replacement

Arguments: `rdi` status out, `rsi` state, `rdx` user, `rcx` key, `r8` order. Steps are the same on all three bodies.

1. Resolver `0x3c0cc70(order +0x20, state + names, state + 0x90)`. An error is the status, all 0x60 bytes, no hook.
2. Kind dword 1 is spot, any other kind is perp. Spot with state byte `+0x3ac8` set gives `0xf9`, no check, no hook.
3. Check of the new order. An error is the status, all 0x60 bytes, no hook. The old order is still in the book. On success `+0x08` of the result holds a 0x48 byte record, and the book comes from record `+0x28`, not from the wire asset.
4. Book. Perp: `dex = value / 10000`, `local = value % 10000`; `dex >= rows length` panics at `l1/src/dex_registry/perp_dex.rs:30` through unwrap of word `0x141`; `local >= count` panics at the location in `locations`. Spot: index against the spot count.
5. Old oid. First body: key byte bit 0 set means map lookup. Second and third: key byte equal to 1 means map lookup. Bytes 0 and 1 agree on all three. A map miss gives `0x38`. Else key `+0x08`.
6. Order lookup. Absent gives `0x38`.
7. Shape: old `+0x90` must equal record `+0x31`, old `+0xa2` must equal record `+0x30`, and when the old order has a parent, record kind `+0x19` must not be 2. Else `0x39`.
8. Old links are copied to the stack: parent, peer, kid list, and the tag and 0x20 bytes at `+0x48`, `+0x50`.
9. Removal with reason 2 (`r9d`), rows into a new Vec, then flush.
10. Insert with a built group, the 0x50 byte argument #926 names: tag 1 with the 0x20 bytes when old `+0x48` is 1, else tag 0, then an empty child Vec and zeros. Tags 2 and 3 never pass here, so a modify never sends a child list or a twap slice tag. The dex row accessor at `state +0x3368` and the book view run whatever the insert returned.
11. Insert word other than `0x186`: each copied kid goes through the child removal with reason 2, in list order, gone or not, then one flush. Word `0xc4` becomes `0x3a` and keeps the String at `+0x08`, dropping the asset dword. Any other word is the status, all 0x60 bytes.
12. Insert word `0x186`. Bit 0 of insert result `+0x51` clear: the kid list is freed, and no link changes. Bit set: relink below, with the new oid from result `+0x38`.
13. Perp reads `state + names` row by dex, spot passes `state + 0x90`. The row conversion takes 0x50 bytes from result `+0x08` and writes 0x30 bytes to status `+0x08`; the row Vec is freed with stride 0x238 perp, 0x228 spot.
14. Hook: when state `+0x3a88` is set, method at table `+0x40` gets user and `status != 0x186`. This runs on every path from step 5 on, and not on steps 1 to 3. Cancel uses method `+0x38` with a third argument.

### Relink

| Step | First body | Second and third |
| --- | --- | --- |
| Keep only kids still in the book | `0x25182c0`, `0x2517c10` | `0x43073d0` first loop |
| Old parent lists the new oid, once, and the new order names the old parent | `0x26e3d40` with a one item list | `0x43032b0` with a one item list |
| When the old peer is still there: new order names it, it names the new oid | inline at `0x271cf43`, `0x271d53e` | `0x43073d0` at `0x43074ac` |
| New order takes the kept kids, each kid names the new oid | `0x26e3d40` | `0x43032b0` |

The two columns are one rule. The same specification predicts the final links on all three bodies, in all 470 cases. `0x26e3d40` writes the kids' parent even if the target order is gone, and the new order names the old parent even when that parent has left the book. Second and third bodies build a whole stack body and hand it to `0x43073d0`, which reads `+0x10..+0x47` only.

### Status words

| Word | Text | Source |
| --- | --- | --- |
| `0x38` | `Cannot modify canceled or filled order` | old order not found: map miss or oid miss |
| `0x39` | `Attempted to modify to invalid new order` | byte +0x90 or +0xa2 differs, or the old order has a parent and kind is 2 |
| `0xf9` | `Spot disabled` | spot route with the state byte set; no check and no hook |
| `0x3a` | `Error placing new order during modify: <String>` | insert failed with 0xc4 after the old order was removed |
| `0xc4` | `<String> asset=<dword>` | insert status that turns into 0x3a |
| `0x186` | `no fixed text in the arm` | replaced; the hook flag is 0 only here |

### Reference labels

`reference_claims` holds the checks. Wrong: the old order is resolved by client id when the key byte says so, and the peer comes from the old body, not from the insert result. Incomplete: the reference rebinds every child, has no retain and no link from the old parent, and has no group argument or hook. `0x3a` from 196 and the child prune on failure agree.

### Inferences

- Marked as inference: the key byte is an enum tag, so only 0 and 1 occur and the two tests of step 5 agree on real input. Reason 2 is `canceled`, from the status serializer table cited in #161. Old `+0x90` and `+0xa2` are the reduce and side bytes the reference names: the bytes prove only the compare. Record kind 2 is the reference `tif_code` 2.
- A replacement that does not rest leaves kids naming the old oid. This follows from step 12; what the insert or a later sweep does to those kids is outside this packet.
- A failed insert leaves the old parent listing the removed oid unless the removal itself cleans it, and #108 owns that removal. Nothing restores the old order.

### Unresolved

- Whether the check at step 3 can pass on a record whose packed asset leads to another book than the resolver route. The body reads only the record.
- What the 0x20 bytes at old `+0x50` mean. #926 lists them as the group payload and shows that insert request `+0x48`, `+0x50` store tag and payload at the same offsets as the old body.
- Meaning of insert result `+0x51` beyond its use here.
- The third resolver kind: kind 2 runs as perp here; whether the resolver returns it is not read.

## Implementation and comparison

not yet implemented. The file carries a specification in Python only as a check of the bytes.

## Results and limitations

| Cases | 470 |
| Mismatches | 0 |
| Instructions stepped | 176,039 |
| Stepped / total: first body: one replacement | 1008 / 1250 |
| Stepped / total: first single wrapper | 59 / 59 |
| Stepped / total: first batch closure | 81 / 97 |
| Stepped / total: first perp book view | 28 / 37 |
| Stepped / total: first spot book view | 21 / 30 |
| Stepped / total: second body: one replacement | 1070 / 1281 |
| Stepped / total: second single wrapper | 59 / 59 |
| Stepped / total: second batch closure | 110 / 143 |
| Stepped / total: second perp book view | 28 / 37 |
| Stepped / total: second spot book view | 18 / 27 |
| Stepped / total: third body: one replacement | 1070 / 1281 |
| Stepped / total: third single wrapper | 59 / 59 |
| Stepped / total: third batch closure | 110 / 143 |
| Stepped / total: third spot book view | 18 / 27 |
| Stepped / total: first retain of kids, perp arm | 77 / 91 |
| Stepped / total: first retain of kids, spot arm | 77 / 91 |
| Stepped / total: first attach of kids | 101 / 115 |
| Stepped / total: second and third spot clone of the kid list | 41 / 47 |
| Stepped / total: second and third relink, run with no mutants | 119 / 133 |
| Stepped / total: second and third attach, run with no mutants | 101 / 115 |
| Stepped / total: second perp child cancel, run with no mutants | 53 / 63 |
| Stepped / total: second spot child cancel, run with no mutants | 51 / 61 |
| Stepped / total: third perp child cancel, run with no mutants | 53 / 63 |
| Stepped / total: third spot child cancel, run with no mutants | 51 / 61 |
| Mutants killed / survived / unreached | 972 / 80 / 145 |

Every surviving mutant has its reason in `mutations.tsv`, and they fall into five classes: context words the view does not read, drop flags read only by unwind pads, dangling pointers of an empty list, capacity overflow tests, and old body fields copied into a stack body that `0x43073d0` never reads. Unreached rows are allocator failure arms, panic arms, unwind pads, the old body client id tag, and the drop of a rows vector that is empty on that path.

Limits: every case uses fake state. Order lookups are stubbed over a Python table, so tree shapes do not matter here. Kid lists reach 5 items. A batch of 10000 entries is not run. The list length gate of batch modify is outside this packet. A mutant counts as killed only if a run differs in the edge log, the final links, the status bytes or live allocations.
