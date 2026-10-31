# fees: request budget of node #94: the cap, the used and surplus split, reserved weight and action weights

- Component ID: fees (Fees and volume, path rule `l1/scaled_vlm.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: repository 1f8c67c63ca4794c9689235471c60297f8a5c985, reference tree `references/can1357-hl` at 999556f6e0a474b8312db96ec3149e1c44e97c23 (labels checked as clues only)
- Claim status: observation for addresses, branches, constants and every value in `vectors.tsv`; inference for the names `userRateLimit`, `nRequestsUsed` and `expiresAfter` and for the dollar unit; unresolved for where, or whether, this binary compares used with the cap
- Scope included: handler 0x2758ae0 and copies 0x4d82190, 0x4d82320; view 0x21e2910, volume sum 0x275f500, row lookup 0x2755580; weight function 0x33632e0 with 0x3a1b6c0; row get-or-insert 0x1f849b0 + 0x27c3c90 and 0x47d7ca0; listed address ranges of 0x2208580, 0x27584a0, 0x24bcae0
- Scope excluded: balance read 0x36f7560, debit 0x370a3d0, credit 0x37067b0 (stubs that check their arguments), the rest of the three range functions, the fees that a fill charges

## Reproduce

Run from the repository root, Python 3 standard library only. No objdump, readelf or other external program runs, and the node is never run.

```
python3 tools/fees_request_budget.py --out research/work-items/fees-request-budget-94
python3 -m unittest tests.test_fees_request_budget
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The first command took 175 s on 3 worker processes and rewrites `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv`, `reference-diff.tsv` byte for byte. It checks the SHA-256 of the input first and stops on any other input, on any model mismatch, on an unlisted unexecuted instruction, and on a mutant survivor outside the listed equivalents. ELF sections and FDEs come from `tools/elf_index.py` and `tools/fde_extents.py`.

## Evidence

Coordinates are virtual addresses. Function ends are FDE ends; the decoder must land on each one. The three range functions are decoded only over the ranges in `evidence.json`, and each range must land on its own end.

### Reserved weight: 0x2758ae0, 0x4d82190, 0x4d82320

Three bodies of 390 bytes each. Arguments: result record, exchange, user address, weight `w`.

| step | result |
| --- | --- |
| first dex list empty | panic through `unwrap` (0x2758c43, message length 0x2b, error tag 0x141) |
| `w * 500` overflows u64 | status 0x13f, no payload written |
| cost >= 0x0ccccccccccccccc | status 0x13f, payload = cost |
| balance of first dex row < cost | status 0x34, no state change |
| else | debit cost, credit cost to exchange +0x5d0 (+0x1050 in 0x4d82190), row get-or-insert, row +0x28 saturating `+= w`, status 0x186 |

Status text from the Display table at 0x59a8d0: 0x13f "Invalid input number"; 0x34 "Insufficient balance to reserve request weight.". The row stamp is not written here, and weight 0 still creates a row when the balance check passes.

Excerpt, for reading only (binutils, not part of the evidence files):

```
2758b23: mov $0x1f4,%ecx
2758b2b: mul %rcx
2758b2e: jo  2758c16
2758b48: movabs $0xccccccccccccccc,%rax
2758b52: cmp %rax,%rbp
2758be5: add 0x28(%rax),%r14
2758bf0: cmovae %r14,%rcx
```

### Row of the budget

Hash table of 0x58-byte buckets at exchange +0x740 (+0x11c0 in the other exchange shape), 20-byte key, value at bucket +0x18. Words read here:

| value offset | use |
| --- | --- |
| +8 | total charged weight, saturating add at 4 sites |
| +0x28 | reserved weight, saturating add in the handlers |
| +0x30 | 12-byte time: packed date, seconds, nanoseconds |

A new row (0x1f849b0 and 0x47d7ca0) is zero except the date, which is the result of the date helper on day 719163: 0xf6401a, 1970-01-01. Bytes +0x3e, +0x3f and the 4 bytes between key and value stay unwritten. The default cells behind slots 0x57749b8 and 0x5773960 are built the same way (0x34d71a0, 0x3790ee0).

### View: 0x21e2910

Arguments: result record, state, user. One direct caller, the wrapper 0x27d0780 at 0x27d085b (itself called once, at 0x2587905), which passes state = its second argument + 0x570 under a read lock at +0x568. With `S` from the sum below, `T` = row +8, `R` = row +0x28:

| record | value |
| --- | --- |
| +0 | `S` |
| +8 | `max(T - R, 0)` |
| +0x10 | `S / 100 + 10000` (floor) |
| +0x18 | `max(R - T, 0)` |
| +0x20 | 12-byte time, the later of row +0x30 and value +0x10 in the B-tree at state +0x4450 |

A user with no row reads the default cell, so `T = R = 0`. The time compare is signed on the date word, then unsigned on seconds, then on nanoseconds. Tree node: values stride 0x20 at +0, keys stride 20 at +0x168, length u16 at +0x246, edges at +0x248. The wrapper stores `S / 100.0` as f64 at its result +0 (divsd at 0x27d0972, constant 100.0 at 0x20a960) and copies the next three words; that float path is pinned as bytes, not evaluated.

### Volume sum: 0x275f500

For each row of list +0x1040 (stride 0x2f0) the helper 0x36f57f0 on row +0xf8 gives value +0x40 and +0x48; then 0x371b3a0 on state +0x80 gives value +0 and +8. Result `(rax, rdx)`. Each of the 4 adds that carries calls the recorder 0x358dcd0 with `rdi = 0`, then saturates. Records: l1/src/qtys/impl_ntl.rs:664:1; l1/src/scaled_vlm.rs:15:21; l1/src/raw_vlm.rs:17:21.

### Weight of an action: 0x33632e0, 0x3a1b6c0

Reads the u64 tag at +0 and jumps through table 0x5896dc (88 rows from tag 0x74; a smaller tag takes row 20). Rows outside the table are not reached by any vector.

| tag | weight |
| --- | --- |
| 0x76, 0x77, 0x78 | `max(word +0x18, 1)` |
| 0x82 | `max(word +0x40, 1)` |
| 0x8b | `word +0x18 / 20 + 1` |
| 0xb8 | `word +0x20 / 20 + 1` if byte +8 is 2, else 1 |
| 0xa8 | weight of the action at pointer +0x20, times `max(word +0x18, 1)`, u64::MAX on overflow |
| every other tag | 1 |

### Charges to row +8

`charge_sites` in `evidence.json` scans the 41 + 83 direct calls of the two get-or-insert helpers for an add to row +8 or +0x28 as the next instruction. It finds the adds to +0x28 of the three handlers, the four adds to +8 below through 0x1f849b0, and 8 more adds to +8 through 0x47d7ca0 in other function bodies (listed there, with their functions, and not evaluated here). A row pointer kept in another register first would not show. The four below saturate and stamp row +0x30.

| site | condition | added |
| --- | --- | --- |
| 0x2208745, in 0x2208580 | record word +0 == 1 and word +8 below now in ms | `w * 5` (u64::MAX on overflow), result byte 0xe, status 0xca |
| 0x2208849, in 0x2208580 | otherwise | `w` |
| 0x27585ce, in 0x27584a0 | inner result byte 0xf and u16 status 0xca | `w * 4` (top two bits set: u64::MAX) |
| 0x24bcdba, in 0x24bcae0 | low bit of bpl set and word below now in ms | `w * 4`, stamp from the pointer at rsp+0x50, status 0xca |

Now in ms is computed from the 12 bytes at exchange +0x60, floored at 0: `(days * 86400 + seconds) * 1000 + nanoseconds / 1000000`. The compare is strict: a word equal to now is not expired. Status 0xca text: "Action already expired". 0x2208580 calls 0x27584a0 at 0x2208bfc after the `w` add, so that path can reach `w + 4w`; the code between those two points is outside the ranges evaluated here.

### Search for a gate

`cap_scan` in `evidence.json`: the u64 reciprocal of 100 appears in 113 functions, and only 1 site has the bytes of 10000 within its window (0x21e2aba). String counts in the file: `Too many cumulative` 0, `cumVlm` 2, `nRequestsCap` 1, `nRequestsSurplus` 1, `nRequestsUsed` 1, `reserveRequestWeight` 3, `userRateLimit` 1.

### Inferences, kept apart from the above

- The view is the `userRateLimit` record: `cumVlm`, `nRequestsUsed`, `nRequestsCap` are adjacent strings at 0x4203ad, and `nRequestsSurplus` is a separate 16-byte literal at 0x207b90. So the cap is 10000 plus one request per unit of `S / 100`, and with the f64 division by 100 the volume word reads as cents and the unit as one dollar. Nothing in these bytes shows the currency.
- The first two words of the record at 0x2208580 are `Option<u64>` expiresAfter in ms, because that is what the reference has next to this kind of action, and the compare is against block time in ms.
- Weight tags by reference index (tag - 0x74): 2 BatchModify, 3 Cancel, 4 CancelByCloid, 14 Order, 23 ValidatorL1UpdateReferenceOracle, 52 MultiSig, 68 Hip3Deploy. These names are not checked against a dispatch table here; index 23 and 68 look doubtful.
- 500 per unit reads as 0.0005 of a 6-decimal token. Which token depends on the balance read, which is a stub here.
- Reference rows, with verdicts, are in `reference-diff.tsv`. The main one: `scaled_vlm.rs` calls `scaled / 100 + 10000` an account priority or tier seed; it is the request cap.

## Implementation and comparison

not yet implemented. There is no Rust for this path. The comparison here is byte-evaluated code against a separate Python model.

## Results and limitations

- 2300 vectors, 0 mismatches. Groups and outcomes are in `evidence.json`.
- 559 mutants of every conditional, field offset and immediate of the subjects and ranges: 535 killed, 24 equivalent, each with a written reason in `mutations.tsv`. Mutants of a subject run only on the vectors that reach it.
- 1300 instructions listed in `instructions.tsv`, 1236 executed. Not executed: unwind clean-up after the panic, the panic for a date the helper cannot refuse, padding, and the unreachable arms of the real date helper 0x151f6f0, which is a helper and not mutated.
- 29 unit tests pass, including corruption controls for the digest, section and FDE lookups, `.bss` bytes and 8 byte patches of constants.
- Balance, debit, credit, the row hashes, byte compare, once and drop helpers are stubs. Their semantics are not claimed.
- The three range functions start from a built frame, not from their real entry. Which callers reach those ranges is not shown. The 8 adds through 0x47d7ca0 are found by bytes only; that they copy the four evaluated sites is not checked.
- This binary may enforce the cap nowhere: no compare of row +8 with the cap was found, but the scan only sees the compiled shape with both constants close together, so that is unresolved, not disproved.
- Unknown: the role of the B-tree at state +0x4450, row words +0x10, +0x18, +0x20, and what the time in the view is used for.
- No progress gate is requested.

Next question: which code reads row +8 or the view record to refuse an action, and what does the tree at state +0x4450 store?
