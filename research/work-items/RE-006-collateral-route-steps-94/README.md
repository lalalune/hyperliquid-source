# RE-006: what node #94 moves around an order in abstraction modes 3 and 4

This packet shows every collateral move node #94 makes before and after a book insert for users in `unifiedAccount` and `portfolioMargin` mode (`move_token`, the settle pass, the pull, the sweep and the account block calls), with amounts, limits, shares, order of calls and failure arms, so a reconstruction can run those modes without guessing which balance an order draws on.

- Component ID: RE-006 (book state transitions), the collateral steps around an order
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no body for any function here.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants, both copies of each: move `0x46ea0b0` / `0x46eaa10`, undo `0x46e98e0` / `0x46e9850`, reserve move `0x46eb400` / `0x46eb850`, settle `0x46ebca0` / `0x46ed7d0`, wrapper `0x46ef300` / `0x46ef3d0`, sweep `0x46ef4a0` / `0x46ef720`, pull `0x46efb70` / `0x46ef9a0`, account step `0x46f7240` / `0x46f73d0`, gather `0x46f02f0` / `0x46efd40`. Earlier packets name some of these only as stubs or table rows: #926 and #885 stub `0x46ea0b0`, `0x46efb70`, `0x46ef4a0` and ask this question, #629 lists `0x46ef4a0`, #944 and #131 list `0x46ebca0`, #922 lists `0x46efb70`, `0x46ef4a0`, `0x46ef300` in a tool. None reads a body. Real bytes with no mutants: amount helper `0x4c23110` (a row in #46 and #922), key collector `0x47beca0`, iterator `0x4896090`, map insert `0x492e880` with node split `0x423ad10`, map drain `0x4947500`, user iterator `0x330f760`. Stubbed at the edge: transfer `0x46e8290` / `0x46e89a0`, helper `0x48cdac0`, finish `0x46f0ee0` / `0x46f0b20`, value read slot `0x57738b8`, spot user lookup slot `0x5773170`, count map `0x47d7550`, status drop `0x472f840`. Excluded: the bodies of those stubs, and what the hosts do besides these calls.

## Reproduce

From the repository root:

```
python3 tools/collateral_route_steps.py --out research/work-items/RE-006-collateral-route-steps-94
python3 -m unittest tests.test_collateral_route_steps
```

The tool takes about 180 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `route_call_sites.tsv`, `cases.tsv`, `mutations.tsv`. The hand excerpts below are for reading and are not parsed by any tool. Addresses are ELF virtual addresses. Function ends come from `.eh_frame`.

## Evidence

### Which step runs for which mode

The four routers `0x4ca9710`, `0x4ca8eb0`, `0x4ca8510`, `0x4ca7cb0` hold the same shape, pinned in `evidence.json` under `routers`. `0x4ca8eb0` as read:

```
4ca93c2 cmp ebx,0x4
4ca93c5 sete al                     ; pull flag = (mode == 4)
4ca9401 call 46efb70                ; state, user, token of the dex, 1, dex, word, flag
4ca94bf call 4d472f0                ; the order
4ca94c4 cmp ebx,0x4
4ca94c7 jne 4ca94f2                 ; mode 3 goes to a plain move
4ca94e8 call 46ef4a0                ; mode 4: sweep with source 1, dex
```

| Step | `unifiedAccount` (3) | `portfolioMargin` (4) |
| --- | --- | --- |
| Before the order | pull, flag 0: settle the token, then move spot to the dex | pull, flag 1: settle, account block calls, then move spot to the dex |
| After the order | `0x46ea0b0` dex to spot (#926) | sweep: dex to spot, then account block modes 2 and 1 |

The mode names are the order of the text at `0x5a72f4` (`dexAbstractionunifiedAccountportfolioMargin`), as #926 and #922 already read it.

### `move_token`

The format text at `0x1e03c9` and `0x1e76b6` gives the name: `move_token to_spot: ` and `move_token from_spot: `. Arguments: out, state, user, token, source (flag, dex), target (flag, dex), cap (flag, value). No flag means spot. In order:

1. State `+0x1258` and word `+0x38` of the user row from `0x47d7550` (map state `+0x11f0`) go up by one, saturating, on every call, also when nothing moves.
2. Same source and target: 0.
3. User in the 20 byte key set at state `+0x1350`: 0. The status is still OK.
4. Target dex row, stride 0x2f0 from state `+0x1040`, index below `+0x1048`, else panic `Invalid perp DEX` (`0x141`, `l1/src/dex_registry/clearinghouses.rs:11:29`). Row byte `+0x230` of 3 has no limit. Any other value: limit = max(`+0x1c0` - `+0x238`, 0). `+0x1c0` negative panics (`l1/src/qtys/mod.rs:843`). Overflow of the subtraction saturates and reports through `0x5773190` (`l1/src/qtys/impl_ntl.rs:62`).
5. Source dex: its token `+0x50` must equal the token, or the text `token mismatch` is built, dropped, and the result is 0 with status OK. Have = max(slot `0x57738b8`(row, user, 4, byte `+0x2ed`), 0).
6. Source spot: `(total - hold) / 100` from the token tree of the user (node keys `+8`, values `+0x60` stride 0x18, total then hold). A hold above the total reports (`l1/src/qtys/impl_wei.rs:6`) and gives 0.
7. Amount = min(have, limit, cap), each only if present. 0 ends with status OK.
8. Source dex: transfer `0x46e8290`(dex, mode 1, amount). A failure returns text `move_token to_spot: ` plus the inner status.
9. Target dex: token check, then transfer (dex, mode 0, amount). A failure first credits the source back through `0x46e98e0` (mode 0), then returns `move_token from_spot: `. A failed credit back is dropped. The token check here returns status 0x168 with `token mismatch`, and it comes after the debit of step 8, which is not undone on this arm.
10. Result: status `0x186` and the amount at `+8`.

Spot itself is not debited in this body: a spot source only runs step 9. Transfer mode 0 and 1 are its two directions (inference from the two format texts).

### Settle `0x46ebca0`

Arguments: out, state, user, flag byte, every word, token. Tokens are the token, or with `every` all keys of the map at state `+0x568` (u64 keys, node keys `+0x798`, length `+0x7f2`, edges `+0x7f8`).

1. For each row of `+0x1040`, taking the index from row `+0x30`: if the row token is listed, flag 0 runs `move_token` from that dex to spot, flag 1 runs transfer mode 2. Failures are dropped.
2. With `every`, a sweep from spot of every key of the map.
3. For each token, each dex of that token: read the value, mode 2 with flag, mode 4 with byte `+0x2ed` without. Need = -value when negative, else 0 (the value `i64::MIN` panics). Skip when need is 0 and bit 0 of the second return word is clear. With that bit set the dex joins the hit list. With `every`, the first such dex of a token runs a reserve move (word 2, byte = flag). Then `move_token` from spot to the dex, cap = need. A failed or short move marks the token as failed. With `every`, a token that took the reserve move ends in a sweep from spot.
4. With flag set and any hits, per token in key order: with `every` a reserve move (word 2, byte 1). Then share = free spot in 1e-6 units x 3 / (3 x H + every), H being hits left, this token included. Each hit dex with the same token reads mode 4 again and receives min(share, need) from spot.
5. The result is the list of failed tokens, or the niche word `0x8000000000000000` for none. `0x46efb70` frees the list unread.

So with two dexes of a token and no map entry each gets a half of free spot, and with a map entry each gets 3/7. From `sample_lines`, free amount and moves:

```
every=0 free=1000000: dex 0 +500000 dex 1 +500000
every=1 free=1000000: dex 0 +428571 dex 1 +428571
```

The 3.0 is `0x4008000000000000` at `0x20aab8`. The rounding is a cast toward zero.

### The small steps

- Account step `0x46f7240` (token, mode, optional word, byte): amount helper `0x4c23110`, table `0x70bd94`: modes 1 and 2 pass the free spot wei, modes 0 and 3 pass none. `0x48cdac0` gets the block at state `+0x498`, user, token, mode, amount, the option, byte xor 3, the 12 bytes at state `+0x60`, and state `+0x80`. First word 3: status `0xe1` with its byte. First word 2: OK, 0. Else finish `0x46f0ee0` with the record: anything but `0x11` gives `0xe1` with byte 10, else OK and the word at record `+0x100`.
- Reserve move `0x46eb400` (token, target, word block, byte). Word 2: if the token is in the map, modes 3 then 0. Word 1 or 3: if the key at block `+8` is in the map, mode 3 on that key with the option from block `+0x10`, and a failure here ends the function before the move. Then, for all words but 2, mode 3 on the token if in the map. Failures of the other steps are dropped. Last, `move_token` spot to target.
- Sweep `0x46ef4a0` (token, source): `move_token` source to spot, then modes 2 and 1 if the token is in the map, byte 0.
- Pull `0x46efb70` (token, target, word block, flag byte): settle with `every` = flag and token in map, flag 0. Then flag: reserve move, byte 0. No flag: `move_token` spot to target. Only the low byte of the flag counts.
- Gather `0x46f02f0`: `move_token` from every dex to spot, then a reserve move with word 0 for every key of the map, target none, so one mode 3 per key. It ends in a user lookup at state `+0x598` and a walk whose result is never used.
- Wrapper `0x46ef300` turns a move into `Option<amount>`, dropping the error.

### Copies

Each second copy reads the same fields 0xa80 lower for `+0x1040` and up, and calls its own siblings. `copies` in `evidence.json` compares row by row: 8 of 9 families have equal shape and only shifted fields. `0x46eaa10` is 12 bytes longer with two more rows. The same specification runs on it, with the field shift. Which of the two is perp and which spot style state is not settled here. Direct call sites of all entries are in `route_call_sites.tsv`.

## Implementation and comparison

Not yet implemented in Rust. The comparison here is between the real bytes, run in the tool's evaluator with edges stubbed, and a separately written specification in the same tool. Both copies of every function run all cases.

| Metric | Value |
| --- | --- |
| Cases | 840 |
| Mismatches | 0 |
| Instructions stepped | 760,004 |
| Stepped / total: collateral move copy 1 `0x46ea0b0` | 417 / 470 |
| Stepped / total: collateral move copy 2 `0x46eaa10` | 411 / 472 |
| Stepped / total: undo of a debit copy 1 `0x46e98e0` | 27 / 27 |
| Stepped / total: undo of a debit copy 2 `0x46e9850` | 27 / 27 |
| Stepped / total: reserve move copy 1 `0x46eb400` | 228 / 230 |
| Stepped / total: reserve move copy 2 `0x46eb850` | 228 / 230 |
| Stepped / total: settle pass copy 1 `0x46ebca0` | 1067 / 1401 |
| Stepped / total: settle pass copy 2 `0x46ed7d0` | 1067 / 1401 |
| Stepped / total: move wrapper copy 1 `0x46ef300` | 37 / 37 |
| Stepped / total: move wrapper copy 2 `0x46ef3d0` | 37 / 37 |
| Stepped / total: sweep copy 1 `0x46ef4a0` | 120 / 121 |
| Stepped / total: sweep copy 2 `0x46ef720` | 120 / 121 |
| Stepped / total: pull copy 1 `0x46efb70` | 118 / 119 |
| Stepped / total: pull copy 2 `0x46ef9a0` | 118 / 119 |
| Stepped / total: account block step copy 1 `0x46f7240` | 95 / 95 |
| Stepped / total: account block step copy 2 `0x46f73d0` | 95 / 95 |
| Stepped / total: gather copy 1 `0x46f02f0` | 273 / 317 |
| Stepped / total: gather copy 2 `0x46efd40` | 273 / 317 |
| Stepped / total: amount helper: a table row in #46 and #922, run with no mutants `0x4c23110` | 124 / 124 |
| Stepped / total: key collector, run with no mutants `0x47beca0` | 118 / 199 |
| Stepped / total: key iterator, run with no mutants `0x4896090` | 83 / 121 |
| Stepped / total: result map insert, run with no mutants `0x492e880` | 89 / 123 |
| Stepped / total: result map node split, run with no mutants `0x423ad10` | 209 / 727 |
| Stepped / total: result map drain, run with no mutants `0x4947500` | 146 / 225 |
| Stepped / total: user tree iterator with an unused result, run with no mutants `0x330f760` | 7 / 121 |
| Mutants killed / survived / unreached | 1563 / 123 / 202 |

All 123 survivors were read and sorted by class in `mutations.tsv`: 32 in the unused user walk of gather, 19 second reads of a bound already checked, 18 in walks of a result map of height 2 or more (over 132 tokens), 12 sums that need over 2^62 hits, 10 start values of empty Vecs, 10 layout overflow tests, 8 back halves of iterators, 6 share cast clamps, 4 overlapped text bytes, 2 share reads that the later move caps, and 2 words that need a stale key. Two rounds of survivors improved the run first: panic text and word checks, dropped text, a zero filled stack for unset option words, keys past every node end, and 9 and 13 row states. The 202 unreached rows are allocator, panic and unwind arms, the second token check of a move, arms the sums make dead, and the descent code of trees deeper than the two levels built here.

Negative controls in `tests/test_collateral_route_steps.py`: wrong digest, a non-ELF file, a mid-function start, an address outside every mapping, a flipped branch, a changed divisor, a changed spec, a leak, a mutated tree length, and a router pin on a wrong function.

## Results and limitations

- All cases agree on the ordered edge calls, results and both counters, on both copies.
- Fake state only. Row fields and balances are chosen for the branches, not taken from a chain.
- The meaning of the account block modes 0 to 3, of value modes 2 and 4, of transfer mode 2, and of the second return bit of the value read are not proved here. They are stubs. The map at `+0x568` is named by its use only. Which users sit in the set at `+0x1350` is open.
- Mode 2 (`dexAbstraction`) goes through the same `0x46ea0b0` per #885. Its host logic is out of scope.
- Hosts other than the routers were not read past their call sites.

No progress gate is requested.

Next question: what does `0x48cdac0` do for modes 0 to 3, and who writes the user set at state `+0x1350` that `0x4d9ce10` reads?
