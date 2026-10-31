# RE-007: shortfall sweep of `apply_bole_liquidations`: user filter, cancel and second look, classes, counters, row move to the system account, order amounts

This packet shows how the BOLE step picks unhealthy users, gives tier users a cancel and a second health look, moves what remains onto the system account, and turns it into orders, so a reconstruction can now write who is swept, what each of the 10 counters counts, what a user keeps after a move, and how order amounts are scaled.

- Component ID: RE-007 (risk, oracles, liquidation), BOLE liquidation path
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for bytes, layouts, order of calls, constants, rounding and comparison direction; inference for what the words mean; unresolved items are listed under Results and limitations
- Scope included and excluded: included, whole and with mutants, are the sweep `0x2765600`, its value helper `0x21a35e0`, the row move `0x3735db0`, the fold body `0x3767210`, the list step `0x3739be0` and the iterator drop `0x255cb70`. The copies `0x4d96ad0`, `0x4d98480`, `0x4c22cf0` and `0x44c6f60` run all sweep cases, with no mutants. The standard B-tree code and the unit helper `0x32815f0` run as real bytes with no mutants. Each stubbed edge has its arguments checked and is listed in `evidence.json`. Excluded are the report `0x373d8e0`, the health read `0x28db540`, the row builder `0x3736bd0`, the order builder `0x251a290` and the order send `0x26f4400`.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned binary in place:

```
python3 tools/artifacts.py verify
python3 tools/shortfall_sweep.py --out research/work-items/RE-007-shortfall-sweep-94
python3 -m unittest tests.test_shortfall_sweep
sha256sum -c MANIFEST.sha256   # inside the folder
```

The tool took about 240 s at a load near 10 and checks the input SHA-256 first. It reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`, with no objdump or readelf output. It never runs the binary. All numbers below come from the generated files.

| File | Content |
|---|---|
| `evidence.json` | functions with hashes, hosts, direct calls per copy, constants, stubs, real helpers, case outcomes |
| `path-map.tsv` | the path in order |
| `class-samples.tsv` | real runs: score words, class, low flag, counters touched, result |
| `move-samples.tsv` | real runs: all 16 tag pairs of the row move |
| `amount-samples.tsv` | real runs: list rows and send mode for scaled and value rows |
| `mutations.tsv` | every flipped branch, condition, immediate and field offset, with a reason for each that stayed |

## Evidence

Coordinates are virtual addresses. Offsets are from the exchange pointer unless marked otherwise. The BOLE state sits at +0x498, and its user map at +0x598.

### Hosts

| Copy | Step body | Sweep | Value helper | Counter map | User set | Counter base |
|---|---|---|---|---|---|---|
| primary | `0x222caf0` | `0x2765600` | `0x21a35e0` | `+0x770` | `+0x8b8` | `+0x7a0` |
| second | `0x4714080` | `0x4d96ad0` | `0x4c22cf0` | `+0x770` | `+0x8b8` | `+0x7a0` |
| recording | `0x47121b0` | `0x4d98480` | `0x4c22cf0` | `+0x11f0` | `+0x1338` | `+0x1220` |

`0x3739be0`, `0x3735db0` and `0x3736bd0` are one function each, reached through data slots from all 3 copies. The recording copy moves its 3 fields by 0xa80. The copies pass `+0x80` as a new first argument to the order send, so its other arguments move one place. Their iterator drop `0x44c6f60` opens the row drop inline.

### Filter and list

`0x3767210` is the rayon fold body under `0x3739be0`: `0x3739be0` to `0x33c3b00` to `0x38dbbb0` to `0x34434f0` to `0x3767210` is a direct call chain, pinned by `test_fold_body_chain` from E8 bytes. For each user:

| Report | User | Row |
|---|---|---|
| failed, byte 2 | any | none |
| failed, other byte | any | byte and code kept |
| ok | system address | none |
| ok | class 2 or 3 | none |
| ok | class 0 | status 0, flag 0 |
| ok | class 1 | status 0, flag = score >= 1000000 |

Class comes from 4 words of the report (`+8` score, `+0x18` soft, `+0x20` mid, `+0x28` hard): score above hard is 0, above mid is 1, above soft is 2, else 3. The same 3 compares sit inline in the sweep. Class 2 and class 3 take one path everywhere, so soft has no effect on this path.

`0x3739be0` walks the status rows in key order. The first failed row ends it with that row's code, and the sweep returns the code. It skips the system address once more. The rest enter a map of user to flag, with node size 0xf8 and flags at +0xe8.

### Stage 1, per user in key order

1. `0x2755400` gives a state. Byte +0x3c at or above 4 with bit 0 of `+0x5b0` clear calls `0x2731030(.., user, 1)`, which gives a word and pointer. Otherwise the word is `0x8000000000000002`. Bit 0 of `+0x5b0` turns this off for all users.
2. The report is read again, after that call. A failed report stops the sweep with its code.
3. Class 2 or 3, or the system address, counts the word: `0x8000000000000001` adds to index 2, any other negative word except the none word adds to index 1, and a positive word is freed. No row.
4. Class 0 or 1 adds to index 3 under the list flag and index 0 under the new low flag. `0x28db540` must not fail, and its words must not be negative (unwrap panic). `0x3736bd0(user, low flag)` then gives tag 2, which inserts the user in the set at `+0x8b8`, or a 0x80 row, which is pushed.

Each index counts in 2 groups, chosen by a byte: nonzero uses +0x50, zero uses +0x78, so index i is at `+0x7a0 + group + 8i`. The same value goes to a per-user block from the map at `+0x770`, at `group + 8i`. All adds saturate at 2^64 - 1.

### Stage 2, row move `0x3735db0`

The row carries a map from token to 0x50 byte values. For each token in key order:

| Value | Effect |
|---|---|
| tag 3 at +0 | stop; later tokens move nothing, and all nodes are still freed |
| tag 2 at +0 | first pair skipped |
| tag 0 or 1 at +0 | system words 0 and 1 add +0x18 and +0x20, saturating with a log |
| bit 0 of tag +0 | user keeps the 16 bytes at +8 as new words 0 and 1 |
| tag 2 or 3 at +0x28 | second pair skipped |
| tag 0 or 1 at +0x28 | system words 2 and 3 add +0x40 and +0x48 |
| bit 0 of tag +0x28 | user keeps the 16 bytes at +0x30 as new words 2 and 3 |

The system account is the entry for `0xbb` x 20 in the user map. A missing system or user entry is inserted with word 0 of 0 and a date from `0x151f6f0(719163)` at +8, which is the day count of 1970-01-01. A date of 0 panics. After the walk the user's account map at +0x18 is dropped and replaced by the kept map, so any token not kept is gone. `move-samples.tsv` shows all 16 tag pairs.

### Stage 2, amounts and orders

Odd row tag: each token in the row's second map gives `amount * word +0x78 of the token / 1e14`, rounded down, with the share word passed on. A token missing from `+0x568`, or a quotient at or above 2^64, drops the list and the row, and no order goes out.

Even row tag: `0x21a35e0` sums vector a with the ceil value and vector b with the floor value of `0x32815f0`. It evaluates b even when a failed. Any failure skips the row. Otherwise every b row goes out with `share = a / b` as f64, or 1.0 when b is 0.

The list goes to `0x251a290`. If it returns orders, `0x26f4400` gets source byte 1 with 32 zero bytes and mode `0x90009` for odd tags or `0x80008` for even tags, and `0x24fc8a0` flushes them.

The row move always comes first, so a row with no orders has still moved to the system account. Then `0x28db540` is read again: a score above mid or hard adds to index 4 under row byte +0x7c. A failed read stops the sweep with its code, and the rows left stay unmoved.

## Implementation and comparison

Rust: not yet implemented.

| Metric | Value |
|---|---|
| Cases | 1225 (370 sweep per copy, 87 filter, 28 list) |
| Mismatches | 0 |
| Instructions stepped | 1,956,142 |
| Stepped / total: sweep primary | 1055 / 1268 |
| Stepped / total: sides primary | 184 / 188 |
| Stepped / total: claim shared | 542 / 603 |
| Stepped / total: iterator drop primary | 37 / 56 |
| Stepped / total: filter shared | 124 / 142 |
| Stepped / total: list shared | 133 / 156 |
| Stepped / total: sweep second | 1058 / 1271 |
| Stepped / total: sweep recording | 1058 / 1271 |
| Stepped / total: sides copy | 184 / 188 |
| Stepped / total: iterator drop copy | 48 / 81 |
| Mutants killed / survived / unreached | 724 / 62 / 81 |

A separately written specification predicts every stub argument, event, free, log, counter, account map and result. Node frees of the consumed maps are tracked by address.

## Results and limitations

- Observed: the table and stage lists above, in real runs of all 3 copies with 0 mismatches.
- Inference, not proven: the score is a margin ratio word, and soft, mid and hard are thresholds; the indexes count sweep outcomes; the tier call cancels orders; the kept pairs are what the row builder chose to leave; a row byte +0x7c is the low flag.
- The specification comes from reading the same code, so it is a cross-check.
- `0x38dbbb0` and the rest of the rayon pass are not run. `0x33c3b00` is stubbed, so the link from fold rows to status rows is read, not stepped. Sweep cases take the user list from the case and may hold users not in the map, which `0x3739be0` alone cannot produce, so the default row path in stage 1 is not known to be reachable.
- Fixture tree heights stay below 8, and 62 surviving mutants plus 81 unreached rows each have a reason in `mutations.tsv`. Cold unwind and panic paths are not stepped.
- `0x32815f0` and `0x2731030` are covered by other packets. `0x26f4400` is free and is a good next target, since its mode word bytes pick the row flags.
