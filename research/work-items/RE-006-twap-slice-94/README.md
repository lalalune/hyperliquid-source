# RE-006: node #94 TWAP step, from the due heap to one order slice

- Component ID: orderbook (task RE-006)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation for everything marked as such below; inference where the Inferences section says so; open points are listed under Results and limitations
- Scope included and excluded: included are the four drains, four slice functions, four advance functions, heap push and pop, and the round, floor and ceil helpers they call. Excluded are the collectors `0x47f7fd0` family, the callers `0x47c30a0`, `0x47c33d0`, `0x4ce0680`, `0x4ce0cc0`, the order placement after the slice, the other advance callers, and `0x42f2400`, `0x42f3360` and their siblings, which pop the same heap.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned artifact in place:

```sh
python3 tools/twap_slice.py --out research/work-items/RE-006-twap-slice-94
python3 -m unittest tests.test_twap_slice
sha256sum -c research/work-items/RE-006-twap-slice-94/MANIFEST.sha256
```

The working directory for the last command is `research/work-items/RE-006-twap-slice-94`. The tool checks the binary digest first and fails on any other input. It reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output, calls no external program and never executes the binary. It took about 90 s alone and 420 s on a loaded machine. Only the standard library is used.

Generated files: `evidence.json`, `call_sites.tsv`, `copy_differences.tsv`, `mutations.tsv`.

## Evidence

Coordinates are virtual addresses in node #94. Function bounds are FDE extents.

### Why this is one path

The reference files `l1/time.rs` and `l1/exchange/handlers/35_twap_order.rs` name a 30 s step, a limit of `2 * (duration / 60) + 1`, and the field layout of a schedule entry. They do not say how large a slice is, what its price is, or how the due records are held. The path from the bytes:

| Step | Perp copies | Spot copies | Size in bytes |
| --- | --- | --- | --- |
| Drain due rows | `0x42f1500`, `0x42f18c0` | `0x42f2040`, `0x42f1c80` | 957 |
| Collector, calls the slice per row | `0x47f7fd0`, `0x47f7520` | `0x47f6c30`, `0x47f5c90` | not evaluated |
| Slice | `0x4339480`, `0x4338210` | `0x4336b90`, `0x43377c0` | 2909, 2625 |
| Advance | `0x42eef80`, `0x42f0af0` | `0x42f0240`, `0x42ef990` | 2574, 2223 |

`evidence.json` key `pairing` holds the call sites that link each row. `copy_differences.tsv` has 9 rows: perp copies of a slice and of an advance differ in `+0x1040`/`+0x1048` against `+0x5c0`/`+0x5c8` and in the advance they call, spot copies differ only in that call, and drains differ only in their collector.

### Records

Order value in the user's order map, 0x60 bytes (`order_map` in `evidence.json`): `+0x00` asset, `+0x08` total, `+0x10` duration in seconds as f64, `+0x20` side, `+0x21` copied to the slice, `+0x22` jitter switch, `+0x28` executed, `+0x38` step counter, `+0x40` next due time, `+0x4c` user. Fields `+0x18` and `+0x30` are read by nothing here.

Heap entry, 0x28 bytes: `+0x00` order id, `+0x08` due time (date word, seconds, nanos), `+0x14` user. Holder: `+0x00` capacity, `+0x08` pointer, `+0x10` length, `+0x18` the user map.

Slice output, 0x70 bytes: tag 1, `+0x08` size, `+0x10` byte 3, `+0x19` byte 2, `+0x20` limit price, `+0x28` and `+0x48` asset, `+0x30` side, `+0x31` order byte `+0x21`, `+0x32` byte 0, `+0x50` order id, `+0x58` user. Tag 2 means no order. Every other byte of the 0x70 is left unwritten, and the evaluator checks that.

### Heap

Push `0x44c1900` and pop `0x44c0fe0` keep a binary min-heap on (date as i32, seconds as u32, nanos as u32, user by memcmp, order id as u64). 96 heaps of up to 59 entries popped in exactly that order.

### Drain

While the heap has rows, read the head and find its user and order. If either is gone, pop it and go on, whether or not it is due. Otherwise, if the head is later than `now`, stop. Otherwise pop it and add a 0x20-byte row (user, order id at `+0x18`). So a stale entry leaves the heap as soon as it reaches the head, even with a due time in the future, while stale entries behind a later live head stay.

### Slice

With `N = 2 * (duration / 60) + 1`, where the division saturates to u64 and non-finite values count as 0, `N` itself saturating. A negative or NaN duration trips `assertion failed: self.0 >= 0.` at `base/src/duration.rs:89:13`.

1. A set flag byte (the fourth drain argument) skips everything and goes to the advance.
2. Mid. Perp: market bound (panic at `clearinghouses.rs:11:29`), book bound (panic at `books.rs:14:16`), then `0x3c18b70` on book `+0x80` gives two prices. Either being 0 goes to the advance, otherwise the mid is their average, floored. Spot: slot `0x5774e10` (`0x3730b40`) gives the mid, and 0 goes to the advance.
3. Limit. `1.03 * mid` for side 0, `0.97 * mid` otherwise, through `round` (`0x565f410`), clamped and cast. Then a tick from `0x42c7600` (perp) or `0x4ca6b90` (spot). Side 0 floors to a tick. The other side floors and adds one tick, even on an exact multiple. The result is at least 1.
4. Target. `even = total / N` as f64. If the counter equals `N`, the target is the total. Otherwise it is `floor(counter * even)`. With the jitter byte set it is `floor(fma(even, counter, jitter * even))`, with `jitter = (ms % 40) / 100 - 0.2` and `ms` the Unix millis of `now`, negative values taken as 0. The FMA is `0x565f8c0`, an indirect call through `0x57882e8`, whose resolver stores `vfmadd213sd` at `0x565fd20` or an FMA4 form at `0x565fd30` or a software path at `0x565f8e0`.
5. A target below the executed size goes to the advance.
6. Remainder. `total - executed`, recording at `l1/src/qtys/impl_sz.rs:9:1` and using 0 on underflow. If `price * remainder` does not exceed 30,000,000 (perp) or 3,000,000,000 (spot), the slice is the whole remainder.
7. Otherwise `want = max(target - executed, floor)`, where `floor` is `12,000,000 / price` (perp) or `1,200,000,000 / price` (spot), 0 if the price is larger. The size is `min(3 * even + 1, want, remainder)`, saturating. Below the last step it is floored to 5 significant figures.
8. A size of 0 goes to the advance. Otherwise the record is written.

### Advance

Find the user and the order. A missing order returns. A missing user runs the map entry call (`0x495b000`, `0x495a910`) and returns on the empty map it gives. Then:

1. Add 30 s to the due time. If that is before `now`, add `ceil(behind / 30) * 30` s on top. The panic text for a date overflow is `` `NaiveDateTime + TimeDelta` overflowed ``.
2. Store the time and raise the counter, saturating.
3. If executed reaches total, or the counter exceeds `N`, finish: remove the order, remove the user if that was the last one, convert the value and write a record of 0x278 bytes (perp) or 0x268 bytes (spot), tag 4, `+0x60` 0x8000000000000002, `+0x78` order id, `+0x80` now, `+0x8c` user.
4. Otherwise push the entry back with the new time.

## Implementation and comparison

Rust implementation: not yet implemented. Raw and normalized body comparison: not yet measured.

Comparison here is real bytes against a separately written Python specification. The evaluator runs the bytes of the twelve functions plus heap push, heap pop, `round`, `floor` and `ceil`. Stubs replace the book top, spot mid, tick lookups, the chrono helpers, map removals, conversion, panics, `memcmp` and `memcpy`. `fma` is modelled exactly with fractions. Stubs record their arguments, and these are compared event by event. The whole 0x70-byte slice, the stored time and counter, and the finish record are compared byte by byte.

Mutation control: each conditional branch, set, cmov, immediate and non-stack field offset in one copy per family, plus the drain, push and pop, is flipped by one bit and the cases rerun.

## Results and limitations

| Metric | Result |
| --- | --- |
| Slice cases, each of 2 perp copies | 280 |
| Slice cases, each of 2 spot copies | 264 |
| Advance cases, each of 4 copies | 122 |
| Drain cases, each of 4 copies | 69 |
| Heap cases | 96 |
| Mismatches, all runs | 0 |
| Perp slice outcomes, 2 copies | order 434, reschedule 98, none 14, panic 14 |
| Spot slice outcomes, 2 copies | order 448, reschedule 60, none 14, panic 6 |
| Advance outcomes, 4 copies | requeue 192, finish 240, failed removal 8, nothing 16, panic 32 |
| Drain outcomes, 4 copies | with rows 84, without 192 |
| Instructions stepped | 1,548,965 |
| Stepped / total, perp slice | 624 / 642 |
| Stepped / total, spot slice | 579 / 593 |
| Stepped / total, perp advance | 470 / 489 |
| Stepped / total, spot advance | 431 / 444 |
| Stepped / total, drain | 195 / 212 |
| Stepped / total, heap push | 120 / 125 |
| Stepped / total, heap pop | 261 / 265 |
| Mutants killed / survived / unreached | 904 / 90 / 8 |

`mutations.tsv` gives a reason on each surviving or unreached row. The 90 survivors fall into these groups, all argued in that file: low bits of finite tests on values that cannot reach the top double, clamps whose two arms give one number, sign masks over a word whose bit 0 is clear, a price that is at least 1, date arithmetic the jitter cannot see, ladder rungs moved by one, `-2` that saturates to the same `-1`, repeats of a walk that already found its key, and two heap moves. The 8 unreached rows are an overflow arm of `floor(x / unit) * unit`, a second assertion after `ceil`, a second recorder after a remainder that is already 0, and unwind cleanup.

Limits:

- The stubs stand in for chrono, so calendar correctness of the added time is not shown, only which values go in and how the answers are used.
- Tick lookups and the book top are stubs. `0x42c7600`, `0x4ca6b90` and `0x3c18b70` are only pinned as callees.
- The FMA choice depends on the CPU at run time. All three targets should give the same value only if the software path is exact, which was not checked.
- One copy per family went through mutation. The other copy of each pair is run on the same cases and differs only as listed.
- Which caller sets the flag byte, and to what, is not settled. It comes from a pointer in `0x47c33d0` and a stack byte in `0x4ce0680`.
- No progress gate is requested.

Next question: `0x42ed300`, `0x42ee6e0`, `0x42eca60` and `0x42edcf0` also call the advance. They are the calls from `0x4ce0680`/`0x4ce0cc0`. How does a slice's fill reach `+0x28`, and what do the bytes `+0x10` = 3 and `+0x19` = 2 of the slice mean to the insert path?
