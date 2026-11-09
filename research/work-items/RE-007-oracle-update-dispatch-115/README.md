# RE-007: reconstruct the node #115 oracle update dispatch (root 0x2753b90, body 0x2d35a80) and its drop glue

- Component ID: risk (RE-007 clearinghouse / oracle path; source hints `l1/clearinghouse/oracle/oracle.rs`, `l1/dex_registry/clearinghouses.rs`, `l1/dex_registry/perp_dex.rs`, `base/l1_map/entry.rs`)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `main` at the time of the run; `references/can1357-hl` used only as a label hint, nothing copied. No #94 result is reused.
- Claim status: observation (byte-level behaviour of six functions, compared 24,000 times) plus inference (names of the fields)
- Scope included and excluded: included are the root 0x2753b90, the update body 0x2d35a80 up to and including the queued event and the map-entry call, the two-string drop 0x2783790, the event-vector drop 0x2776870 and the result-enum drop 0x42320d0. Excluded (listed under Limits): the event flush 0x2419810, the second enum drop copy 0x277e390, the body tail after the map entry, and the internals of every callee that is stubbed.

With this packet the node #115 path "flat asset id -> clearinghouse and asset row -> update context -> oracle update body -> queued event -> event flush" can be written as plain code: the id split (`id / 10000`, `id % 10000`), the three bounds checks that decide which panic fires, the 0x94-byte context layout, the body's reject ladder (codes 0xd2 and 0xdd, the pass-through of a failed validation), the saturating event counter, the two block-time branches (a bit-exact integer reconstruction of the Unix-millisecond conversion and the argument protocol of the trading-state branch), the layout of the queued 0x2b8-byte event, and the drop behaviour of the argument block, the event vector and the result enum (nine handlers, decoded from the two jump tables). The Python models in `tools/re007_oracle_dispatch_115.py` reproduce what the original bytes do on 24,000 generated cases, and 54 deliberately wrong models or corrupted bytes are checked against them (52 caught, 2 shown to be unobservable).

## Reproduce

```
python3 tools/re007_oracle_dispatch_115.py --out research/work-items/RE-007-oracle-update-dispatch-115
python3 -m unittest tests.test_re007_oracle_dispatch_115
```

Python 3 standard library plus the repository parsers `tools/elf_index.py` and `tools/fde_extents.py`; no external program is started and the binary is never executed. The tool first checks the binary SHA-256 and stops if it differs. The output is deterministic (fixed seed, no time or path in any file); two runs with other hash seeds are byte-identical. Regeneration takes about 35 seconds and under 1 GB of memory; the test file takes about 40 seconds.

Files written by the tool (all regenerated, none hand-written): `members.tsv` (FDE extents of the seven bundle members, read from `.eh_frame`), `pins.tsv` (byte patterns of the constants the models use and where they sit), `panic-literals.tsv` (RIP-relative literals of the root's three panic sites, decoded with `struct`), `cases-*.tsv` (every n-th of the 24,000 cases: path, number of observed calls, digest of the call trace, result), `paths.tsv` (how many cases took each path), `controls.tsv` (the 54 negative controls), `equivalent-mutants.tsv`, `measure.json`.

## Evidence

Coordinates are virtual addresses of the ELF (`.text`). Function extents come from the FDE of each address; a non-start address is rejected.

| function | bytes | what the bytes do (observation) |
|---|---|---|
| 0x2753b90 | 820 | `id/10000` via the magic `0x346dc5d63886594b`, `>>11`; compares the quotient with the count at exchange-state +0x7d0 and +0x3ad0; clearinghouse record `+0x7c8 + q*0x510`; asset row `rec[+0x150] + local*0x60`, price qword at row +0x20, row count at rec +0x158; oracle book `[+0x3ac8] + q*0x200 + 0x188`; builds a context on the stack (0x58 bytes of the argument, price, record, exchange state, event-vector address, limit from exchange +0x39d0, the 0x14-byte key); calls 0x2d35a80, then 0x2419810 with an empty vector `{0, 8, 0}`, the clearinghouse index and the exchange state; copies the 0x70-byte result to the caller |
| 0x2d35a80 | 3548 | see the ladder below |
| 0x2783790 | 82 | two capacity-niche fields (+0 and +0x20) with their pointers (+8, +0x28) |
| 0x2776870 | 194 | event vector `{cap, ptr, len}`: drops `len` elements of 0x2b8 bytes with 0x22fcdc0, then frees `cap*0x2b8` when `cap != 0` |
| 0x42320d0 | 842 | result-enum drop: u16 tag at +0, tags 0x3d..0xd8 and 0xf0..0x109 go through jump tables at 0x7c7828 and 0x7c7a98, tags 0x160, 0x16f, 0x17d, 0x188 are compared directly, everything else returns |

Body ladder (`tools/re007_oracle_dispatch_115.py: model_body`), in the order the bytes execute it:

1. `0x2d357d0(book, key)`; a result above 9 writes the u16 `0xd2` to the output and leaves.
2. The ring descriptor (nine words built from the book's inline-or-deque fields at +0x38..+0x50, both the inline mode and the two-slice mode) is passed to `0x294ab40`; `book[+0x10] + count` (saturating at 2^64-1) `>=` the context limit writes `0xdd` and leaves.
3. `0x22e5380(...)` with the argument block, the key, the price and the clearinghouse record; any tag other than `0x1a2` is copied unchanged (0x70 bytes) to the output.
4. On Ok the counter at exchange +0x48 is incremented with saturation. If the flag byte of the result is 2 the trading-state branch runs: the constant at 0x4592b0 goes to `0x15ed960` (secs, nanos), the nanosecond total is clamped to 2^63-1, `0x162a9a0` is asked to add it to the block time, two range tests decide whether the answer is usable, the day count (`mulhi * 0x1845c8a0ce512957`) goes to `0x16290d0`, a zero answer selects the 12-byte default at 0x4679d0, and `0x2d2d960` receives a 0x6c-byte block; the output gets tag `0x1a2` and the counter value.
5. Otherwise the Unix-millisecond value is computed inline (year/ordinal unpacked from the date word, 400-year cycle correction for years <= 0, `*86400`, `+secs`, `*1000`, `+nanos/10^6`, clamped at zero), `0x2a81140` builds a record, a 0x2b8-byte event with tag 4 is assembled (record, niche word `0x8000000000000004`, counter, date, secs, nanos, key) and pushed to the vector at context +0x70 (grow through the slot at 0x64e5a28 when full, copy through the slot at 0x64df508), then `0x2db23f0` and `0x2421680` are called. The model stops there (see Limits).

## Implementation and comparison

The comparison harness is an offline x86-64 interpreter (a copy of the shared core with its decoder; no new instruction was needed beyond a small `TailMachine` that serves a direct tail jump to a nested drop function as a hooked call). Every external callee is a hook that records its arguments (pointers into the stack are replaced by the bytes they point to) and returns generated values. The model for each function predicts the exact list of hook calls, the output bytes it writes, the counter, and for the queued event the defined bytes of the element and the vector fields; a case passes only if all agree with the interpreter running the original bytes.

- Cases: 24,000 in total: root 4,000 (2,066 return, 485 first/second-bound panics, 1,449 asset-bound panics), body 9,000 (eight paths, each between 211 and 2,714 cases, see `paths.tsv`), argument-block drop 1,500, event-vector drop 1,500, result-enum drop 8,000 (1,305 of them have a pointer the model declines and both sides must fault together).
- Independent ground truth for the arithmetic: `tests/test_re007_oracle_dispatch_115.py` checks `days_millis` against Python's `datetime` for 400 random dates between 1970 and 2100, 2000-01-01 and the epoch, and that dates before 1970 clamp to 0.
- Negative controls (`controls.tsv`, 54): 30 wrong models (wrong divisor, stride, comparison, constant, clamp, saturation, handler rule) and 24 single-byte corruptions of immediates and tag compares in the original bytes. 52 are detected by the first mismatching case (the case number is in the table). Two are not detected and are recorded in `equivalent-mutants.tsv` with the reason: the century magic in the year <= 0 branch (every such date is before 1970, so the result is clamped to 0 whatever the constant; checked for the whole signed year field, 262,145 years x 2 ordinals x 2 clocks) and lowering the first tag bound 0x15f (tag 0x15f takes a different route but both end in the no-op return; run on both byte versions for tags 0x15e..0x161).
- Results are in `measure.json`: cases 24,000, case failures 0, negative controls 54, detected 52, equivalent 2.

## Results and limitations

Observed and compared: everything in the Evidence table for the modelled functions. Inferred only: the names "clearinghouse", "oracle book", "event counter", "limit" (from the shapes and the source-path hints), and that the second argument of `0x162a9a0` and the callee `0x16290d0` are the chrono-style time-add and date-from-days functions (only their argument protocol is verified here, not their bodies).

Not done, listed so nobody reads this as a full-component claim:

- `0x2419810` (flush, 2,992 bytes, drains the event vector through event vtables) is only seen as a call with its argument bytes.
- `0x277e390` has the same outer shape as `0x42320d0` but its sub-handler table differs (one extra tail jump to `0x2780300`); it is not modelled.
- The body after the `0x2421680` call (small-map to B-tree promotion, the node search with 0x58-byte values, the insert slot) is not modelled; the model stops at the hook.
- The stubbed callees `0x2d357d0`, `0x294ab40`, `0x22e5380`, `0x2a81140`, `0x2d2d960`, `0x162a9a0`, `0x16290d0`, `0x15ed960`, `0x2db23f0`, `0x2421680`, `0x4233f10`, `0x4232440` are not reconstructed; the nine drop handlers that reach `0x4232440` and `0x4233f10` only record the call.
- Unwind landing pads (after `ud2`) are not exercised.
- No component gate is requested.

Next question: reconstruct the map-entry pair `0x2db23f0` / `0x2421680` and the B-tree node search at 0x2d365c8, which decide where the queued event is stored.
