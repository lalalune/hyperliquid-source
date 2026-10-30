# RE-006: node #94 TWAP slice result, from the order result to the status JSON

- Component ID: orderbook (task RE-006)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation for everything under Evidence; inference only where the Inferences section says so; open points are listed under Results and limitations
- Scope included and excluded: included are the four result handlers, the two callers, the rejection Display `0x3a008e0`, the history serializer `0x47ef250`, its field wrapper `0x4a87060`, the status serializer `0x42e9000`, and the tag 4 arm of the row flush `0x432a100`. Excluded are the slice placement that makes a result, the advance functions and the drains (only called, and stubbed), the map removals, the rest of the flush, and the serializers of the `time`, `twap_id` and `state` fields.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned artifact in place:

```sh
python3 tools/twap_fill_result.py --out research/work-items/RE-006-twap-slice-result-94
python3 -m unittest tests.test_twap_fill_result
sha256sum -c research/work-items/RE-006-twap-slice-result-94/MANIFEST.sha256
```

The working directory for the last command is `research/work-items/RE-006-twap-slice-result-94`. The tool checks the binary digest first and fails on any other input. It reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output, calls no external program and never executes the binary. It takes about 15 s. Only the standard library is used.

Generated files: `evidence.json`, `error_classes.tsv`, `call_sites.tsv`, `copy_differences.tsv`, `mutations.tsv`.

## Evidence

Coordinates are virtual addresses in node #94. Function bounds are FDE extents.

### Path

| Step | Perp | Spot | Size in bytes |
| --- | --- | --- | --- |
| Caller, first copy | `0x4ce0680` | same | 1598 |
| Caller, second copy | `0x4ce0cc0` | same | 1598 |
| Handler, reached from the first copy | `0x42ed300` | `0x42eca60` | 2541, 2207 |
| Handler, reached from the second copy | `0x42edcf0` | `0x42ee6e0` | 2541, 2207 |
| Advance, called when the order stays | `0x42eef80`, `0x42f0af0` | `0x42f0240`, `0x42ef990` | stubbed |

`evidence.json` key `pairing` has the single call site of each link. `copy_differences.tsv` has 25 rows: the perp copies differ in the market fields `+0x1040`/`+0x1048` against `+0x5c0`/`+0x5c8` and in the advance, the spot copies only in the advance, and the callers in field offsets and callees.

### Handler

Arguments: `rdi` tracker, `rsi` user, `rdx` order id, `rcx` result, `r8` exchange, `r9` row vector. The user is looked up in the tree at tracker `+0x18`, and the order in that user's map.

1. A missing user runs the map entry call (`0x495b000`, `0x495a910`) and returns on the empty map it gives. A missing order returns. Neither writes a row or advances.
2. Status `0x186`, success. The result holds a fill vector, pointer at `+0x10`, length at `+0x18`, stride 0x238 (perp) or 0x228 (spot). See Fills.
3. Status `0xc4`, rejected. The word at `+0x08` gives a tag: with the top bit set, the word without that bit; otherwise tag 2. If bit `tag % 64` of `0xfc02f9` is clear, the handler only advances. If it is set, the Display turns the payload into text, and the order ends.
4. Any other status. `0x4b011c0` makes the text with a second argument of 0, and the order ends.

### Rejection tags

`error_classes.tsv` holds one row per arm of the jump table `0x5a572c`, 24 arms, taken from the real Display run on each tag.

| Result | Tags |
| --- | --- |
| Order stays, 11 tags | 1, 2 minimum value (10.0 after `$`, or 10.0 and the payload text); 8 no immediate match; 10 no liquidity for a market order; 11, 12, 13, 15, 16, 17 open interest at cap; 14 open interest rising too fast |
| Order ends, 13 tags | 0 tick size; 3 margin; 4 maximum position; 5 reduce only; 6, 7 post only; 9 TP/SL price; 18 spot balance; 19 too far from oracle; 20 outcome settled; 21, 22 cross margin; 23 halted |

Tags 1, 2, 6 and 13 use templates. Tags 1 and 2 pass the f64 at `0x20a8a8`, which is 10.0, and tag 13 passes the f64 at `0x20a2f8`, which is 0.01. Tag 6 prints two payload fields around an at sign, shown as `[at]` in the table. The templates are length-prefixed strings with `0xc0` for a placeholder, and the tool reads them from the file.

### Fills

With fills `f[0..n]`, and `key`, `first`, `second` at `+0x208`, `+0x210`, `+0x218` (perp) or `+0x1f8`, `+0x200`, `+0x208` (spot):

- `first` and `second` are summed, saturating at u64::MAX. Each overflow calls the recorder with Location `l1/src/qtys/mod.rs:827:1` or `:829:1`.
- If any `key` differs from `f[0].key`, both amounts become 0. The check runs after that row's sums, so recorder calls can come before it.
- If `first` is 0 or above `second`, both amounts become 0. Equal values pass. A `cmova` after this test can no longer change anything.
- Record `+0x28` takes `first` and record `+0x30` takes `second`, saturating, with recorder calls on the same two lines.
- The advance always runs after that, so a success with nothing added still moves the order on.

### Ending an order

1. Perp only: asset `/ 10000` must be below the market count, or `unwrap` panics at `l1/src/dex_registry/clearinghouses.rs:11:29`. Spot has no such bound.
2. The convert call (`0x46ca710`, `0x46ca2b0`) writes 0x58 bytes. Perp passes the market, stride 0x2f0. Spot passes exchange `+0x90`.
3. A row of 0x278 (perp) or 0x268 (spot) bytes is pushed. See below.
4. The order leaves its user's map. If the removal finds nothing, `0x4344430` drops status word `0xce` and the handler returns. If the map is now empty, the user leaves the tree.

A failed text write panics at `library/alloc/src/string.rs:2918:14`.

### Row and status

Row: `+0x00` tag 4; `+0x08` 0x58 bytes from convert; `+0x60` text capacity, pointer, length; `+0x78` order id; `+0x80` exchange `+0x60`, 12 bytes; `+0x8c` user. In the perp flush `0x432a100`, entry 2 of table `0x6eed68` (`tag - 2`) is `0x432a2a7`, which starts with `mov edx, 0x98` for its copy. That 0x98 is the whole body after the tag: 0x58 + 0x18 + 8 + 12 + 20.

The serializer `0x47ef250` reads, from its record pointer: `time` at `+0x78`, `twap_id` at `+0x70`, `state` at `+0x00`, `status` at `+0x58`. Against the row body these are the same four fields in the same places. The `status` field goes through `0x4a87060` to `0x42e9000`, which uses the tag rule of the handler with a default of 3:

| Word at the slot | JSON |
| --- | --- |
| `0x8000000000000000` | `"activated"` |
| `0x8000000000000001` | `"terminated"` |
| `0x8000000000000002` | `"finished"` |
| no top bit | `{"error":"<text>"}` |

The word `0x8000000000000002` is loaded once in each of the four advances, and `0x8000000000000001` once in each of `0x42f2400`, `0x42f2bb0`. A handler's own row, copied from `+0x08` and run through the real serializer, gives `"status":{"error":"Insufficient margin to place order."}` on all four copies (`chains` in `evidence.json`).

### Caller

Offsets here are for `0x4ce0680`. Key `callers` in `evidence.json` has those of `0x4ce0cc0`.

The caller computes one flag: `now < limit`, comparing exchange `+0x60` (date as i32, then seconds and nanos as u32) with `+0x4524`, or `+0x28 < +0x4408` as u64. For each perp result of 0x88 bytes, the asset `/ 10000` picks a dex (`+0x3df0`, stride 0x138, tracker at `+0x18`). A dex at or past `+0x3df8` panics at `l1/src/dex_registry/perp_dex.rs:30:33`. Each result gets a fresh empty row vector, and the rows go to the flush `0x432a100` straight after it. If the byte `+0x4548` is set, the spot side is skipped and an empty vector comes back. Otherwise the spot drain gets the same flag, and spot results run the same way with the flush `0x432a990`.

### Inferences

- `first` is executed size and `second` executed notional. This rests on record position, the reference's two progress fields at `+0x28` and `+0x30`, and recorder lines 827 and 829.
- The gate `0 < first <= second` may be a compiled `second / first != 0`. Only the two comparisons are observed.
- The 0x88-byte record read by `0x47ef250` is the row body without the user.
- These records feed the output named `node_twap_statuses`, whose name is at `0x6fd940` and in the reference at `node/aux.rs:8`. No such link is traced here.
- The flag looks like an activation window on time and height, because a set flag makes the spot drain's slices skip to the advance.
- The stay tags are conditions that can clear by themselves, and most end tags are faults of the order or account. This is a reading of the texts. `Halted` and `Price too far from oracle` fit it less well.

## Implementation and comparison

Rust implementation: not yet implemented. Raw and normalized body comparison: not yet measured.

Comparison here is real bytes against a separately written Python specification. The evaluator runs the bytes of the four handlers, two callers, the Display, `0x47ef250`, `0x4a87060` and `0x42e9000`. Stubs replace the advance, map removal, convert, status text, `memcmp`, `memcpy`, `fmt::write` and `write_str`, the collectors and drains, the flush, and the three other field writers. Stubs record their arguments, and these are compared event by event. The record body, the row prefix and the JSON text are compared byte by byte.

Mutation control: each conditional branch, set, cmov, immediate and non-stack field offset in one perp handler, one spot handler, one caller, the Display and the three serializers is flipped by one bit and the cases rerun.

## Results and limitations

| Metric | Result |
| --- | --- |
| Handler cases, each of 4 copies | 143 |
| Caller cases, each of 2 copies | 42 |
| Display cases | 26 |
| History serializer cases | 18 |
| Field wrapper cases | 10 |
| Handler rows through the real serializer | 8 |
| Mismatches, all runs | 0 |
| Handler outcomes, 4 copies | kept 292, ended and user kept 76, ended and user removed 156, removal found nothing 8, nothing 24, panic 16 |
| Caller outcomes, 2 copies | returns 76, panic 8 |
| Instructions stepped | 141,389 |
| Stepped / total, perp handler | 487 / 516 |
| Stepped / total, spot handler | 438 / 465 |
| Stepped / total, caller | 269 / 309 |
| Stepped / total, Display | 207 / 207 |
| Stepped / total, history serializer | 73 / 73 |
| Stepped / total, field wrapper | 101 / 101 |
| Stepped / total, status serializer | 191 / 191 |
| Mutants killed / survived / unreached | 665 / 6 / 7 |

`mutations.tsv` gives a reason on each surviving or unreached row. The 6 survivors are 2 formatter option words, which only `core::fmt` padding reads and which `handler_pins` fixes instead, and 4 rows of a second user walk that cannot miss. The 7 unreached rows are unwind cleanup.

Limits:

- `key`, `first` and `second` are named by position only. What `key` is, and why `first` may not exceed `second`, is not settled.
- Which row kinds or callers can reach the `"activated"` arm was not traced.
- The hop from the row body to the 0x88-byte record that `0x47ef250` reads rests on matching offsets and sizes. The rest of the flush, which would show that hop, was not read. The row has a user at `+0x8c` that the record does not.
- The flush table entry is read for `0x432a100` only. The spot and second-copy flushes were not read.
- The handlers treat status `0xc4` as the only wrapper of a tag. Which path produces it was not traced.
- One copy per kind went through mutation. The other runs the same cases and differs only as listed.
- The advance is a stub here, so "stays" means the advance is called. What the advance then does is outside this packet.
- No progress gate is requested.

Next question: what are `+0x208`, `+0x210`, `+0x218` of a 0x238-byte fill, and where does the flush put the row body?
