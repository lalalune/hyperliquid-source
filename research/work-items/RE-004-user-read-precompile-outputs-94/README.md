# RE-004: HyperEVM user read precompiles: what each output word holds, and how it scales

This packet shows what a Rust rebuild of eight read precompiles must return word by word: `0x811` scales both user lanes with a floor (the reserve path ceils its borrowed total), refuses a user with no row while `0x801` and `0x804` answer with zeros or an empty list, `0x805` nets pending withdrawals out of the undelegated word and stops at 0, `0x800` and `0x813` sign-extend two of five words, and `0x804` turns each lock time into Unix milliseconds floored at 0.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no code for these precompiles.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are whole functions `0x3305000` (`0x800`), `0x3305ec0` (`0x813`), `0x3248a20` (`0x801`), `0x32480a0` (`0x804`), `0x324c530` (`0x805`), `0x324aba0` (`0x809`), `0x324ba00` (`0x810`), `0x324a610` (`0x811`), and their callees `0x3c18310`, `0x35935b0`, `0x3992540`, `0x3be3530`, `0x3bd0820`, all with mutants. Stubs with checked arguments stand for the ABI decoders, position lookup `0x32696f0`, user lookups `0x371b3a0` and `0x373acd0`, stake sum `0x3c0f050`, hash `0x399c7a0`, the error formatter, the allocator, `memcmp`, the 128 bit divide and `Bytes` construction. The gate order and gas of these functions are the subject of the gas packet in open #814, and they are run here only so the output rows are reached. Excluded: `0x80b`, `0x80c`, `0x80d`, `0x812`, and the eight addresses left out of #814, who fills the state these functions read, and what `0x32696f0` does.

## Reproduce

From the repository root:

```
python3 tools/user_read_precompiles.py --out research/work-items/RE-004-user-read-precompile-outputs-94
python3 -m unittest tests.test_user_read_precompiles
```

The tool takes about 3 minutes on a loaded server. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `address-constants.tsv`, `decoder-label.tsv`, `key-text.tsv`, `holders.tsv`, `output-map.tsv`, `rounding-samples.tsv`, `product-guard.tsv`, `gas-table.tsv`, `lock-time-samples.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs. Row counts are in `evidence.json`.

| Precompile | Function | Input (decoder) | Output | Gas total |
| --- | --- | --- | --- | --- |
| `0x800` | `0x3305000` | user, u16 (`0x37e6a00`) | 5 words | `1000 + 33 * (n + 160)` |
| `0x813` | `0x3305ec0` | user, u32 (`0x37e6480`) | 5 words | `1000 + 33 * (n + 160)` |
| `0x801` | `0x3248a20` | user, u64 token (`0x37e6b80`) | 3 words | `1000 + 33 * (n + 96)` |
| `0x805` | `0x324c530` | user (`0x37e6060`) | 4 words | `1000 + 33 * (n + 128)` |
| `0x809` | `0x324aba0` | nothing (`0x37e6230`) | 1 word | `1000 + 33 * (n + 32)` |
| `0x810` | `0x324ba00` | user (`0x37e6060`) | 1 word | `1000 + 33 * (n + 32)` |
| `0x811` | `0x324a610` | user, u64 token (`0x37e6b80`) | 4 words | `1000 + 33 * (n + output)`, saturating |
| `0x804` | `0x32480a0` | user (`0x37e6060`) | `2 + 3k` words | `1000 + 33 * (n + 32 * (2 + 3k))`, saturating |

Each function starts with the checks of #814: own address in the set at `ctx +0x38`, `n <= 2000`, `1000 + 33n <= gas`, decode. A failed decode returns the text `Invalid input`. In all eight, the output is built before the final gas compare, and a call that cannot pay for it frees the output and returns the no-text form. `output-map.tsv` holds one probe per function, so word order comes from a run and not from a table written by hand. `0x800`, `0x813`, `0x801`, `0x805`, `0x809` and `0x810` hand out `Bytes` from an exact-size buffer, with one vtable slot for an even pointer and another for an odd one. `0x804` allocates room for one word too many, so its capacity never equals its length and only the shared form at vtable `0x5670a08` is reachable.

### `0x811` and `0x3c18310`

Order after decode: token `>= [ctx+0x10]+0x198` gives tag `0xea` with the token. Reserve B-tree at `[ctx+0x48]+0xd0` (stride `0xb0`) misses: tag `0xe1` inner 0. User lookup `0x373acd0` through slot `0x5773e58`, then `0x35935b0` on the map at `+0x18` (32-byte values, key at `+0x168`, length at `+0x1c2`, edges at `+0x1c8`). No row: tag `0xe1` inner 0, not zeros. So a user who never touched a reserve gets a failed read here, and a zero read from `0x801`.

`0x3c18310` takes the row `(r0, r1, r2, r3)`, walks the reserve tree twice and returns two lanes:

```
lane 1: p = r1 * reserve+0x58 (128 bits); if p >= 1e14 * 2^64: flag 0, else q = floor(p / 1e14)
lane 2: p = r3 * reserve+0x78 (128 bits); if p >= 1e14 * 2^64: flag 0, else q = floor(p / 1e14)
flag = r != 0 || q == 0, so with a correct divide it is 1
```

`0x811` writes `r0, q1, r2, q2`, and a clear flag zeroes both words of that lane, `r0` or `r2` included. The lanes fail apart. The guard is the only bound: the compare at `0x3c183e6` cannot set carry, so only the high word decides, which is `p < 1e14 * 2^64`, the exact condition for `q` to fit in 64 bits (`product-guard.tsv`). `rounding-samples.tsv` shows the floor against a ceil on the same inputs. The reserve record at `+0x58` and `+0x78` is the one from #784, where the borrowed total at `+0x40`, `+0x58` rounds up. So one index gives a floor per user and a ceil for the total. When the reserve map misses, `0x3c18310` returns two clear flags, but `0x811` has already refused by then, so the path runs only in direct cases.

### `0x805` and `0x3992540`

`0x3992540` is called from `0x324c69f` and from two other sites (`holders.tsv`). `S = [ctx+0x20]`.

| Word | Value |
| --- | --- |
| 0 | `0x3c0f050(S+0x168, user)`, the stake sum from #599 |
| 1 | `max(U - P, 0)`: `U` is `+0` of the `user_states` value (map at `S+0x1f8`, 0 if absent), `P` as below |
| 2 | `P`, `+0` of the map at `S+0x228` (0 if absent) |
| 3 | `N`, `+8` of the same value (0 if absent) |

`0x3992540` looks up `S+0x228` twice, once for the 16-byte value and once more for `P`, so `U` is read between. Word 1 stops at 0 with `sub; cmovae`. #599 could not say what fills the struct behind the keys `delegated`, `undelegated`, `totalPendingWithdrawal`, `nPendingWithdrawals`, and these four results come in that order. The key run sits at the file offset in `key-text.tsv`. So if the names fit, the reported `undelegated` is `U - P`, and the gate in #599, `x + P <= U`, is the same as `x <= undelegated` as reported here.

### `0x800`, `0x813`

Both pass `[ctx+8]+8`, `[ctx+8]+0x10`, the user and the index to `0x32696f0`. `0x800` takes the index as u16 at decoder `+0x16`, `0x813` as u32 at decoder `+0x18` with the user at `+4`. A tag byte of 2 at `+0x1c` passes the first three words out as an error. Otherwise:

| Word | Source | Width |
| --- | --- | --- |
| 0 | `+0x00` | i64, sign bytes in the top 24 |
| 1 | `+0x08` | u64, zeros above |
| 2 | `+0x10` | i64, sign bytes in the top 24 |
| 3 | `+0x18` | u32 |
| 4 | `+0x1c` | one byte, any value but 2, passed as it is |

### `0x801`, `0x809`, `0x810`

`0x801`: token bound with tag `0xea`, user lookup `0x371b3a0` through slot `0x5773170`, then an inline B-tree walk at `+0x10` (`u64` keys at `+8`, values of `0x18` bytes at `+0x60`, length at `+0x16a`, edges at `+0x170`). A hit gives the three words in order. A miss or an empty map gives three zeros, and there is no error.

`0x809` returns `[[ctx+0x30]+0x28]`. `0x810` tests a hash set at `[ctx+0x40]` (control `+0`, mask `+8`, items `+0x18`, key state `+0x20`, slots `0x58` bytes, 20 key bytes compared with a 16 byte and a 4 byte load), answering 1 or 0 in the last byte. Items 0 skips the hash.

### `0x804`, `0x3be3530`, `0x3bd0820`

`S = [ctx+0x20]`. The map at `S+0x168` holds `user -> (root, height, length)`. A missing user or a null inner root gives `k = 0`. Otherwise `0x3be3530` walks the inner map in key order, with parent pointers at `+0`, parent index at `+0x1ec`, into rows of `0x28` bytes, and `0x3bd0820` turns them into rows of `0x60` bytes. Output:

```
word 0: 0x20
word 1: k
then per row in key order: 12 zero bytes + 20 address bytes, value +0, lock time in ms
```

Value: `+0` amount, `+8` date word, `+0xc` seconds, `+0x10` nanoseconds (node offsets `+8`, `+0x10`, `+0x14`, `+0x18`). Lock time, read from the rows at `0x3be3570`:

```
year = date >> 13, ordinal = (date >> 4) & 0x1ff, days from 0001-01-01 with the 400 year shift for year <= 0
days = ordinal + 1461y/4 - y/100 + y/400 - 719163, with y = year - 1 (integer steps as in the bytes)
ms = (days * 86400 + seconds) * 1000 + nanoseconds / 1e6
ms <= 0 gives 0
```

So a default or old lock reads as 0, and nanoseconds at or above `1e9`, the leap second form, are not rejected (`lock-time-samples.tsv`). This packet does not study the calendar step itself, only that the word comes out of it floored.

## Implementation and comparison

The bytes run in a small x86-64 evaluator inside the tool, with no objdump and no execution of the binary. Each named case builds real fixtures: B-trees with the searched key left in unused slots, a hash table with probes and twins, and for `0x804` trees up to height 17. A rule list written apart from the evaluator predicts the fixture heap, the divide log, the stub events and the output bytes of each run.

341 named cases and 320 vectors matched. 1058 of 1119 edits of reached conditions, immediates and field offsets are found, 61 survive, and each survivor has its reason in `mutations.tsv`. Rust rebuild: not yet implemented.

## Results and limitations

- The functions are whole, but `0x800`, `0x813`, `0x805` word 0 and the user lookups rest on stubs, so nothing here says how those values are made.
- Unreached rows are listed per function in `evidence.json`. They are landing pads, allocation size panics, vector growth that the exact capacity makes dead, and the `0x804` empty and unique buffer forms.
- The floor proof for `0x3c18310` is by the shape of the guard plus edge cases, not an exhaustive run: the divide is a stub that returns `num // den`, and injected quotients reach the flag.
- Unresolved: why the flag test `r != 0 || q == 0` exists, since a correct divide cannot clear it.

Inferences, not observations:

- Lane 1 as borrow and lane 2 as supply follows from #784's reading of the record. The text `basis`, `value` beside `totalBorrowed` in `key-text.tsv` suggests `r0`, `r2` are basis words and `q1`, `q2` are values. No serializer of these words is read here.
- The keys of `key-text.tsv` as the names of the four `0x3992540` results rests on order. The other two callers `0x27db2b5` and `0x375ecdd` are not read here.
- `0x801` words as total, hold and entry value, `0x800` words as size, entry, margin, leverage, isolated flag, and `0x809` as a block number are the natural reading only.
- `0x810` as "user exists" comes from nothing but the 20-byte key.

Next question: what writes the `0x811` row words `r1` and `r3`, and does a write rescale them against the index at that time.
