# fees: volume path at 0x372faa0 (node #94)

- Component ID: fees (path rule `l1/fees/*`, `l1/raw_vlm.rs`, `l1/scaled_vlm.rs`; first task "maker/taker
  fee formulas and time-window rollover")
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository
  `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference leads
  `references/can1357-hl/l1/exchange/impl_trading.rs` and `l1/exchange/handlers/34_twap_cancel.rs`
  (compared below, nothing copied)
- Claim status: observation for the decoded bytes, constants, panic records, exact divisions and
  evaluated outcomes; inference for names and roles; unresolved items at the end
- Scope included and excluded: included - the whole function: the table lookup, the three routes to a
  raw value, both products, the conversion result rule, the flag multiplier, the division by 5, the
  predicate weight, both divisions by 1000000, the update dispatch, eight checked additions and all
  the B-tree searches. Excluded - the bodies of the callees (stubbed), what the sets and maps mean,
  the rate conversion helper `0x32814c0`, `0x37153f0` (separate packet), node #115.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12 (standard library only).
The tool runs no external program, so its output does not depend on a binutils version. The node is
only read as a file and is never executed; the evaluator below interprets its bytes in Python.

```
python3 tools/artifacts.py verify
python3 tools/fees_spot_volume.py --out research/work-items/fees-spot-volume-94
python3 -m unittest tests.test_fees_spot_volume
sha256sum -c research/work-items/fees-spot-volume-94/MANIFEST.sha256
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x372faa0 --stop-address=0x3730b3d artifacts/node/94/hl-node
```

The tool refuses to run if the input SHA-256 differs. It prints
`{"blocks_not_executed": 3, "hook_calls": 8, "instructions": 889, "instructions_not_executed": 24,
"mismatches": 0, "vectors": 1904}` and writes:

- `evidence.json`: extents, constants, sites, panic records, callers, coverage.
- `instructions.tsv`: every instruction with its size, bytes and decoded form, from the tool's own
  decoder.
- `vectors.tsv`: 1904 evaluated inputs and outcomes.

## Evidence

Coordinates are ELF virtual addresses. The function is `0x372faa0..0x3730b3d` (FDE `0xe4d3e0`, 4253
bytes; `.eh_frame_hdr` has 121299 entries). It has no direct call site: pointer slot `0x5774578`, the
slot 24 bytes after the one of `0x37153f0`, names it through a RELATIVE relocation, and `call [rip+d]`
byte patterns through that slot occur at `0x24fd976`, `0x432b038` and `0x432bae8`.

Method. A table decoder reads the bytes from the FDE start and must land exactly on the FDE end, 889
instructions. An evaluator interprets them from entry to `ret` or a panic. Input records fault on unset
bytes. Every call is a stub that keeps the callee-saved registers and overwrites the rest with junk.
The B-tree stubs check the entry handle the search built against the key and the expected slot. Each
outcome is compared with `model()` in the tool, a separate closed form. The steps below are what that
model states, with `rdi = state`, `rsi = record`, `edx = side`, `rcx = runtime`.

1. Table. `t = [record+0x1f8]` indexes 32-byte rows at `[state+0x178]`, length `[state+0x180]`. A row
   holds two ids, `x` at `+0` and `q` at `+8`. An index at or above the length panics at
   `l1/src/spot_meta.rs:565:25`.
2. Raw value, three routes:
   - direct, when `q == 0` or `q` is in the set at `[state+0x248]`:
     `n = product(a, b)` with `a = [record+0x1f0]` and `b = [record+0x200]`. The price of `q` comes from
     the map at `[state+0x1d0]`, or from the call through slot `0x5774548` on a miss. `0x32814c0(n, q,
     price, state+0x10)` returns a flag and a value. The value replaces `n` only if bit 0 of the flag is
     set and the value is below `0x28f5c28f5c28f5c` (`u64::MAX / 100`).
   - priced, otherwise when `x` is in the set at `[state+0x1e8]`: `product(price(x), b)`, with the same
     price lookup.
   - none, otherwise: 0.

   `product(u, v)` is `u * v`, except that a u64 overflow or a result above `0x7ffffffffffffffe` gives
   **0**. It does not saturate.
3. Scaled value. It starts equal to the raw value. If `q` is a key of the map at `[state+0x230]` and
   its value byte at `+0x2c` of the 48-byte value is 1, then `scaled = weighted(raw, [runtime+0xa0])`.
   Only that byte value counts: 0 and 2 leave it unchanged. `weighted(v, f)` is `to_i64(f64(v) * f)`,
   floored at 0; non-finite products give 0.
4. Weight. If `x` is in the map at `[state+0x260]`, `scaled = floor(scaled / 5)`. Otherwise, if the
   predicate through slot `0x5773198` on `(state+0x10, x)` is true,
   `scaled = weighted(scaled, [state+0x150])`. The map wins over the predicate.
5. Units. `raw_units = floor(raw / 1000000)`, `scaled_units = floor(scaled / 1000000)`. All three
   divisions are exact for every u64 by the round-up reciprocal test.
6. Dispatch. The predicate is called a second time. The per-side block is at `record + side*0xf8`, with
   the user id at `+0xd0`, `mode` at `+0x60`, and `gross` at `+0xb0`. `own` is this side's user and
   `other` the opposite one:

   | mode | predicate | gross | external add (`0x3596da0`) | split (`0x3745a60`) | users updated | day totals |
   |---|---|---|---|---|---|---|
   | 2 | false | any | none | no | own | side != 0 |
   | 2 | true | any | none | no | none | no |
   | not 2 | false | any | own | yes | own | side != 0 |
   | not 2 | true | 0 | none | yes | none | no |
   | not 2 | true | nonzero | other, then own | yes | own, other | always |

   The split call gets `q` and the amounts unchanged. Unlike `0x37153f0` there is no multiplication by
   100 here.
7. User update, map at `state+0x298`. If `scaled > 999999`, that is `scaled_units >= 1`:
   `[entry] += scaled_units`, `[entry+8] += raw_units`, and in the day map at `[entry+0x28]`
   `[day entry + 8*match] += scaled_units`. Otherwise only `[entry+8] += raw_units`, and the day map is
   not touched. `match` is `tag == side` for `own` and `tag != side` for `other`, with
   `tag = [record+0x224]` and `day = [record+0x218]`, a signed 32-bit key.
8. Day totals, map at `state+0x358`: `[entry] += scaled_units`, `[entry+8] += raw_units`.
9. Accumulation. The eight additions call the hook at slot `0x5773190` with location
   `l1/src/qtys/impl_ntl.rs:664:1` on carry, then store `u64::MAX` and go on.

Analysis was complete for this function's own instructions; callee bodies were not analysed.

## Implementation and comparison

Not yet implemented. No Rust component is added and no differential execution was run, so there is no
build comparison and no normalization mask.

Comparison with the reference lead, which is not a target comparison. A text search of
`references/can1357-hl/l1` found no function with these steps: the division by 5, the routes, the
predicate and the 999999 threshold do not appear. The nearest is
`process_spot_transfer_with_volume_accounting` in `l1/exchange/impl_trading.rs`, and it differs. Whether
it is the same site was not established.

| item | `impl_trading.rs` | binary |
|---|---|---|
| product above `0x7ffffffffffffffe` | rejected with a status | value 0, and the function goes on |
| divisor | `SPOT_NOTIONAL_PRODUCT_SCALE = 100_000_000` | 1000000 |

## Results and limitations

- Decoding: 889/889 instructions from the FDE start to the FDE end, using no external program. As a
  one-off authoring check, not part of the evidence, GNU objdump 2.42 listed the same 889 addresses and
  the same operation names.
- Evaluation: 1904/1904 vectors match the model, 0 mismatches: 840 route, 460 arithmetic, 192 dispatch,
  72 saturation, 336 tree and 4 admission. Routes: 1206 direct, 392 priced, 303 none, 3 panics. Outcomes:
  1901 ok and 3 table index panics. The vectors are a product of boundary values, a sample and not a
  proof over all inputs.
- Coverage: 865/889 instructions executed. The other 24 are 9 padding nops and three panic blocks,
  and the tool fails if any other instruction stays unexecuted:
  - `0x37309c9..0x37309d9`: a second table bound. The length is read again after callees, so this
    needs a callee to change it.
  - `0x3730af3..0x3730b18`: a sign panic on the raw value, which is at most `0x7ffffffffffffffe`.
  - `0x3730b18..0x3730b3d`: a sign panic on the scaled value, which is 0 or more.
- Unit tests: `tests/test_fees_spot_volume.py`, 46 tests. Negative controls: wrong digest; a wrong file
  through the CLI; addresses outside the image; truncated and over-wide ULEB128; an unlisted opcode; an
  FDE overrun; changed immediates and float constants; a wrong pointer slot; wrong division constants;
  extra and missing unexecuted code; and byte mutations of the threshold at both sites, all three
  division shifts, the limit branch, the product limit on both routes, the flag value and stride, both
  tag compares, the record stride, the signedness of the day compare, the predicate branch, three field
  offsets, and the mode and gross gates.
- Inferences, not proven:
  - This is the spot path. The evidence is the panic in `spot_meta.rs` and the row of two ids. A comment
    in `references/can1357-hl/l1/exchange/handlers/34_twap_cancel.rs` labels `0x24fc8a0`, the function
    that holds one caller here, as the spot persist path, and `0x24fb610`, a caller of `0x37153f0`, as the
    perp one. That comment is a lead, not evidence.
  - `x` is a base token and `q` a quote token, `a` a price and `b` a size. `0x32814c0` converts to a
    common unit. The set at `+0x248` holds quote tokens that need no pricing by `x`.
  - `raw_units` and `scaled_units` are raw and scaled volume. The reference type names fit, but no hook
    location names `raw_vlm.rs` or `scaled_vlm.rs` here.
  - `[runtime+0xa0]` is the same field that `0x37153f0` reads as a fee multiplier.
  - `mode` is the niche of an optional split, as in `0x37153f0`. Only 0, 1 and 2 were evaluated.
- Unresolved: what the predicate is, and whether its two calls can differ, because the stub returns one
  answer for both; what the map at `+0x260` and the multiplier `[state+0x150]` are; what `0x32814c0`
  computes; whether the reference helper above is this site or another one; node #115.
- No progress gate is requested.

Next question: what does `0x32814c0` compute from `(n, q, price)`, and when does its flag clear? That
decides which value the direct route keeps.
