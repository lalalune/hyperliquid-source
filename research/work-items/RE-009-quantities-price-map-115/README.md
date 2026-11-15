# RE-009 quantities: per-asset price-map builder at 0x55be0d0 (node #115)

The 2,225-byte function at `0x55be0d0` is now reconstructed as a complete flow: it turns a market index into either one of two early status words (`0x19e`, `0x101`) or an ordered map of `(dex*10000 + slot) -> 96-bit decimal` prices that it hands, together with the by-value argument map, to `0x55c0010`; this fixes the scale rule (a clamped f64 factor, replaced by 1.0 for the dex-0 names `HYPE` and `PURR`), the saturation and floor-of-one rule, the `6 - szDecimals` power-of-ten divisor, and the five panic edges, so the two members `0x4dd6150` (map insert) and `0x55c0010` (next stage) can now be reconstructed against a known caller contract.

- Component ID: hl-quantities (work-item family RE-009, bundle root `0x55be0d0`, members `0x4dd6150`, `0x55c0010`; only the root is reconstructed here)
- Target release: Linux x86-64 node #115, `artifacts/node/115/hl-node`
- Target SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `a8616af9432b8d8517b2af677880e117b7c28ef3` (`origin/main` when the packet was built)
- Claim status: root `0x55be0d0` reconstructed and compared on 12,000 byte-level cases; five callees run as real bytes; the insert, next stage, price lookup, allocator, drop glue and panic edges are contracts (see Limits). Not a node-wide claim; no gate raised.
- Scope: one function and its inputs/outputs/state. No #94 material is used; no reference-repository label or comment is copied.

## Reproduce

```
python3 tools/quantities_price_map_115.py --out research/work-items/RE-009-quantities-price-map-115
python3 -m unittest tests.test_quantities_price_map_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The tool refuses a binary whose SHA-256 differs, never executes the node and calls no external program. A run takes about 165 s and 335 MB on the build host. Two regenerations into different folders are byte-identical (`diff -r`).

## Evidence

Observations (disassembly of `[0x55be0d0, 0x55be981)`, FDE-exact, 433 instructions, 40 conditional jumps, 15 direct calls, 12 indirect calls; `edges.tsv`, `functions.tsv`, `constants.tsv`):

- Arguments: `rdi` = result slot (written as a `u16` status on early exits), `rsi` = context, `rdx` = pointer to a 21-byte tail record, `rcx` = market index, `r8` = pointer to a 32-byte by-value map (either a B-tree variant tagged by `0x8000000000000000` or a vector of 24-byte elements).
- Market table: `ctx+0x7c8` pointer, `ctx+0x7d0` count, stride `0x510`. `rcx >= count` goes to the unwrap-panic slot `0x64df6a0` (`0x55be8b8`).
- Early exits, in order: `market+0x378 == 0x8000000000000000` or `market+0x408 == 0x8000000000000001` store `0x19e`; else `market+0x58 != 0` stores `0x101`. Each releases the argument map (B-tree: loop on `0x51da3a0` until it returns 0, with the iterator state words at `rsi+0..0x40`; vector: deallocate `cap*24` bytes when `cap != 0`).
- Loop: `n = market+0x10` slots; key `= 10000 * market+0x50 + i` (`mulq` overflow panics at slot `0x64df870`, the add carry at `0x64df520`). The key is looked up in the container at `market+0x428` (ring of 16-byte pairs when `[+0x428]` is not the niche, real `0x45547e0`; otherwise B-tree `0x35bd660` with root `+0x430`, height `+0x438`). The value is an asset id.
- Price: slot `0x64e78b0` (relocated to `0x38bb170`, a clock-reading routine) is called with `rdi = market0+0x148`, `rsi = asset id`, `rdx` = pointer to `{u64 ctx+0x60, u32 ctx+0x68}`, `ecx = 0`; a zero result skips the slot.
- Scale: `S = (f64 ctx+0x7a0 + -1.0) + 1.0` (two separate adds, constants `0x458dc8`, `0x4592b0`). For dex 0 (`market0+0x50 == 0`), an asset id below 10,000 and below the row count whose name length is 4 and whose first four bytes equal `HYPE` (`0x459f10`) or `PURR` (`0x45a1e8`) uses 1.0 instead of `S`.
- Value path: `float(price) * scale` -> routine `0x63efe40` (relocated from slot `0x64e1890`; adds `copysign(0.49999999999999994, x)` and truncates) -> `max(x, 0.0)` (NaN becomes 0) -> an infinity is replaced by 0.0, a finite value is capped at 2^64 -> saturating cast to u64 (limit constant `0x458d58`) -> `max(1, q)`.
- Checks: `asset / 10000` (multiply-high by `0x346dc5d63886594b`) must equal `market0+0x50`, and `asset % 10000` must be below the row count `market0+0x10` (both go to assertion slot `0x64df830`); the byte at `row+0x1d` of the 32-byte row (`market0+0x8` array) must be below 7 (index slot `0x64df848`).
- Quotient: `float(q) / POW10[6 - byte]` with the table at `0x91b7c0` (1, 10, ..., 1e6); split into fraction/exponent and passed to `0x5c43c60` with positive flag, 64-bit and rounding flags set. Tag 1 gives a 16-byte decimal that is inserted via `0x4dd6150(sret, &local_map, key, &decimal)`; any other tag only runs a drop-glue call.
- Finish: `0x55c0010(out, ctx, 0, &arg_map_copy(32), &{1, tail[0..21]}, &local_map(32), market_ptr as the stack argument)`.

Excerpt (objdump, for orientation; the packet itself parses bytes only):

```
55be0e4: cmp    0x7d0(%rsi),%rcx       ; index against market count
55be0fa: imul   $0x510,%rcx,%rbp       ; market record
55be351: mov    $0x2710,%eax ; mulq 0x50(%rbp)   ; 10000 * dex
55be44e: call   *0xf2945c(%rip)        ; price slot 0x64e78b0
55be49d: call   *0xf233ed(%rip)        ; round slot 0x64e1890
55be543: movabs $0x346dc5d63886594b,%rdx ; asset / 10000
55be6e2: call   5c43c60                ; f64 -> decimal kernel
55be79d: call   4dd6150                ; local map insert
55be82c: call   55c0010                ; next stage
```

Inferences (not proven by bytes): the map is the "mark price per asset in decimal" feed for the next stage; the clock-reading price routine is a time-dependent oracle value; the 24-byte vector variant is a small ordered map that `0x4dd6150` converts to a B-tree after 32 entries (read from its first instructions only).

## Implementation and comparison

`tools/quantities_price_map_115.py` carries the shared x86-64 evaluator (copied, with a path-free header) and runs the real bytes of `0x55be0d0`, `0x45547e0`, `0x35bd660`, `0x5c43c60` and `0x63efe40`. Contracts: deallocation, price lookup (table by asset id; events record the argument words), drop glue (event records the tag word and call site), `0x51da3a0` (returns 1 for a case-chosen number of pulls and logs the iterator state), `0x4dd6150` (logs key and 16 payload bytes), `0x55c0010` (logs the argument images and the market pointer) and the five panic slots.

The specification (`spec`) is written separately from the listing. It predicts the outcome, every event in order and the decimal payload; the decimal comes from the existing independent converter specification in `tools/decimal_from_f64_115.py` (itself proven against `0x5c43c60`), applied to the f64 split performed by the root. Cases are 12,000: 46 directed (every saturation edge, `inf`/`nan`/negative/zero factors, all four `HYPE`/`PURR`/`HYPD`/`USDC` x dex cases, tree and vector argument maps for every early exit, add/mul overflow) and the rest drawn from a fixed 64-bit LCG with rings (cap above length, rotated head), B-trees of height 0 and 1, empty roots, inconsistent asset ids and missing prices.

Negative controls: 146 single-byte mutants of the root (every conditional-jump condition, `set`/`cmov` condition, immediate byte and displacement byte). Each runs against a 70-case pool plus the directed cases; a context/market fill pattern is non-uniform so a displaced read cannot hide behind a repeated byte.

## Results and limitations

- `measure.json`: 12,000 cases, all matching (0 differences); 146 negative controls, 118 detected, 28 equivalent with a per-mutant reason in `equivalent-mutants.tsv`, 0 unexplained. 118 + 28 = 146.
- Reached 352 of 433 instructions (`coverage.tsv`). The rest are: unwind pads (`0x55be923..0x55be981`), two duplicate unwrap panics, the non-finite-quotient branch (`0x55be29b..0x55be340`) and the zero/subnormal split (`0x55be6a3..0x55be731`) - the quotient is at least 1e-6 and below 2^64, so it is always a positive normal double - and a few negative-operand and dead-store instructions.
- Equivalent mutants include redundant re-tests of conditions already settled (the displaced field holds fill bytes with the same answer), `u64::MAX` vs `u64::MAX - 1` (both are 2^64 as f64), bit 0 of the fraction mask (the low 32 bits come from the unmasked register), and the dex-0 `asset > 9999` edge (needs 10,000 rows; smaller tables reach the same branch).
- Unresolved: what `0x4dd6150` does after 32 entries and what `0x55c0010` computes (only their call contracts are fixed); what the price routine `0x38bb170` reads beyond its argument words; whether the root's clock-dependent price is a mark, oracle or external price; the writer of `market+0x428` containers; the real meaning of the `0x156`/`0xb0`/`0x1a2` tag words (observed as drop-glue tags only).
- The case sets use hand-built heaps, so they show the function matches its listing for the modelled field layout, not that every live heap shape is covered.
