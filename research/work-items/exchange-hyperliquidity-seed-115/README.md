# exchange: Hyperliquidity seeding check of node #115 (hyperliquidity.rs:360, function 0x38bc000)

With this packet the whole decision of the Hyperliquidity seeding function can be re-implemented from bytes: which
requests are refused and with which of fifteen texts, in which order the checks run, the level-count limits (10 to 4000),
the `1.003^n` count formula and its saturating conversion, the three overflow-guarded product limits, the 1e15 price
cap, the two market-cap bands (`[1e9, 1e11]` at the end price and `[0, 1e7]` at the start price, widened to 0.7x / 1.3x
by the real band callee `0x38bcaa0`), the exemption of a token named `HYPE`, the funding cap, and the registry write that
is the only state change - each checked against an independent Python specification (12,000 cases, 59 negative controls,
all detected).

- Component ID: `exchange` (`l1/src/hyperliquidity.rs`, with `l1-shared` Locations in `spot_meta.rs`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `origin/main` at `0781ce048`; no reference source was copied
- Claim status: observation (control flow, constants, offsets, texts, Locations, stub argument registers) and inference
  (field names, meaning of the stub results); no PROGRESS gate is requested
- Scope included: body `0x38bc000` (FDE extent 2705 bytes) and the band callee `0x38bcaa0` (212 bytes), both run for real
  from their bytes. Excluded and replaced by recorded stubs: the registry membership test `0x455be80`, the entry lookup
  `0x4716cc0` with its ring search `0x45584b0`, the supply lookup `0x3cc62f0`, the balance helper `0x3c4b1a0`, the level
  generator `0x38bddf0`, the tick lookup `0x3be2a50`, the market-cap helper `0x434f660`, the cost helper `0x38bcb80`, the
  registry insert `0x3cd82a0`, the f64 library call, the free function `0x635de30`, the lazy-global getter `0x1560a40` and
  the once-initialiser `0x5c87d50`.

## Reproduce

Run from the repository root with the node #115 artifact in place (the binary is never executed):

```
python3 tools/hyperliquidity_seed_115.py --out research/work-items/exchange-hyperliquidity-seed-115
python3 -m unittest tests.test_hyperliquidity_seed_115
sha256sum -c research/work-items/exchange-hyperliquidity-seed-115/MANIFEST.sha256
```

The tool checks the SHA-256 first, then reads the ELF with the shared `tools/decimal_scaled_u64.py` reader (section
headers, `.eh_frame_hdr` search table, RELATIVE relocations). It uses no external program, clock or unseeded randomness
(cases come from `random.Random(<string>)`); two runs into different folders are byte-identical. It keeps one case at a
time, so memory is the 106 MB image plus one 106 MB patched copy while a byte control runs.

## Evidence

Coordinates are virtual addresses of the `.text` image; call sites are offsets from the body start `0x38bc000`.

| file | content |
| --- | --- |
| `callees.tsv` | every call site reached by the cases, its offset and the callee address read from the call bytes |
| `locations.tsv` | the three panic exits with the Rust `Location` decoded from the relocated record |
| `messages.tsv` | the fifteen refusal texts read from `.rodata`, with the lengths the body loads |
| `outcomes.tsv` | how many of the 12,000 cases ended in each outcome |
| `cases.tsv` | every 20th case: generator class, outcome, the six request words and the call sites reached |
| `controls.tsv` | each negative control, its meaning and the first case where it diverged |
| `measure.json` | case count, control count, detected count, mismatches |

Observed layout (register use at entry): `rdi` result slot (tag `0x1a2` = Ok with the amount at `+8`, tag `0xee` =
refusal with a `.rodata` text pointer and length), `rsi` registry map, `rdx` six request words
`{A, token, size, levels, seeded, cap}`, `rcx` state (`+0x18/+0x20` 32-byte token rows, `+0x30/+0x38` 0x158-byte token
records, `+0x370`, `+0x510` tables), `r8` context (word `+0x108` is the only external write).

Order of events, all read from the listing and reproduced by the specification:

1. `levels > 4000` -> "too many Hyperliquidity orders"; `levels < seeded` -> "cannot seed more levels than exist".
2. Registry membership: if `[map] == 0x8000000000000000` the map is a B-tree searched inline (keys at `+0x168`, count `u16` at
   `+0x1c2`, children at `+0x1c8`), otherwise `0x455be80` answers and **a zero answer means "already exists"**.
   A hit gives "Hyperliquidity already exists" (after touching the once-cell at `0x64f01d8` when it is non-zero).
3. Row bounds (panic `spot_meta.rs:590:25`), entry lookup `0x4716cc0`, once-cell `0x64fd9a8`, then the entry is found
   either by an inline B-tree walk (keys at `+8`, values of 24 bytes at `+0x60`, count at `+0x16a`, children at `+0x170`)
   or by the ring search `0x45584b0` (entries of 32 bytes, head and wrap read from the object).
4. When the held word is zero and `levels == 0` the function takes the empty path (step 11 with an empty value). Otherwise a
   non-zero second entry word -> "Hyperliquidity already has token hold"; a non-zero row word -> "quote token must be USDC for
   Hyperliquidity"; no supply -> "Hyperliquidity missing max supply"; `levels < 10` -> "too few Hyperliquidity orders".
5. `x = 1.0 * 1.003^levels` is computed by repeated multiplication (blocks of eight, then the remainder), handed to the
   library call, and the answer is converted to `u64` with saturation (NaN and infinities give 0, `>= 2^64` gives
   `u64::MAX`). `levels*size > 0x1999999999999999`, a count above 1,000,000, `A*count` or `size*A*count` above the same limit
   (or overflowing) -> "Hyperliquidity configuration invalid"; `size == 0` -> "zero Hyperliquidity order size".
6. `size * (levels - seeded)` (saturating) must equal what the balance helper `0x3c4b1a0` reports for the held word, with
   answer 1; otherwise a second balance call and "Hyperliquidity has incorrect balance".
7. The level generator `0x38bddf0` fills a vector of 24-byte levels (price word at `+0x10`); an empty vector panics
   (`hyperliquidity.rs:360:29`). `first*size < 1e6` (no overflow) -> "Hyperliquidity starting order value must be at least 1
   USDC"; first price equal to last price -> "Hyperliquidity starting price too small".
8. For the last price (band `[1e9, 1e11]`) then the first price (band `[0, 1e7]`); a zero price ends the loop: price above
   `1e15` or not a multiple of the tick -> "Hyperliquidity price is invalid"; then `0x434f660` must answer 1 with a market cap
   that `0x38bcaa0` accepts. Otherwise the token record must be named exactly `HYPE` (length 4, bytes `48 59 50 45`), else
   "market cap must be in range [1B, 100B] USDC at Hyperliquidity end price and [0, 10M] USDC at Hyperliquidity start
   price"; a token index beyond the record table panics (`spot_meta.rs:119:33`).
9. `0x38bcaa0`: `lo*700000*100 <= cap <= hi*1300000*100` with every multiplication overflow-checked (overflow -> false).
10. Cost helper `0x38bcb80`: answer 1 with cost `<= cap` or "insufficient usdc for seeding hyperliquidity".
11. Success: once-cell, context word `+0x108` := `A`, registry insert `0x3cd82a0` (value `{vector cap, vector ptr}` or the empty
    form `{0x8000000000000000, levels}`), free of the displaced vector when its capacity word is signed `>= MIN+2` and non-zero,
    result `Ok(cost)` (`Ok(0)` on the empty path). Error exits free the level vector when its capacity is non-zero.

## Implementation and comparison

`tools/hyperliquidity_seed_115.py` lays out registry maps (B-tree of one or two levels, or the ring form), entry maps, rows,
token records, level vectors and the context in the shared evaluator, runs the body bytes with a recorded stub at each
call site, and compares result, context write and the full call trace (arguments seen by every stub) with
`spec()`, written from the listing and sharing no code with the evaluator. The band callee is not stubbed.

12,000 cases come from 35 generator classes (one per refusal text, each panic, success, empty seed, HYPE exemption, band and
product edges, ring and tree entries, signed-capacity edges of the displaced vector). Results are in `outcomes.tsv`.

Negative controls (59, all detected, `controls.tsv`): 19 wrong specifications (limits off by one, inverted tests, dropped
checks, wrong bands), 31 single-byte patches of the body and of `0x38bcaa0` (constants, tags, strides, branch senses,
the `HYPE` bytes), and 9 out-of-range or damaged-input checks (flipped digest byte, address inside a body, wrong extents,
unwritten stub read, non-Location address, 65-bit value, unknown call site, unknown text).

## Results and limitations

- 12,000 cases, 0 mismatches; 59 negative controls, 59 detected; 16 unit tests, none skipped.
- Inference only: the six request words match the 48-byte ledger record that the spot-deploy charge bodies build before their
  "fee" call (`0x240` in those bodies resolves to this function), which suggests a start price, spot token, order size, level
  count, seeded level count and a funding cap; the names are not proven. The text `HYPE` exemption is a byte observation.
- The stubs' contracts are inferred from the registers the body passes and tests. In particular `0x455be80` returning zero
  for "exists", the meaning of `0x3c4b1a0`'s pair, and the f64 library function behind `0x63f08e0` (the specification takes its
  answer as input) are unresolved. The sites named `drop_*` call `0x1560a40`; their purpose is unresolved.
- Entries of the tree forms beyond a node's first levels are exercised only up to two levels and six keys; node capacity
  11 is read from the strides, not tested at full width.
- The binary was not executed; no gate is raised.

## Next question

Reconstruct the level generator `0x38bddf0` and the cost helper `0x38bcb80`, which decide the ladder prices and the funding
amount that this function only validates.
