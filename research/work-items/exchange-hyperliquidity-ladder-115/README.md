# exchange: how does node #115 build a Hyperliquidity price ladder, its tick sizes and its funding cost?

This packet lets the Rust reconstruction implement the node #115 Hyperliquidity ladder path exactly: the price tick rule (five significant digits, clamped by the token decimals difference, 1000 for a special token set, four distinct refusal panics), the level generator (round the start price down to the tick, then repeat `round(price * 1.003)`, saturate to u64, floor to one and re-floor to the tick) and the funding cost sum (checked `price * size` over the first `seeded` levels), because all three bodies were run as real instructions over 12,000 cases against a separately written specification, with the libm `round` routine also executed from its bytes, and 57 negative controls were all detected.

- Component ID: exchange (`l1/src/hyperliquidity.rs` callees; Locations in `l1/src/spot_meta.rs` and a vendored `indexmap`)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main `0781ce048` at run time; no reference tree text was used and no node #94 result is reused
- Claim status: observation for bytes, constants, call targets and behaviour on the tested domain; inference for the words "tick", "ladder level", "special token set" and "seeded"; unresolved items are under limits
- Scope included and excluded: included are the tick function `0x3be2a50`, the level generator `0x38bddf0`, the cost helper `0x38bcb80` and the libm round routine `0x63efe40`, all run as real bytes. Stubbed as recorded edges: the u64 key hash `0x47172c0`, the set probe `0x3ed2180` and the vector growth slot target `0x43bbf00`. Unwinding after a panic is not run. This packet requests no progress gate.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/hyperliquidity_ladder_115.py --out research/work-items/exchange-hyperliquidity-ladder-115
python3 -m unittest tests.test_hyperliquidity_ladder_115
```

The tool refuses any input whose SHA-256 differs, uses the shared evaluator `tools/decimal_scaled_u64.py` (extended inside the tool with the packed-double forms these bodies need), needs about 650 MB resident and about 60 s, and is byte-identical between runs and output folders. `MANIFEST.sha256` lists every file here except itself. `measure.json` holds the counts quoted below.

## Evidence

Addresses are virtual addresses; `.text` and `.rodata` equal file offsets.

### Boundaries and reach

`callees.tsv`: the targets reached per harness and how often. The three bodies are exact FDE starts of 807 bytes (`0x3be2a50`), 569 bytes (`0x38bddf0`) and 110 bytes (`0x38bcb80`); the tool refuses a changed extent. The libm routine `0x63efe40` has no FDE; its first `0x71` bytes (through the `ret` at `0x63efeb0`) are pinned by SHA-256 `dd46dae4...d565f` in the tool.

Callers of the three bodies (call bytes): the seed check `0x38bc000` (draft sibling packet) calls the level generator at `0x38bc5d5`, the tick function at `0x38bc82d` and the cost helper at `0x38bc930`; the level generator itself calls the tick function at `0x38bde15` and `0x38bdf51`; the funding packets in `research/work-items` list further direct callers of `0x3be2a50`.

### Tick function `0x3be2a50` (price, token index, context)

Context layout read from the loads: rows pointer `+0x08` and count `+0x10` (32-byte stride, first word the token id, second word the quote id), token table `+0x20` / `+0x28` (stride `0x158`, decimals bytes at `+0x48` and `+0x49`), special-set entries `+0x50` / `+0x58` (16-byte stride, key at `+0x08`), hash keys `+0x80` / `+0x88`.

1. Row index `>=` row count: panic `rows_oob` (`spot_meta.rs:590`).
2. Special set: count 0 is skipped, count 1 compares the row's first word with the single entry, count 2 or more calls `0x47172c0` (hash of the key) then `0x3ed2180` (probe). Only bit 0 of the probe's `al` means found; a found index `>=` count panics `map_oob` (vendored indexmap `map.rs:762`). A hit returns **1000** immediately.
3. Otherwise the tick is `10^(digits(price) - 5)`, from 1 up to `10^15`: the byte ladder compares with `100000`, `10^6`, `10^7`, `10^8`, `10^9`, then `price >> 10 < 5^10`, `>> 11 < 5^11`, `>> 12`, `>> 13` (the same decades without large constants), then `<= 10^14-1` ... `< 10^19`. `tick_by_price.tsv` shows the real table around every power of ten, from 0 to `2^64-1`.
4. Token indices `>=` the token count: panic `tokens_oob` (`spot_meta.rs:119`). The decimals difference is `tokens[second].byte[0x49] - tokens[first].byte[0x48]` as bytes; a borrow panics `decimals_underflow` (`spot_meta.rs:1055`). The tick becomes `min(tick, 10^diff)`; for a difference of 0 that is 1. For a difference of 20 or more `10^diff` does not fit in u64 and the digit tick is returned unchanged (the byte code builds the power from the bits of the difference and drops out on the multiply overflow or on any bit above `0x10`).

### Level generator `0x38bddf0` (token, start price, size, count, context)

Registers: `rdi` output, `rsi` token, `rdx` start price, `rcx` size, `r8` count, `r9` context. The start price is floored to its tick (`price / tick * tick`, at least 1). Then, count times, one 24-byte level is appended (word 0 = 0, word 1 **never written**, word 2 = price; growth goes through the vector grow slot when length equals capacity), and the next price is `u64(max(round(float(price) * 1.003), 0))` with NaN and infinity mapped to 0, saturation at the `2^64` constants, a floor to 1, and a floor to the tick of the new price (the tick function is called again with the new price). The result record is `{cap, ptr, len, size}`. The loop is a do-while: a count of 0 would run 2^64 times, so the caller must exclude it (the seed check does, through its empty-ladder branch).

`round` is the statically linked routine `0x63efe40`: it adds `copysign(0.49999999999999994, x)` and clears the fraction bits (values at or above `2^52` pass through), which is round half away from zero. The tool runs these bytes, not a model of them.

### Cost helper `0x38bcb80`

The argument block holds three pointers: the level vector (`ptr` at `+0x08`, `len` at `+0x10`, 24-byte levels, price at `+0x10`), the level count to take and the size. It sums `price * size` over the first `take` levels (fewer when the vector is shorter). A multiply overflow, a product above `0x7ffffffffffffffe` or an accumulator carry returns `rax = 0` and `rdx` = the sum before the failing level; success returns `rax = 1`.

## Implementation and comparison

`tools/hyperliquidity_ladder_115.py` builds a context, a vector or an argument block, runs the real bytes in the evaluator until the return marker or a panic call, and compares the result, the full recorded call trace (hash, probe, grow, round input bits) and, for ladders, the written and unwritten bytes with `spec_tick`, `spec_ladder` and `spec_cost`, which are written from the listing and share no code with the evaluator. Panic Locations are decoded from the relocated records (the vendored source path is shortened to `z_vendor/...`).

Case mix (12,000): 2,400 cost, 3,600 ladder, 6,000 tick; boundary sweeps at every power of ten, special-set sizes 0/1/2/3/5, found bits with high garbage, decimals bytes at 0/16/20/32/48/255, counts up to 70 (four vector growths), start prices up to `2^64-1`. `outcomes.tsv` lists the outcome classes; `cases.tsv` samples every 10th case.

Negative controls (57): 19 wrong specifications, 28 single-byte patches of the three bodies (each must change a result within the first 300 cases of its own harness), 10 damaged or out-of-range inputs. Their first mismatching case is in `controls.tsv`.

## Results and limitations

Metrics (`measure.json`): 12,000 cases, 0 mismatches; 57 negative controls, 57 detected; 21 unit tests with no skips.

Limits: the hash, the probe and the growth are recorded stubs, so the hash function, the set membership rule beyond "bit 0 of `al`" and the allocator are not claimed; the meaning of the special token set (which tokens, why 1000) is not established; unwinding and drop of the vector after a panic are not run; the field at word 1 of a level is only shown to be unwritten by this function; the tool covers the three bodies only, not the registry write or the market-cap helpers. Names are inferences. No gate is requested.

Next question: reconstruct the market-cap helper `0x434f660` and the registry insert `0x3cd82a0` that consume the ladder, or the set membership pair `0x47172c0` / `0x3ed2180` to identify the special tokens.
