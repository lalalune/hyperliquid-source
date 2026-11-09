# RE-008: node #115 shared value observer `0x1547530` (21st stage): value clamps, day sums and window sums

- Component ID: abci. Question: the 20th stage (open PR #5946) found that the record entry adds count × value to the day sum `+0x210`, and that the window record turns the day totals into `total_n` and `total_mean`. It left open the float check between the product and the store, and whether code outside the record entry reads `+0x208` or `+0x218`.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5045, #5839, #5865 and #5946. It does not depend on their files.
- Claim status: instruction bytes, constants, offsets, FDE extents and the operand census are observations. The two clamp rules are a hand trace of the pinned branch sequence, written as Python models in the tool; they are not computed from the bytes. "Ring", "day", "window", "count" and "calls" are inferred labels. The binary was not executed.
- Scope included: the record entry from the day reset `0x1547562` to the window sum store `0x1547898`, the overflow target `0x1548a0b`, the constructor's `+0x218` store, and a census of `[reg+0x208]` / `[reg+0x218]` operands in the 77 functions that call the record or constructor slot. Scope excluded: the window rollover (#5839), the window record (#5946), and the data flow of the census operands.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/observer_value_range_115.py --check
python3 -m unittest tests.test_observer_value_range_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the count

- When the flag `+0x25c` is 1, the count is multiplied by 50 (`mov ecx, 50` / `mul rcx` at `0x15475ba`, `0x15475c2`).
- On overflow, `jo` at `0x15475cb` goes to `0x1548a0b`, which sets the count to `u64::MAX` and returns to the conversion. So the ×50 count saturates; it does not panic.
- The count is converted to f64 and multiplied by the value (`mulsd` at `0x15475fd`, #5946).

## Evidence 2: the product clamp (`0x1547601..0x1547658`)

The product's bits are tested with the masks `0x7fffffffffffffff`, `0xfff0000000000000` and `0xfffffffffffff`, and the bound `0x3ff` on `(abs + 0xfff0000000000000) >> 53` (normal exponent), plus `bits - 1 < 0xfffffffffffff` (positive subnormal) and `abs == 0` (zero).

Traced rule: the product is kept when it is ±0 or positive and finite. A negative, NaN or infinite product becomes `0.0`. There is no panic and no counter on this path; the record still counts the call.

| Product | Used |
|---|---|
| 1.5, 1e308, 5e-324 | unchanged |
| 0.0, -0.0 | unchanged |
| -2.0, -5e-324 | 0.0 |
| inf, -inf, NaN | 0.0 |

## Evidence 3: the day sums

- `+0x210` = clamp(`+0x210` + product), stored at `0x1547758`. The sum clamp uses the same tests, then compares the absolute bits with `0x7ff0000000000000` (`0x1547745`): a sum of `+inf` becomes the constant at `0x459090`, which is `0x43f0000000000000` = 2^64 as f64. A negative, NaN or `-inf` sum becomes 0.0.
- `+0x200` = `+0x200` + count, saturating at `u64::MAX` (`cmovb` at `0x1547721`).
- `+0x208` = `+0x208` + 1, saturating (`cmove` at `0x154773a`).
- On a new date (`0x1547562`), `+0x200..+0x218` and the ring head and length (`+0x50`, `+0x58`) are zeroed.

## Evidence 4: the window sums

- The raw value (not the clamped product) is pushed to the front of the ring: head at `+0x50`, length at `+0x58`, buffer at `+0x48`, capacity at `+0x40`. The length is cut to the limit at `+0x1f8` (2000 per #5839).
- `+0x88` = clamp(`+0x88` + product), with the same 2^64 constant (`0x154784a`, store `0x1547898`).
- `+0x78` = count, saturating; `+0x80` = calls + 1, saturating.

So the window and the day keep the same three totals: count, calls and clamped value sum.

## Evidence 5: `+0x208` and `+0x218` outside the record entry

- The constructor stores `+0x218` with `movsd [r14+0x218], xmm0` at `0x1548dd2`. #5865 reads this as the scaled first guard constant. The record entry does not read it.
- Census: in `.text` there are 1261 `[reg+0x208]` and 1994 `[reg+0x218]` operands with a 32-bit displacement and a base other than `rsp`. Inside the 77 functions that call the record slot `0x64e1010` (68 calls) or the constructor slot `0x64e1020` (35 calls), there are 17 and 13. The full list is in `evidence.json`.
  - Two of the `+0x208` sites are the record entry's own increment (`0x1547732`, `0x1547740`); one `+0x218` site is the constructor store.
  - Spot checks: `0x15ed69c` tests a byte flag at `+0x200` and takes a pointer at `+0x208`; `0x422acd0` reads `+0x208..+0x220` and then writes `+0x208 = 0`, `+0x210 = 8`. Neither matches the observer layout (`+0x200` is a u64 count, `+0x210` an f64 sum), so these bases are inferred to be other structs.
  - The other sites are not classified.

## Implementation and comparison

The tool pins 65 instruction byte runs, two RIP-relative loads of the 2^64 constant and the constant itself, then recomputes the census. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: computing the clamp rules from the bytes by emulation (not allowed for this repository).

## Results and limitations

- Result: the observer never stores a negative, NaN or infinite value in its day or window sums; such products count as 0, and an overflowing sum saturates at 2^64. Counts saturate at `u64::MAX`, including the ×50 count.
- Limits: the clamp rules are a hand trace of pinned bytes, not a proof. The census matches one operand shape (32-bit displacement, non-`rsp` base) and does not follow data flow, so it cannot show that no other code reads `+0x208` or `+0x218` through an observer pointer. 23 of the 30 census sites (the ones not named above) are not classified.
- Next lead: classify the remaining census sites, starting with `0x2cc1120` and `0x54a9c70`, which hold observers (#5872, #5931).
