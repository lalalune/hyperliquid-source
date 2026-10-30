# RE-004: what price does node #94 give a generated Bole order?

- Component ID: RE-004 (quantities and rounding), exchange Bole path
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (labels checked as leads only, nothing copied)
- Claim status: observation for the bytes, the outcomes and the tail table; inference for the names taken from the Location path and the reference; unresolved items are listed under limits
- Scope included and excluded: included are the two row functions `0x2774c40` and `0x4c6bf70` and the three filter loops `0x251a290`, `0x47f71d0` and `0x47f8550`. Excluded as edges are the row helper `0x327f720` (subject of `RE-004-spot-wei-scale-family-94`, stubbed here), the callers of the loops, and the source of the third word. `round` at `0x565f410` runs as real bytes because the price depends on it, but it is a subject of open #197, not of this packet.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/bole_generated_px.py --out research/work-items/RE-004-bole-generated-px-94
python3 -m unittest tests.test_bole_generated_px
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs.

## Evidence

Addresses are virtual addresses. `.text` VA minus file offset is 0x1000; `.rodata` VA equals file offset.

### Boundaries and copies

| Function | FDE | Size | Called from |
| --- | --- | --- | --- |
| row `0x2774c40` | `0x2774c40..0x2774fc6` | 902 | `0x251a2fd`, `0x251a45a` |
| row `0x4c6bf70` | `0x4c6bf70..0x4c6c2f6` | 902 | `0x47f723d`, `0x47f739a`, `0x47f85bd`, `0x47f871a` |
| loop `0x251a290` | `0x251a290..0x251a5db` | 843 | `0x276695c` |
| loop `0x47f71d0` | `0x47f71d0..0x47f751b` | 843 | `0x4d97e49` |
| loop `0x47f8550` | `0x47f8550..0x47f889b` | 843 | `0x4d997f9` |

The row copies decode to 177 instructions each and differ in one row: the Location passed to the row helper at offset `+0x2d5` (`copy-differences.tsv`). Both Locations read `l1/src/exchange/impl_bole.rs:377:35`. That path is why this is called the Bole path. The row helper is reached through slot `0x5774e20`, which holds `0x327f720`; that slot has 4 callers.

### Input and outcomes

The row function takes an output pointer, a context and a pointer to a 24-byte triple `(key, quote, m)`, where `m` is an f64 at `+0x10`. `outcomes.tsv` lists the 28 named cases. In order:

1. `key == 0`: output tag 2. No state is read.
2. `key >= [exchange+0x218]`: panic with Location `l1/src/spot_meta.rs:113:33`. The rows are 0xe8 bytes wide at `[exchange+0x210]`.
3. Walk the index list at row `+0x58`, length `+0x60`. An index at or past `[exchange+0x200]` panics with Location `l1/src/spot_meta.rs:565:25`. A slot (0x20 bytes wide at `[exchange+0x1f8]`) with a nonzero word at `+8` is skipped. An exhausted list gives tag 2.
4. Look up `key` in the B-tree at `[exchange+0x568]`, height `+0x570`. Node layout read from the bytes: length u16 at `+0x7f2`, keys at `+0x798`, edges at `+0x7f8`, 0xb0-byte values from `+0`. A missing key gives tag 2. The value word at `+0x10` is the reference price.
5. The counter at `[exchange+0x38]` goes up by one, saturating at `u64::MAX`. The template carries the value from before the bump.
6. The row helper gets slot index, `side = 1`, the price, `quote`, `exchange+0x90` and the Location. A row whose first dword is 2 gives output tag 2, and the counter stays bumped.
7. Otherwise 0x210 row bytes are copied out, `+0x210` is replaced by the reference price, and `+0x218..+0x228` is copied.

`template.tsv` lists every byte the function writes into the 0x1f0-byte template. Two sub-records sit 0xf8 apart; the word 2 at `+0x60` and `+0x158`, the counter at `+0xc8` and `+0x1c0`, 20 `0xbb` bytes at `+0xd0` and the 20 context bytes at `+0x1c8`. Every other byte keeps the stack mark, and the tests compare all 0x1f0 bytes.

### The price

```
0x2774c75  movsd  xmm0, [rdx+0x10]      ; m
0x2774e35  addsd  xmm0, [0x20a278]      ; -1.0
0x2774e66  addsd  xmm0, [0x20a730]      ; +1.0, reference word already in xmm2
0x2774e6e  mulsd  xmm0, xmm2
0x2774e72  call   [0x576f6d8]           ; round
```

The tool pins these rows by exact form, and it also checks that nothing else in that range writes `xmm0`. Both additions are present in both copies. So

```
px = tail(round(((m - 1.0) + 1.0) * (reference as f64)))
tail(y) = 1                      if y is NaN, y <= 0 or y is +inf
          u64::MAX               if y >= 2^64
          max(1, trunc(y))       otherwise
```

`round` is half away from zero. 359 values, including the neighbours of `2^k + 0.5` for k up to 53, match an exact rational model.

`tail` is proved over all 2^64 f64 bit patterns for both copies. The round call is made to answer a chosen pattern and the whole function runs. Each piece of the table has one decision record (every branch, cmov, compare and cast outcome from the round return to the end of the floor). Inside one sign class the value is monotone in the bits and each compare has a constant side, so equal records at both ends mean one path for the whole piece. 256 interior points per piece are also held to the closed form. There are 15 pieces per copy from 3240 refinement runs (`tail-pieces.tsv`). Note that +inf gives 1, while a finite value above 2^64 gives `u64::MAX`.

### The filter loops

Each loop reads 24-byte triples from an iterator, calls the row function and keeps rows whose tag is not 2, in input order. Rows are 0x228 bytes. The first keep allocates 4 rows (0x8a0 bytes), and a full vector calls a growth helper. The input buffer is freed once, with size `24 * capacity`. 9 cases on each of 3 loops match (`wrappers.tsv`). The row function and the growth helper are edges here, so the capacities past 4 in that file follow the stub, which doubles.

## Implementation and comparison

Rust implementation: not yet implemented.

`references/can1357-hl/l1/exchange/impl_bole.rs` is close and was the lead for this packet. It differs from the bytes in these ways:

1. Line 281 computes `multiplier * reference_px`. The bytes compute `((m - 1.0) + 1.0) * reference`. The results differ where the two additions change `m`: `m = 0.1, reference = 15` gives 1 in the bytes and 2 in the formula, and `m = 1e-17, reference = 1e18` gives 1 and 10 (`price-examples.tsv`). In the case set, 126 of 1851 price cases differ. For `0.5 <= m <= 2`, `m - 1.0` is exact (Sterbenz), so the sum gives back `m` and the two agree. `multiplier-identity.tsv` shows `m` unchanged in every sampled row at exponent 0 and above, and changed in part of the rows below that.
2. `BoleBuildOutcome::invalid_market`, `invalid_scale` and `product_overflow` have no counterpart in the row function. The two bounds checks are panics with `spot_meta.rs` Locations. Every failure the row helper reports becomes the same tag 2 as a no-op, after the counter bump.

The reference agrees on the rest: the zero-key no-op, the slot skip, the saturating counter, the 0x228 row, the 0x1f0 template, the `0xbb` bytes, `side = 1` and the floor of 1.

Comparison method: the real bytes run in a byte evaluator (x86-64 decoder and SSE subset, copied from the tool of open #197) with these edges stubbed: row helper, memory copy, panic, allocator and vector growth. A separately written specification predicts the whole outcome for each case: the kind, the counter, all row helper arguments, all template bytes and the output bytes. Unused B-tree key slots hold a stale copy of the searched key, so a walk past the length is seen.

## Results and limitations

| Metric | Result |
| --- | --- |
| Row function cases per copy | 1879 of 1879 match (1865 rows, 9 tag 2, 3 panics, 2 bounds panics) |
| Price cases | 1851, of which 126 differ from the reference formula |
| `round` values | 359 of 359 |
| Tail pieces | 15 per copy, all 2^64 patterns |
| Loop cases | 27 of 27 |
| Mutations of `0x2774c40` | 62: 59 killed, 3 survive |

Mutations flip each reached condition and immediate, drop either addition or both, and change four constants. The three survivors cannot be seen by any input, and the reasons are in `mutations.tsv` and enforced by the tool: a mask bit that never decides the compare, a shift whose result only differs on bits already zero, and a one-byte longer copy into a word that is overwritten. The bound change at `0x2774e92` changes only one input, `f64::MAX`, and is killed by the whole-domain pass rather than by vectors. Dropping both additions, which is the reference formula, is killed.

Limits:

- The proof over all inputs covers the tail only. The steps before it are pinned rows plus IEEE arithmetic, and the u64 to f64 conversion and `round` are checked on vectors. `round` is not proved here.
- The three stubbed edges are not modelled. What the row helper does with the price is outside this packet.
- Only `0x2774c40` is mutated. `0x4c6bf70` is covered by the row comparison and the same cases.
- Unresolved: what `m` means, why the source keeps both additions, the meaning of the two words set to 2 in the template, and the fields of the 0xb0-byte value beyond `+0x10`.
- The names `quote`, `reference` and `m` come from the reference and its row helper use. They are not proved by bytes.
- No progress gate is requested.

Next question: what fills the third word? The caller `0x2765600` appears to have two sources, a stored f64 in a per-token map and a ratio of two u64 values with default 1.0, and it scales a per-token amount by a pool word at `+0x78` over 1e14. Neither is pinned here.
