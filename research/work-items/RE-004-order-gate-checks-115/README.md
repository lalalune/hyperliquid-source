# RE-004: reconstruct the node #115 order-gate scale resolver, market check, margin bound check and 0xd0-row ring search

This packet rebuilds, as executable pure-Python rules proved against the real instruction bytes, four more callees
of the order value gate (`RE-004-order-value-gate-115` names them `resolve`, `market_check`, `margin_check` and
stubs them): the decimals resolver `0x29aea00` (asset index -> record -> kind byte -> exact division by
10^(8-kind) or refusal 0x6a), the market check `0x22e7f80` (eight ordered refusals, a keyed set lookup that
exists in a ring form and a B-tree form, and four host checks), the two-sided margin bound check `0x292a0c0` (up to two
parsed bounds, rescaled by a record kind difference and ordered against each other or against a reference),
and the ring binary search `0x24cd450` over 0xd0-byte rows that the market check calls. The rules reproduce 17200
generated cases with 0 mismatches against the bytes, and 134 negative controls (116 byte mutants, 9 wrong rules,
9 damaged inputs) are all detected. A Rust port can now take, from `tools/order_gate_checks_115.py` instead of
re-reading 3,074 bytes of code, the exact status words and their precedence (0x62, 0x75, 0x103, 0x1d, 0x195/0x193,
0x192, 0x6a, 0x6b, 0x1a2 for the market check; 0xdb, 0x158, 0xad, 0xd9, 0xda, 0x1a2 for the margin check), the
half-of-entry limit comparison, the first-byte-equals-2 quirk of the margin pair, and the exact panics.

- Component ID: RE-004 (quantities and rounding); no other component
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: 0781ce04826eeefd89fe336cb8ea073be0c1de30 / references/can1357-hl (labels were not used)
- Claim status: observation for the control flow, field offsets, constants, status words and comparison widths under the
  stated host model; inference for every role name; unresolved: what the four host checks decide, what the stubbed
  map holds, the parse and rescale bodies behind two slots, and the meaning of the status words
- Scope included: the four bodies above (3,074 bytes of FDE extent, 692 instructions), their field reads and host
  calls. Scope excluded: the bodies behind the stubs, the drop glue `0x277e390`, the map lookup `0x2db0710`, the
  writers that fill the tables, and every progress gate. No gate is requested.

## Reproduce

Working directory: repository root. The tool reads the binary as bytes and never executes it; it needs only
the standard library and the shared evaluator `tools/decimal_scaled_u64.py`.

```
python3 tools/order_gate_checks_115.py --out research/work-items/RE-004-order-gate-checks-115
python3 -m unittest tests.test_order_gate_checks_115
```

The first command rewrites every generated file in this folder (all but `README.md` and `MANIFEST.sha256`)
byte for byte; it was run repeatedly with different hash seeds and time zones with identical output. Input check:
the binary's SHA-256 must equal the value above or the tool stops. `MANIFEST.sha256` lists every file of the folder.

## Evidence

Coordinates are virtual addresses of node #115. Extents come from the `.eh_frame_hdr` table through the shared
evaluator; each body's linear sweep ends exactly at its extent end.

| Body | VA range | Bytes | Insns | Role (inferred) |
|---|---|---|---|---|
| `resolve` | 0x29aea00-0x29aeaf2 | 242 | 73 | index vector -> record -> kind byte; `value / 10^(8-kind)` if exact |
| `market_check` | 0x22e7f80-0x22e81b6 | 566 | 147 | order pre-checks: ordered refusals, set membership, register lookup, limit check |
| `margin_check` | 0x292a0c0-0x292a7bd | 1789 | 335 | two optional text bounds parsed, rescaled and ordered |
| `ring_search_d0` | 0x24cd450-0x24cd62d | 477 | 137 | binary search of a deque of 0xd0-byte rows by 20-byte key |

`sites.tsv` lists every instruction as raw bytes (692 rows); `statuses.tsv` lists every 16-bit status immediate the
bodies store, read from the instruction bytes; `slots.tsv` the host slots and stubbed helpers.

**Resolve rule** (`0x29aea00`, args: out, value, index, table). The table holds an index vector (count +0x10, pointer
+0x8, 0x20-byte entries whose first word is a record number) and a record array (count +0x28, pointer +0x20, 0x158-byte
records with a kind byte at +0x48). An index >= count calls the bounds panic with `(index, count)`; a record number >=
record count calls the one-argument panic. A kind above 8 writes status 0x6a. Otherwise the multiplier is
10^(8-kind) (kind 8: 1, kind 0: 10^8, built from the bits of 8-kind); the value must divide exactly (a 32-bit divide when
value and multiplier fit in 32 bits, else 64-bit), a remainder writes 0x6a, and success writes 0x1a2 at +0 and the
quotient at +8.

**Market rule** (`0x22e7f80`, args: out, ctx, key20, index, amount, flag byte, state pointer on the stack):
1. amount 0 -> 0x62 (no host call).
2. host check A `(ctx, index)` non-zero -> 0x75.
3. flag byte non-zero -> 0x103.
4. the 20-byte key is looked up in the set at state+0xa18: a ring `(cap, ptr, head, len)` searched by `0x24cd450`, or,
   when the first word is 0x8000000000000000, a B-tree `(root, height)` walked inline (node: up to 11 keys of 20 bytes at
   +0x7f0, u16 count at +0x8ce, children at +0x8d0; a null root is an empty set). Present -> 0x1d.
5. `ctx[+0x18][index * 0x20]` is the register id; index >= `ctx+0x20` -> bounds panic (after step 4, so a present key
   hides a bad index).
6. host check B `(ctx+0x58, id)` non-zero: value 1 -> 0x195; any other value with `ctx+0x228 == 1` -> 0x193 with the byte
   7 stored at +2; otherwise fall through.
7. host check C `(ctx+0x58, id)` non-zero -> 0x192.
8. map lookup `(ctx+0x510, &id)` null -> 0x6a; else the entry word `e` is read and host check D
   `(ctx+0x10, id, amount)` returns `(flag, bound)`: success 0x1a2 only when `flag == 1` and `bound <= e >> 1`, else 0x6b.

**Margin rule** (`0x292a0c0`, args: out, bounds, index, flag, reference, table). `bounds` holds bound A (tag word at +0,
pointer +8, length +0x10, byte +0x18) and bound B (tag at +0x20, pointer +0x28, length +0x30); a tag equal to
0x8000000000000000 means absent. Both absent -> 0xdb. A bound's text length above 100 -> 0x158 (the refusal hands back the
bounds pointer, `+0x20` for B). Otherwise the parse slot `(ptr, len)` fills a block; a parse status other than 0x1a2 is passed
through; the pair `(y, x)` at `table[index]` selects two records, the rescale slot gets the 16-byte payload (u32 at block +4, u64
+8, u32 +0x10), the constant 2 and `kind49(x) - kind48(y)` (a borrow calls the subtraction panic); a rescale status other than
0x1a2, or a result of 0, gives 0xad (the status word is passed to the drop glue first, except for the zero result). A alone
succeeds with `(0, A, A byte)`. With B present, B is processed the same way and then ordered: if A's byte is 2 (also when A is
absent) B is compared with the reference, failure 0xda; otherwise B is compared with A, failure 0xd9. The comparison passes only
when `(flag_low_byte ^ (B < other)) | (B == other)` is zero, i.e. B differs from the other value and `(B < other)` equals the low
byte of `flag`. Success writes `(B, A, A byte)`; when A is absent the A field is stack garbage and is not compared.

**Ring rule** (`0x24cd450`): `(0, index)` for a present key and `(1, insertion point)` otherwise over the rotated layout
`(head + i) mod cap`, 0xd0-byte rows with the key first, compare result used only by sign.

Raw tables: `cases.tsv` (case classes with counts), `hook-sequences.tsv` (host-call name sequences), `field-reads.tsv` (every
modelled-memory read by region and offset), `mutants.tsv`, `spec-flaws.tsv`, `damage.tsv`.
Slots `0x64e4e60` and `0x64e6468` carry the addends `0x43099f0` and `0x421e9d0` in the file; this packet only stubs them.

## Implementation and comparison

`tools/order_gate_checks_115.py` runs each body's real bytes on the concrete evaluator in `tools/decimal_scaled_u64.py`
(extended in the tool with `cltq` and call through a register). Memory the model did not write reads as unknown, so an
unexpected read fails the run. The host checks, parse and rescale slots, the map lookup, the drop glue, the panic helpers and
the compare are recorded host calls whose arguments are checked in every run (the margin payload shuffle, the constant 2 and the
kind difference included). Each case comes from a seeded generator (one seed per body derived from its name), runs, and is compared
with the pure rule: outcome (return or panic), status word, payload and the full ordered host-call log.

| Body | Cases |
|---|---|
| `resolve` | 4200 |
| `market_check` | 5200 |
| `margin_check` | 5200 |
| `ring_search_d0` | 2600 |
| total | 17200, 0 mismatches |

Controls (all counted in `measure.json`): 116 byte mutants (every conditional branch flipped, every imm8 of ALU/shift/imul
instructions not aimed at `rsp` incremented, every 16-bit status immediate incremented; each checked against the first 130 cases of
its body; 116 killed, 0 survived); 9 wrong rules (kind 9 accepted, unscaled multiplier, floor instead of exact division, set
check missing, check B any value, missing `ctx+0x228` rule, missing halving, missing flag in the margin order, late insertion point);
9 damaged inputs (flipped binary byte changes the digest, four mid-function starts refused, index past the end is a panic,
unpopulated table and ring refused).
This is not a Rust port: no Rust is written and no equivalence to the original source is claimed.

## Results and limitations

- `measure.json`: cases 17200, negative_controls 134, negative_detected 134 (mismatches 0, mutants killed 116, survived 0,
  spec flaws 9, damage controls 9).
- The four host checks, the map, the parse and rescale bodies and the drop glue are stubs: the packet proves what these
  functions do with the answers, not the answers. In the margin check the fields of an error block other than the status word (and
  the returned pointer for 0x158) are copied junk and are not compared.
- B-trees are generated as complete trees of height 0-2 with at most 3 separators per inner node, rings only sorted with distinct
  keys; unsorted input is outside the model.
- Role names are mine, and the numeric status words are not named by the binary. The 20-byte keys are address-sized and the
  meaning of "register id", "entry word" and the bound texts is not established.
- Next question: the bodies behind host checks A-D (`0x3c11a70`, `0x3c07600`, `0x3c09af0`, `0x3c4b1a0` by their slot addends)
  and the drop glue/tagged-union teardown `0x2308120` that the gate also calls, then the writers of the set at state+0xa18.
