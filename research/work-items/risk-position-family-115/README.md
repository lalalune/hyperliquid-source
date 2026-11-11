# risk: reconstruct node #115 position fold 0x3bebd70, position check 0x447e810 and margin test 0x469b990 with the account map lookup (SipHash-1-3 + hashbrown probe) and the B-tree iterator

This packet makes it possible to re-implement, as plain executable rule lists, three clearinghouse routines of node #115 that the earlier
position-ratio packet explicitly left out, together with the account-map lookup all of them share: the fold of every position of one account into
a saturating figure (`0x3bebd70`), the single-position check that ends in an emit request or a small status code (`0x447e810`), and the
margin test that combines two helper results with four checked products (`0x469b990`). The lookup is reconstructed down to its hash: the 20-byte account key is hashed with
standard SipHash-1-3 under two keys stored in the map, probed in a hashbrown table with 16-wide control groups, and the entry is found by an inline 20-byte
compare. The rule lists agree with the real bytes of ten functions on 12,535 byte-built cases, and 426 negative controls (31 wrong readings of the rule
lists, 13 structural controls, 382 edited bytes) are all detected.

- Component ID: `risk` (Clearinghouses and risk; reference leads `l1/clearinghouse/*`). Filed under the component ID; the node-wide work item is not assumed.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30` (repository head the packet was built on). No reference source was copied.
- Claim status: observation (bytes run in an evaluator, compared with an independently written rule list); inferences are marked as such.
- Scope included: the whole FDE bodies `0x3bebd70` (898 bytes, 225 instructions), `0x447e810` (990, 217), `0x469b990` (783, 181), the map lookup `0x4716be0`
  (214, 59), its hash `0x4717440` (363, 91) and the hasher write `0x45927a0` (471, 141), the probe `0x3ee6740` (316, 77), the B-tree iterator step `0x37c5ba0`
  (548, 126), the ring search `0x455cb20` (284, 90) and the B-tree search `0x35be560` (146, 39). Scope excluded: the ten opaque callees (eight GOT slots and two direct calls) listed in
  `call-sites.tsv` (run as recording stubs), the callers of the three subjects, the meaning of the helper results, and every other copy of these routines.
  The ring and B-tree searches and `0x35be560` were already run by the earlier position-ratio packet for a different subject; here they serve as callees of `0x447e810`.
  An earlier trace packet (`RE-006-node115-runnerup-search`) lists `0x447e810` only as one of 29 caller frames of `0x35be560`; it records no behaviour of it.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/risk_position_family115.py --out research/work-items/risk-position-family-115
python3 -m unittest tests.test_risk_position_family115
```

The tool reads only the ELF bytes through the repository parsers (`tools/elf_index.py`, `tools/fde_extents.py`), checks the binary SHA-256 first and never
executes the binary. It calls no external program. Two runs into different folders (different hash seed and time zone) were compared with `diff -r` and are
byte identical. A full run takes about 45 s and a peak resident size of about 380 MB on one core; the test file takes about 90 s. Every number in this
folder is produced by the tool and is recorded in `evidence.json` and `measure.json`.

## Evidence

Coordinates are virtual addresses of the loaded image. `.text`, `.rodata` and `.data` are file-backed; the evaluator reads the static default container and
the once word from the file bytes (`.data`), and every heap structure is built by the tool in a private memory.

| File | Content |
| --- | --- |
| `function-rows.tsv` | every instruction row of the ten bodies: address, size, raw bytes, decoded operation (1,246 rows) |
| `call-sites.tsv` | every call site of the ten bodies: direct target or GOT slot, whether it ran as real bytes or as a stub, and where the slot resolves (RELATIVE addend) |
| `locations.tsv` | the panic and saturation `Location` records read from the relocation table and the four message strings |
| `constants.tsv` | the four f64 constants and every `movabs` constant of the ten bodies |
| `named-*.tsv`, `vector-*.tsv` | digests of the named cases and a sample of the generated vector cases per family (`fold`, `check`, `test`, `map`, `hash`) |
| `model-variants.tsv`, `structural-controls.tsv`, `mutations.tsv` | the negative controls |
| `evidence.json`, `measure.json` | totals, per-function unreached rows, outcome counts |

## Implementation and comparison

The evaluator (about 1,000 lines, decoder and interpreter for the instruction subset these bodies use) executes the real bytes. Calls into the ten bodies run as
bytes; the ten remaining callees are recording stubs whose arguments are logged and whose results come from the case. A rule list written separately from
the bytes predicts, per case, the result, the panic or fault, and the exact ordered list of recorded calls. The comparison is exact (result bytes, panic
site, every recorded argument). Cases are generated by an LCG stream and by named lists that target each branch; they are run one at a time and only
counts and sampled digests are kept.

What the bytes do (observed, then the rule list):

**Fold `0x3bebd70`** (`rdi` container, `rsi` table of 96-byte rows, count at `+0x10`, rows at `+8`)

1. The container word 0 is a capacity; the value `0x8000000000000000` selects a B-tree (`root` +8, `height` +0x10), anything else a ring buffer (`buf` +8, `head` +0x10,
   head may be up to twice the capacity). The length is at +0x18 and the starting accumulator at +0x48. Records are 72-byte (key, 64-byte record) in the ring
   and a key array plus 64-byte values in the tree. A ring is walked as two slices from the head; a tree is walked by the real iterator step `0x37c5ba0`.
2. Per position: `key % 10000` (multiply by `0x346dc5d63886594b`, shift 75) must be below the row count (index panic `oracle.rs:433:18`); the row field at +0x20 must be
   non-negative and its product with the record word +0x10 must not overflow (both panic at `position.rs:204:57`).
3. The magnitude of the product is divided by the unsigned 32-bit record word +4 (a 32-bit divide below 2^32, a 64-bit one above; a zero divisor is the
   hardware divide fault, modelled as outcome `fault`). A quotient of 2^63 or more is a `Result::unwrap()` panic with the 43-byte message.
4. Tag (record word +0, compared as a full 32-bit word with 1): not one: `acc = sat(acc + product)`, then `acc = sat(acc - quotient)`; one: `extra = sat(product + c)`
   (c = record +8); if `extra >= quotient` (signed) nothing changes, else `acc = sat(sat(acc + extra) - quotient)`. Every saturation calls the report slot with its
   own `Location` record (three distinct records: `qtys/mod.rs:834:1` for the sum, `impl_ntl.rs:70:1` for the difference and a second record naming the same `impl_ntl.rs:70:1` for the stored-balance sum).
5. Result: `i64::MAX` when the accumulator is `i64::MIN`, else `max(-acc, 0)`.

**Check `0x447e810`** (`rdi` result, `rsi` state, `rdx` 20-byte account key, `rcx` asset key, `xmm0` f64)

1. The f64 must satisfy `not (0.5 > x)` and `not (x > 1.0)`; NaN passes both comparisons. Otherwise the result is the 16-bit code `0x46`.
2. `key / 10000` must equal the state word +0x50 and `key % 10000` must be below the asset count at +0x10, else a panic at `perp_meta.rs:163:38`. The asset mode byte
   (+0x1c of 32-byte rows) must be 2, else code `0x14e`.
3. The account container is found by the lookup below (a hit, or the static default container, which is all zero in `.data`). If the once word at `0x64fdaf8` is not zero the
   once closure is called first (the file value is 3). The position is then searched by key with the real ring or tree search; a miss is code `0x1a2`.
4. Row index panic as in the fold; row field non-negative and product overflow panic as in the fold; record tag bit 0 clear is code `0x1a2`.
5. `total = sat(product + c)` (report slot on saturation); a magnitude of 2^63 or more is the unwrap panic; `scaled = float(|product|) * (1.0 / x)`; non-finite scaled
   becomes 0.0, finite is clipped to 2^63; the cast is truncating, with everything above `2^63 - 1024` mapped to `i64::MAX`; `diff = cast - total`; overflow is code `0xc4`;
   `diff <= 0` is code `0x1a2`; else the emit slot is called with (state, key pointer, asset key) and its 112-byte result is copied, unless its first 16-bit word is `0x1a2`.

**Margin test `0x469b990`** (`rdi` closure context, `esi` side)

1. The account key is the first or second 20-byte key of the pair, chosen by the whole 32-bit side word being nonzero; the sign flip of the later figure uses only the low byte of the side word.
   The lookup and the once call are as above; the container pointer and the state go to the route slot, whose two outputs are `A` and `B` (`B < 0` is the unwrap panic).
2. `gap = sat(A - B)` (report slot), `spare = acc - max(gap, 0)` with the accumulator at container +0x48; overflow of that subtraction drops an error value `0xc4` and returns 2. The big slot and the
   large evaluation helper `0x448bc30` are then called with the logged arguments; its tag 2 returns 2.
3. `rest = A - acc + extra` and, for tag 0 only, `+ unit * delta` (negative unit or overflow returns 2); overflows drop `0xc4` / `0xc3` and return 2.
4. `other = unit * third` (negative unit or overflow: product panic), plus `second` for tag 1 only (saturating, report slot). Result byte: `((tag & 0xff) ^ 1 | other >= -100) & rest >= -100`.

**Account map `0x4716be0`** (state +0x60): entries pointer +8 (0x98-byte entries, 20-byte key at +0x80), length +0x10, hashbrown table +0x18 (control pointer, bucket mask),
SipHash keys +0x38 and +0x40. Length 0 returns null; length 1 compares the 20 bytes directly; otherwise the key is hashed (`0x4717440` writes the 20 bytes with `0x45927a0` and finishes
SipHash-1-3; **the result equals an independently written SipHash-1-3 on all 856 hash cases**), the probe `0x3ee6740` matches the top 7 hash bits against 16-byte control groups,
bounds-checks the bucket word against the length (panic `indexmap/src/map/core.rs:59:35`) and compares the 20-byte key inline. Tables are built by the tool in the
table's own probe order, with fillers (some with the target's 7-bit tag so a group has several candidates), tombstones and 4 to 128 buckets.

Negative controls: `model-variants.tsv` lists 31 plausible wrong readings of the rule lists (for example tag compared by low bit, `>` instead of `>=`, 32-bit divide only,
inverted fraction, side word instead of low byte); `structural-controls.tsv` lists 13 (changed digest, mid-function addresses refused, swapped panic sites, changed f64 bound);
`mutations.tsv` lists 404 byte edits of every reached conditional, immediate and field offset, 382 of which change a result.

## Results and limitations

- 12,535 cases (335 named, 12,200 generated) with 0 mismatches; 426 negative controls, 426 detected; measure in `measure.json`.
- The 22 surviving byte edits are explained one by one in `mutations.tsv`: stores whose value is already in place, the unroll-by-eight thresholds of the iterator (only heights of eight or more), constants whose
  flipped bit is immaterial for the fixed key length 20 or for a comparison against -100, and values that only matter for exactly `DBL_MAX`. None is a missed branch of the rule lists.
- Rows not reached: the iterator's unrolled-by-eight descents and its panics (35 rows), the general-length arms of the hasher write (84 rows: the caller always writes 20 bytes), the probe's
  full-group wrap and capacity panics (11 rows; they need a table with no empty control byte), the map's second bounds check (4 rows; the probe's own check fires first), and two fold rows.
- The ten stubs are opaque: their meaning is not claimed. Observations that follow from the bytes and the resolved slots: the report slot (`0x64e4ea8` -> `0x4524e40`) is called with a null first
  argument and a `Location`; the route (`0x64e6d20` -> `0x3beb980`), emit (`0x64e7b28` -> `0x447d1d0`) and big (`0x64e7b48` -> `0x42051d0`) slots and `0x448bc30` return structures the subjects only read at fixed offsets.
- Inference (not proven): the three subjects look like the isolated-position margin check of the clearinghouse (a per-asset fraction in [0.5, 1.0], a per-account position container, a stored balance per record, a
  floor of -100 in the final test). The names above are descriptive only.
- The once closure is modelled as completing (the word becomes 0) and leaving the all-zero default container; its real body is not run.
- Table layouts, tree node sizes and neighbouring bytes are chosen by the tool; the real allocator layout is not known. The tree-iterator edit at `0x37c5c83` reads two bytes past a leaf node and is explained rather than killed.

## Next question

The large evaluation helper `0x448bc30` (3,317 bytes) that the margin test calls with the two helper results, and the route slot target `0x3beb980` whose two output words feed `A` and `B`;
reconstructing them would turn the stubs of the margin test into real bytes.
