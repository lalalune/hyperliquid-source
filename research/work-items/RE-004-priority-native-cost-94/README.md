# RE-004: how does node #94 turn a price and size into a native token cost with a 1e8 factor?

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, outcomes, the cast table and the factor edge; inference for the words "native token", "price map" and "priority order", which come from error text and arithmetic shape; unresolved items are listed under limits
- Scope included and excluded: included are the three copies `0x24f84c0`, `0x4ae0df0`, `0x4ae1210`. Their helpers `0x375fb50`, `0x3760790`, `0x565f5a0` and the drop functions run as real bytes as edges of this question. Excluded are the callers, the three perp sibling functions next to these copies (other packets list them), the writers of the price map, and the admission gate of priority orders.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/priority_native_cost.py --out research/work-items/RE-004-priority-native-cost-94
python3 -m unittest tests.test_priority_native_cost
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs.

## Evidence

Addresses are virtual addresses. `.text` VA minus file offset is 0x1000; `.rodata` VA equals file offset.

### Boundaries and copies

| Function | FDE | Size | Instructions | Single call site |
| --- | --- | --- | --- | --- |
| `0x24f84c0` | `0x24f84c0..0x24f88dc` | 1052 | 256 | `0x232d926` |
| `0x4ae0df0` | `0x4ae0df0..0x4ae120c` | 1052 | 256 | `0x49e42f6` |
| `0x4ae1210` | `0x4ae1210..0x4ae162c` | 1052 | 256 | `0x49e40b6` |

No `.rela.dyn` RELATIVE record points at any of the three, so nothing reaches them through a slot. The copies differ in 4 of 256 rows each: three direct calls to the drop helper (`0x2506640` against `0x4b10bb0`) and the Location of the pair bound (`0x56bb188` against `0x573dfc8`, both `l1/src/spot_meta.rs:565:25`). See `copy-differences.tsv`.

### Inputs

`rdi` is the result, `esi` a u32 factor, `rdx` a pair index, `rcx` and `r8` two u64 values `a` and `b`, `r9` a context. Fields read from the context:

| Offset | Meaning from the code |
| --- | --- |
| `+0x80` | u32, must be 1 |
| `+0x88` | u64 token id N |
| `+0x1f8`, `+0x200` | pair table pointer and length, stride 0x20, token id q at `+8` of each row |
| `+0x210`, `+0x218` | token table pointer and length, stride 0xe8, bytes `+0x48` and `+0x49` |
| `+0x250`, `+0x258` | root and height of a B-tree from u64 to u64: keys at node `+8`, values at `+0x60`, length u16 at `+0xba`, edges at `+0xc0` |

The fake memory holds only these fields; every other byte is a fill pattern, so a read of anything else would change a result. The real code never reads the value bytes of a stale slot past the length word.

### Closed form

Write `sz(t)` for byte `+0x48` of token t and `wei(t)` for byte `+0x49`.

- `P(t) = 10^(wei(0) - sz(t))`, helper `0x375fb50` through slot `0x5774548`.
- `U(t) = 10^(wei(t) - sz(t))`, helper `0x3760790` through slot `0x5774550`.
- `M(t)` is the map value at key t, or `P(t)` when the map has no such key or no root.

In order, with the error tag or panic at each step:

1. `+0x80 != 1`: tag 0xfb.
2. `M(N)` is computed. A `P` panic can fire here, so a bad N panics before step 3 unless the map holds it.
3. `x = a * b`, 128 bits. Above `0x7ffffffffffffffe`: tag 0x13f.
4. Pair index out of range: bounds panic, `spot_meta.rs:565:25`.
5. `q` is read, then `M(q)`. If `q != 0`, `q` is bounds checked (`spot_meta.rs:113:33`) and `d = U(q)`; if `q == 0`, `d = 1` and the token table is not read.
6. If `x * M(q)` fits in 64 bits, `r = (x * M(q)) / d`. If not, `r = (x / d) * M(q)`, with a flag set when this second product overflows. The order of multiply and divide therefore changes with the size of the product.
7. N is bounds checked, after step 6 on every path (`spot_meta.rs:113:33`).
8. If the flag is set or `r >= 0x28f5c28f5c28f5c`, `r = x`.
9. `amount = ceil(r * U(N) / M(N))`, exact in 128 bits through `0x565f5a0`, then +1 when the remainder is not zero. Above `2^64 - 1`: tag 0xb2. The +1 can carry into the high word; the named case `ceiling carries into the high word` is that input.
10. `f = (factor as f64) / 1e8`. If `f > 1.01`: tag 0xb2, the same tag as step 9.
11. Result tag 0x186 with u64 `cast(f * (amount as f64))`.

`cast` is NaN or +infinity to 0, negative to 0, above `2^64 - 2048` to `u64::MAX`, else truncation. The +infinity row is unusual: a finite value above 2^64 saturates and +infinity gives 0. Both directions that need it are unreached here, because a finite factor times a u64 is finite and not negative (`evidence.json`, `unreached_directions`).

The amount loses its low bits at step 11 for values above 2^53, because the multiply is in f64 even at factor 1.0. Named case `amount above 2^53 rounds` shows it.

With no map entries, `M(q)/U(q) = 10^(wei(0) - wei(q))` and `U(N)/M(N) = 10^(wei(N) - wei(0))`, so steps 6 and 9 are a pure decimal shift from q's wei decimals to N's. A map entry replaces the one-whole-unit term, which is why it reads as a price (inference).

`examples.tsv` holds six worked results from real bytes. With token 0 and N of 8 wei decimals, N of sz 2, `M(N) = 3050000`, `a = 1e8`, `b = 500`: amount is `ceil(5e10 * 1e6 / 3050000) = 16393442623`, and factor 50000 gives 8196721.

### Error text

Tags index the Display jump table at `0x59a8d0`; each arm passes a string pointer and length, read from fixed bytes (`tags.tsv`).

| Tag | Text |
| --- | --- |
| 0xfb | Native token does not exist |
| 0x13f | Invalid input number |
| 0xb2 | Invalid priority |
| 0xb3 | Priority order must be IOC |
| 0xb4 | Insufficient delegatable balance for priority order |
| 0xb5 | Invalid asset for priority order |
| 0x69 | Invalid order |

Tags 0x13f and 0x69 are also built and dropped on the good path before their tests (`tag_writes` in `evidence.json`). Running the drop helper as real bytes shows it does nothing for those words.

### Inferences

These are readings of the observations above, not observations.

- N at `+0x88` is the native token, and `+0x80 == 1` says one is set, from tag 0xfb.
- Token 0 is the unit of the price map, from `P`.
- The result is a cost in native token units, paid by a priority order, from tag 0xb2 and its neighbours. The merged `RE-004-wei-buffered-cap-94` reads the same u32 over 1e8 with the same 1.01 limit and drops the same tag, which it did not name.
- `a` and `b` are price and size, from the shape `a * b` with the limit used for notional. The sources were not traced for this packet.

The reference tree has no text for this: `rg -i "priority order|invalid priority|delegatable" references/can1357-hl/l1` finds nothing, so these three functions have no counterpart there.

## Implementation and comparison

Not yet implemented in Rust. The comparison is real bytes against an integer specification written from the claim.

The evaluator decodes and runs real instructions in Python. Only three slots are stubbed: the panic, overflow panic and bounds entries, which stop the run and report their Location. `0x565f5a0` (128-bit divide), both power helpers and the drop helpers run as bytes. Each run also checks that the result has only the tag and value written, that the context, tables and tree are unchanged, and that callee-saved registers come back.

| Check | Count | Result |
| --- | --- | --- |
| Named cases on each copy | 69 | 0 mismatches |
| Fixed-seed random cases on each copy | 6000 | 0 mismatches |
| Conditional directions covered | all but 2 of each copy | the 2 are explained above |
| Cast, all 2^64 f64 bit patterns | 9 pieces per copy, 1548 runs in all | closed form holds |
| Factor, all 2^32 words | 34 real runs per copy | last admitted 101000000, first refused 101000001 |
| `P` and `U` over all 65536 byte pairs | 131072 runs | closed form holds |
| Mutations of reached conditions and immediates, plus 4 constants, first copy | 79 | 76 killed, 3 survive |

Why these whole-domain rows are proofs: inside one seed range the cast compares a monotone value with constants, so equal decision records at both ends of a piece mean one path, and 256 interior points check the merge. `fl(u32) / 1e8` is monotone and read by one compare, so one edge decides all 2^32 words. The helpers have two byte inputs, so all pairs were run.

The 3 survivors are in `mutations.tsv` with reasons: two write an error word that only feeds a no-op drop, and one is `sar 62` where the low bits are already zero. A survivor outside this list fails the tool. `branches.tsv` gives the count of each direction of every conditional branch and cmov.

## Results and limitations

- Outcomes for integer inputs are checked by vectors, not proved for all u64 values of `a`, `b` and the map. The cast, factor edge and power helpers are whole-domain, and every reached direction was run.
- The 128-bit divide is taken as correct where its inputs were not run. It runs as bytes on every vector.
- The vectors hold the map values at 1 or above. A zero map value at key N is outside the domain of this packet.
- B-tree shapes used are a leaf and one inner level. Taller trees take the same loop, which was not run with height 2.
- Not traced: what fills the price map; who sets `+0x80` and `+0x88`; the sources of `a`, `b` and the factor; how the callers use the result; and why a function indexing the pair table takes this path while another check names asset classes for priority orders.
- Requests no progress gate.

Next question: which assets and order shapes does node #94 admit for a priority order, and what does a nonzero factor change at admission?
