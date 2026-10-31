# RE-004: when does node #94 refuse a spot order as larger than half of total supply?

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the check order, the size rule and the serde key of the supply map; inference for the unit of the map value, for order and TWAP caller names, and for the meaning of the link map; unresolved items are listed under limits
- Scope included and excluded: included are the three gate copies `0x445f170`, `0x445f4f0`, `0x26d1cf0` and the two supply lookups `0x4927990`, `0x284bad0`. The size helper `0x37606b0` runs as real bytes, and its closed form is from the merged packet `RE-004-spot-wei-scale-family-94`. Stubbed as edges: the hash `0x399c4a0`, the 20-byte key compare, the outcome word `0x3728670` and the record lookup `0x3728a70`. Callers are listed, not analysed.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/spot_half_supply_gate.py --out research/work-items/RE-004-spot-half-supply-gate-94
python3 -m unittest tests.test_spot_half_supply_gate
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs.

## Evidence

Addresses are virtual addresses. `.text` VA minus file offset is 0x1000; `.rodata` VA equals file offset.

### Boundaries

`gate-copies.tsv` has one row per copy: FDE, 881 bytes and 219 instructions each. `copy-differences.tsv` compares the copies row by row against `0x445f170`. Three rows differ beyond the code shift: `0x445f4f0` reads the vault tree at context `+0x1350`, `+0x1358` where the others read `+0x8d0`, `+0x8d8`, and `0x26d1cf0` calls lookup `0x284bad0`. Those two lookups have equal bytes (`supply_lookups` in `evidence.json`).

`call-sites.tsv` lists the six direct calls, two per copy. No `.rela.dyn` RELATIVE entry points at a gate. Each site has one `lea 0x80(%r13|%r14),%rsi` and one call to a size scaler in the 0x110 bytes before it (`0x4ca6a90`, or `0x230b0e0` for the third copy), so the size argument is the scaler's output.

`tag-0x67-census.tsv` has 4 byte hits for tag 0x67 in `.text`: one write per gate, and one that sits inside the rel32 of a call at `0x4fe47c5`. Register-then-store forms of the tag are not covered by this scan.

### Check order

Arguments: `rdi` result, `rsi` spot struct, `rdx` user, `rcx` spot index, `r8` size, `r9b` flag, stack word context. The first failure wins (`check-order.tsv`, `outcomes.tsv`):

| Step | Test | Result |
| --- | --- | --- |
| 1 | size == 0 | tag 0x5e `Order has zero size.` |
| 2 | index >= `[+0x180]` | bounds panic, `l1/src/spot_meta.rs:565:25` |
| 3 | row word `+8` of `[+0x178]` (stride 0x20) missing from the tree at `+0x260`, or its byte is not 0 | tag 0x71 `Trading is halted.` |
| 4 | `r9b` != 0 | tag 0xf4 `Reduce-only is invalid for spot trading.` |
| 5 | user found in the 20-byte key tree at context `+0x8d0` or `+0x1350` | tag 0x1d `Vault cannot trade spot.` |
| 6 | outcome word of token t (row word `+0`) | 0 passes, 1 gives tag 0x17f `Invalid spot`, others give tag 0x17d with payload 7 when byte `+0x168` is 1, and pass when it is not |
| 7 | t found in the hash map at `+0x80` with value u, record of u exists, record `+0x30` == u | tag 0x17c `Cannot trade fallback token` |
| 8 | t missing from the tree at `+0x388` | tag 0x66 `Order has invalid size.` |
| 9 | t >= token count, or decimals outside the helper's range | panic in `0x37606b0`, `spot_meta.rs:113:33` or `1199:57` |
| 10 | size rule below fails | tag 0x67 `Order size cannot be larger than half of total supply.` |
| 11 | none | tag 0x186, success |

Tag 0x17d prints `Outcome error: ` then the payload through table `0x59b088`; entry 7 is `Internal`. An empty hash map (`+0x98` == 0) skips the hash call, so step 7 reads nothing. A result writes only its tag word, plus the payload byte for 0x17d; the rest of the fill pattern must survive every run. The evaluator fills every other register with poison, so no further register input exists on any reached path.

### The size rule

For every u64 size >= 1, every u64 supply and every k = wei decimals - sz decimals in `0..=19`:

```
admitted  <=>  size * 10^k <= supply >> 1   (exact integers)
```

A product past u64 gets tag 0x67, never a wrapped compare. The half floors, and equality passes. Supply 0 or 1 refuses every size. The proof has two pieces, both checked per k or per copy:

- `amount-ladder.tsv`: a taint walk over the real helper path shows the size word reaches only moves and the final `mul %rcx` at `0x37606e7`, so no branch depends on it. The block from `0x37606e2` is pinned as bytes: `xor esi,esi; mov rax,rdx; mul rcx; mov rdx,rax; setno sil; mov rax,rsi`. The multiplier from real bytes is 10^k, and the path is the same at sizes 0, 2, largest fit, first wrap and u64::MAX.
- `comparison-tails.tsv`: after the helper every copy runs exactly `test $1,%al; je fail; shr $1,%rbx; cmp %rbx,%rdx; ja fail`, then the 0x186 write. Both branches reach the 0x67 block. `rbx` is the word the lookup returned.

`threshold_runs` then runs the real gate at sizes 1, top, top + 1, largest fit, first wrap and u64::MAX, for all 20 values of k and 13 supplies including 0, 1, 2^63 and u64::MAX: 3705 runs across the copies, 0 mismatches.

### The supply map is `token_to_max_supply`

`spot-fields.tsv` binds names from serializer bytes. In six serializers the key `token_to_max_supply` (19 bytes) sits next to one `lea 0x388(%reg)`. `0x3721d10` also passes `meta` from `+0x10`, the offset the gate gives the helper for the token table. So the second argument is the struct these serializers write, and the word compared is the max supply entry, not a live balance sum, despite the word `total` in the error text.

### Comparison with the reference

`references/can1357-hl/l1/exchange/handlers/35_twap_order.rs` lists the spot path `0x24F7BD0` with a status enum. Status 103 and status 29 are not in it, and `rg -i "half.*supply"` finds nothing under `l1`, so the rule of this packet is absent there. Where a label exists, the binary text differs:

| Status | Reference label | Binary text and use |
| --- | --- | --- |
| 102 | `STATUS_GRID_SIZE_MISMATCH` | `Order has invalid size.`; here it means no max supply entry |
| 244 | `STATUS_SPOT_REDUCE_ONLY_REQUIRES_FLAG` | `Reduce-only is invalid for spot trading.`; any nonzero flag refuses |
| 380 | `STATUS_SPOT_OPEN_ORDER_CONFLICT` | `Cannot trade fallback token` |
| 381 | `STATUS_SPOT_STATE_REJECTED { aux_code }` | `Outcome error: Internal` at this site |
| 383 | `STATUS_UNKNOWN_SPOT_ASSET` | `Invalid spot`, from outcome word 1 |

### Inferences

These are readings of the observations above, not observations.

- The map value is in wei, so the rule compares like units. The reference types `max_supply` as `Wei`, and the helper multiplies by `10^(wei-sz)`, which turns raw size into wei if the scaler output is raw size.
- The flag is reduce-only, from the tag text. The TWAP callers load it from action byte `+0x19`, read by eye.
- `0x4adf630`, `0x4adfe30`, `0x24f7bd0` are spot TWAP entries and `0x4c17b10`, `0x4c19420`, `0x21f8520` are spot order paths. The reference names `0x24F7BD0` a TWAP path. The rest is by shape only.
- Row word `+0` is the base token, because orders are sized in base. Row word `+8` is a book key.
- The map at `+0x80` links a token to another id for the outcome token rules, from the text of tag 0x17c. Its serde key was not found.

## Implementation and comparison

Not yet implemented in Rust. The comparison is real bytes against a specification written from the check order (`spec`).

Real instructions run in a Python evaluator, including the SSE group probe of the hash map, the three B-tree walks and the size helper. Fixtures are real node and table layouts: unused B-tree key slots hold the searched key, and wrong values sit beside right ones. Stubs check their arguments, and the call order is compared with the specification.

| Check | Count | Result |
| --- | --- | --- |
| Named cases, each copy | 69 | 0 mismatches |
| Fixed-seed random cases, each copy | 3000 | 0 mismatches |
| Threshold runs, all copies | 3705 | 0 mismatches |
| Helper ladder | 20 values of k, 5 sizes each | one path, exact product |
| Mutations of conditions, immediates, displacements and the shift, first copy and its lookup | 132 | 131 killed, 1 survivor |

The survivor is the `pshufd` immediate at `0x445f3cd`: 0x45 picks an equal dword, because every byte of xmm0 holds the same tag. Every conditional branch in all copies ran both ways (`branches.tsv`). Mutations cover one copy, since the other two are equal row by row apart from the listed rows.

## Results and limitations

- `0x3728670` is stubbed, so which tokens give outcome word 1 or 2 is not stated here, and neither is the meaning of byte `+0x168`.
- `0x3728a70` is stubbed; only its null test and record `+0x30` are used.
- The writers of `token_to_max_supply` were not traced, so nothing here says the map holds every token, or when a value changes.
- The gate reads no side, price or balance, so buys and sells are treated alike here. Later checks in the callers are out of scope.
- Fixtures hold at most three B-tree nodes. Node search is linear in the bytes, so depth beyond one level adds no new branch, but larger trees did not run.
- Requests no progress gate.

Next question: who writes `token_to_max_supply` (spot genesis, deploy or a later update), and can a stored value differ from the token's own supply record?
