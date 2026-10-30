# RE-004: what is the f64 at dex record +0x2a0 in node #94, and how does a notional pass through it?

- Component ID: RE-004 (quantities/rounding)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c`; `references/can1357-hl` used for leads only, no code copied
- Claim status: observation for bytes, tables and the whole-domain pieces; inference where marked; unresolved items are
  listed
- Scope included and excluded: included are the serde key of the field, its 3 rule-based writer copies, the gate of
  `0x370c100`, and the f64 to i64 chain at 6 sites (2 helpers and 4 inline copies). Excluded are 19 `mulsd` sites and 4
  loads in functions named by other work items or open pull requests, which `field-uses.tsv` lists unread. What each
  caller does with the result is not read.

## Reproduce

Run from the repository root. Python 3 standard library only; no objdump, no execution of the binary.

```sh
python3 tools/usdc_ntl_scale.py --out research/work-items/RE-004-usdc-ntl-scale-94
python3 -m unittest tests.test_usdc_ntl_scale
```

The tool checks the binary digest first and takes about 25 s, half of it on the negative controls. FDE extents come from
`tools/fde_extents.py` and sections from `tools/elf_index.py`, so `.bss` and other NOBITS sections are not
address-resolved. Files: `evidence.json`, `field-binding.tsv`, `field-uses.tsv`, `callers.tsv`, `writer-copies.tsv`,
`writer-pieces.tsv`, `clamp-sites.tsv`, `clamp-pieces.tsv`, `gate-pieces.tsv`, `mutation-controls.tsv`.

## Evidence

Addresses are ELF virtual addresses of node #94. All numbers below are in `evidence.json` or the TSV files. The excerpts
are objdump text for reading only and no generated file holds them.

### The field has a name

Open `fees-unit-conversion-94` (#80) lists `[state+0x2a0]` as unresolved. The bytes name it. `field-binding.tsv` has 3
serializer sites, each `movsd 0x2a0(%r15),%xmm0` followed by a call of a one-field helper (`0x27b4840`, `0x37972f0`, `0x4df8900`). Each
helper starts with `lea key,%rsi; mov $0xe,%edx`, and the 14 bytes at the key are `usdc_ntl_scale`:

```
 370c992:  movsd  0x2a0(%r15),%xmm0
 370c99b:  mov    %rsp,%rdi
 370c99e:  mov    %r14,%rsi
 370c9a1:  call   37972f0
 ...
 3797315:  lea    -0x31fe5fb(%rip),%rsi        # 598d21
 379731c:  mov    $0xe,%edx
```

Around it in all 3 serializers are `+0x2e0` `last_set_global_time` and `+0x2a8` `isolated_external`. The head of the same
record is serialized in `0x370c340`, where the key before `mov 0x50(%r15),%rdx` is `collateralToken`.

### Writer

3 copies, one rule (`writer-copies.tsv`). A loop walks the dex records at stride `0x2f0` and reads `+0x50` into `r12`:

```
 26fd9c4:  mov    $0x3b9aca00,%edi
 26fd9c9:  mov    %r12,%rsi
 26fd9cc:  mov    %r15,%rcx
 26fd9cf:  call   32814c0
 26fd9d4:  movq   %rdx,%xmm1
 ...
 26fd9f5:  divsd  -0x24f37dd(%rip),%xmm0        # 20a220 (1e9)
 26fd9fd:  cmp    %r13,%rdx                      # r13 = 0x28f5c28f5c28f5c
 26fda00:  jb     26fda20
```

With `v = rdx` and `ok = bit 0 of rax` after the call:

| ok | v | stored at `+0x2a0` |
| --- | --- | --- |
| set | `v < 0x28f5c28f5c28f5c` | `(f64)v / 1e9` |
| set | `v >= 0x28f5c28f5c28f5c` | `1.0` |
| clear | any | `1.0` |

`writer-pieces.tsv` holds this for all 2^64 values of `v`, for `rax` 0, 1, 2 and 3. `0x28f5c28f5c28f5c` is
`floor(u64::MAX / 100)`. The conversion `(f64)v` is the usual `punpckldq`/`subpd`/`addsd` chain. Its two halves are exact
doubles and the final add rounds once, so it is correctly rounded. The tool runs that chain on 2066 vectors (edges plus a
fixed generator) and compares all 64 result bits with Python's `float(v) / 1e9`, in each copy.

`evidence.json` gives the largest stored value, `184467440.73709553`, and the largest product at the gated helper,
`3.402823669209385e+25`. Both are finite, and no stored value is negative or NaN. This holds only for values from these
3 writers.

### Gate of 0x370c100

`gate-pieces.tsv`, for every u64 `x`:

```
 370c100:  movabs $0x28f5c28f5c28f5c,%rax
 370c10a:  cmp    %rax,%rsi
 370c10d:  jbe    370c113
 370c10f:  mov    %rsi,%rax
 370c112:  ret
 370c113:  cvtsi2sd %rsi,%xmm0
 370c118:  mulsd  0x2a0(%rdi),%xmm0
```

`x <= 0x28f5c28f5c28f5c` reaches the multiply with `(f64)x`, and above that `x` comes back unscaled. The bound is inclusive
here and strict in the writer. `0x370c1e0` has no gate.

### The clamp chain

`p` is the `mulsd` result. `CAP` is `0x147ae147ae147ae`, `floor(i64::MAX / 100)`. For all 2^64 bit patterns of `p`:

| `p` | `0x370c118` (floor at zero) | 5 other sites |
| --- | --- | --- |
| NaN, +inf, -inf | 0 | 0 |
| finite, `p <= -2^63` | panic | panic |
| `p > -2^63`, `trunc(p) < -CAP` | 0 | `-CAP` |
| `-CAP <= trunc(p) <= 0` | 0 | `trunc(p)` |
| `0 < trunc(p) <= CAP` | `trunc(p)` | `trunc(p)` |
| finite, `trunc(p) > CAP` | `CAP` | `CAP` |

The panic is `neg` with `jo` to Location `0x5714da0`, `core/src/num/mod.rs:320:5`, that is `i64::abs` on `i64::MIN`:

```
 370c191:  test   %rcx,%rcx
 370c194:  jns    370c19e
 370c196:  mov    %rcx,%rax
 370c199:  neg    %rax
 370c19c:  jo     370c1d2
 370c19e:  movabs $0x147ae147ae147ae,%rdx
 370c1a8:  cmp    %rdx,%rax
 370c1ab:  jbe    370c1c8
```

Infinity does not saturate. The first test treats every non-finite `p` as 0, and only finite values reach the clamp to
`[-2^63, 2^63]`. `2^63` itself then becomes `i64::MAX` through the compare with `0x43dfffffffffffff` and a `cmova`, and
ends as `CAP`.

`clamp-sites.tsv` lists the sites. The inline sites end at the join `0x3706f5f`, `0x2768a2a` and the two copies of the
second one, and their value goes on to a saturating add with a recorder at Location `l1/src/qtys/mod.rs:830:1`. That add is
outside this packet.

### How the proof works

The input is a 64-bit parameter `u`: the bit pattern of `p`, the value `v`, or `x`. The tool runs the real bytes from both
ends of a range and records every compare. Each value is either constant over the range or a monotone function of `u`, and
each compare has at most one monotone side, or the tool stops. So if a compare gives the same order at both ends, and the
same top bit, it gives that order on the whole range. A range with equal records at both ends has one path. Other ranges
are split, and the split points need no hand-picked edges. `-p`, truncation and `min`/`max` with a constant keep
monotonicity. Truncation out of range is recorded in the same way, and `neg` records whether the value is `i64::MIN`.

The six bit-pattern seeds keep sign, NaN and infinity apart, because the raw bits are monotone only within one sign.
`clamp-pieces.tsv` has 17 rows per site and each row is held to a closed form at both ends. 11496 runs in total cover all
six sites.

### Field uses

`field-uses.tsv` lists every scalar SSE load, store and `mulsd` with displacement `0x2a0` in `.text`: 46 rows, of which 25
are `mulsd`. 6 `mulsd` sites are proved here and 19 are listed unread. 3 stores are the writer, 3 loads are the
serializers, 4 more loads are listed unread, 8 rows use `rsp` and are stack slots, and 3 stores were not read. Integer moves
and whole-record copies with this displacement are not in the census.

`callers.tsv` has 6 indirect calls of the 2 helpers through slots `0x5774cd8` and `0x5774b60`, which is why a scan for
direct calls finds none, and 6 direct calls of the 3 writer copies. The callers are listed by address only.

### Negative controls

`mutation-controls.tsv` has 27 byte changes in a copy of the target, and all 27 are rejected. 22 fail by behaviour, with a
wrong piece or a wrong result, and 5 because a structural check around the site fails. Examples: `jo` removed makes
`p <= -2^63` give 0, `cmova` removed turns `2^63` into a panic, the non-finite branch removed makes `+inf` give `CAP`, and
the panic Location moved by one byte is seen. Unit tests add a wrong digest, a `.bss` address, an address outside every FDE,
an unknown instruction and a wrong floor claim.

Some first attempts survived and were retargeted, because they were equivalent changes. Finite values near `CAP` are
multiples of 16, so moving a compare bound by 1 changes nothing. Lowering the first bound changes nothing either, because
the clamp below it gives the same value. The negative bound is invisible at the floor-at-zero site, so that control runs at
`0x370c1e5`.

### Inferences

- `usdc_ntl_scale` converts an amount in the dex collateral token to USDC units. The name says so and the writer uses
  `collateralToken`. No type name or comment in the binary confirms it.
- `v = 0x32814c0(1e9, t, b)`, with `t = record +0x50`. Merged `RE-004-spot-wei-scale-family-94` gives its form:
  `d = 1` if `t == 0`, else `10^(wei_t - sz_t)`, and `floor(a * b / d)` when `a * b` fits, with a checked fallback. So on
  that path `scale = floor(1e9 * b / d) / 1e9`, which keeps 9 decimals. The tool ties the `1e9` argument, the call target and
  the default-price slot to each copy, and takes the form from that packet.
- By hand reading, `b` is a value from the B-tree at `[ctx+0x250]` keyed by token, or `0x375fb50(ctx, t)` if the key is
  missing. That helper is `10^(wei_0 - sz_t)`, which gives `scale = 10^(wei_0 - wei_t)`, and 1.0 for a token with the
  decimals of token 0.
- The chain reads like `if v.abs() > CAP { v.clamp(-CAP, CAP) }`. Only the panic shows that `abs` is in the source.

### Reference comparison

- `l1/fees/compute.rs` has this gate and this clamp as `fee_units_for_notional(notional, fee_rate)` and calls the f64
  `base_fee_rate`. The binary key is `usdc_ntl_scale`, so "fee rate" looks like the wrong label for the field. No reference
  code writes that field, and the reference has no `usdc_ntl_scale`.
- `clamp_float_to_i64` in that file has no `abs` step, so the reference gives 0 where the binary panics at `p <= -2^63`.
- The reference matches the rest of the `0x370c100` table: non-finite 0, floor at 0, and `x` unchanged above the gate.
- `ACCOUNT_NTL_CLAMP` in 3 reference files has the value of `CAP`, under a different name.

## Implementation and comparison

not yet implemented

## Results and limitations

No progress gate is requested. Metrics: 6 of 25 `mulsd` sites proved, 19 listed unread; 3 of 3 rule-based writers proved.

Limits:

- `p` is treated as a free f64, so the table covers more inputs than a site may see. `mulsd` is not modelled.
- Float operations use Python's IEEE doubles, with round-to-nearest assumed in MXCSR.
- The `(f64)v / 1e9` value is checked on vectors, and only the branches are proved for all `v`.
- The mask register at the inline sites is seeded with `i64::MAX`. The tool checks that a `movabs` of it exists earlier in
  the function. For `0x3706eb3`, `rbp` is saved and restored in between (`0x3706c45`, `0x3706cd7`), and that walk is by hand.
- `r13` at the writers is checked by a scan for plain writes in the loop, not by data flow. The call in the loop is assumed
  to preserve it, as a callee-saved register.
- The record behind `0x484e270` and `0x1459094` is not established. If `0x484e270` stores this field, stored values can come
  from another source, and the derived range does not cover them.
- Whether any caller passes a value that reaches the panic piece is not traced.
- The 19 unread `mulsd` sites have an exact address and no claimed meaning.
- A linear sweep can resynchronise after a misaligned start, so stopping on the FDE end does not prove alignment by itself.

Next question: what fills the map at `[ctx+0x250]` through slot `0x5774910` (`0x371cf40`), and what is the raw unit of `b`?
