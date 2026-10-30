# RE-007: margin tiers to maintenance shortfall admission, node #94

- Component: clearinghouses and risk
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Upstream base: `1f8c67c63ca4794c9689235471c60297f8a5c985`
- Reference-lead pin: `references/can1357-hl` at
  `999556f6e0a474b8312db96ec3149e1c44e97c23` (comparison lead only)
- Claim: static observation for the instructions, FDEs, relocations, source
  `Location` records, widths, formulas, mode-3 call chain, and negative-surplus
  admission branch; inference where explicitly identified below
- Captured binary executed: no

This packet closes one bounded transition: a validated margin-tier record feeds
the mode-3 maintenance requirement, which feeds cross or isolated signed
surplus, and a concrete caller admits a liquidation candidate only when that
surplus is negative. It does not reconstruct the full risk engine or establish
the decimal scale of the raw quantities.

## Reproduce

Run from the repository root. The analyzer reads ELF bytes, FDEs, RELA entries,
source records, and fixed instruction windows. It never loads or executes the
captured program.

```text
python3 tools/artifacts.py verify
python3 tools/margin_path_static.py
python3 -m unittest discover -s tests -p 'test_margin_path_static.py' -v
(cd research/work-items/RE-007-margin-path-94 && shasum -a 256 -c MANIFEST.sha256)
```

The retained run used the versions in `tool-versions.txt`. The analyzer itself
uses only Python's standard library and the repository's ELF/FDE readers; GNU
`objdump` was used for independent human-readable inspection, not to generate
the deterministic outputs.

Outputs:

- `evidence.json`: authenticated scope, formulas, counts, and limitations;
- `functions.tsv`: eight exact FDE extents;
- `dependencies.tsv`: 19 checked direct/GOT call edges and helper targets;
- `locations.tsv`: seven relocated first-party source records;
- `instruction-bytes.txt`: 30 address-bound raw instruction controls;
- `boundaries.tsv`: 24 deterministic admission, arithmetic, and eligibility
  cases.

## Anchors and dependency map

All coordinates are ELF virtual addresses. An FDE extent is an unwind-described
range, not proof of a source-level function boundary.

| Observed role | FDE extent | Bytes |
| --- | --- | ---: |
| tier lookup | `0x33331a0..0x3333276` | 214 |
| maintenance requirement | `0x3333670..0x33337f9` | 393 |
| initial requirement | `0x3333800..0x3333915` | 277 |
| tier admission/construction | `0x3335590..0x3335c40` | 1,712 |
| position margin by raw mode | `0x3717480..0x37179c5` | 1,349 |
| candidate collection | `0x37d7360..0x37d77d8` | 1,144 |
| single-or-cross surplus | `0x37d77e0..0x37d79e0` | 512 |
| aggregate margin | `0x37d79e0..0x37d7f0c` | 1,324 |

The concrete maintenance path is:

```text
0x36fff7e: ecx = 3
0x36fff8b: call 0x37d7360                 candidate collection
                 |-- 0x37d73b7 -> 0x37d79e0  cross aggregate
                 |                         -> 0x3717480
                 `-- 0x37d76b9 -> 0x37d77e0  isolated surplus
                                           -> 0x3717480
0x37177e1 -> GOT 0x57759a0 -> 0x3333670   tiered maintenance
0x33336ac -> 0x2fe1670                    tier-tree range lookup
```

Every indirect arrow above is backed by an `R_X86_64_RELATIVE` target and a
decoded `ff 15 disp32` call. `dependencies.tsv` also pins the initial-margin
edge, tier-tree construction helper `0x3398f50`, arithmetic recorder
`0x358dcd0`, and candidate-vector growth helper `0x32d5860`. The helper bodies
are not assigned stronger semantics than their observed inputs, outputs, and
call positions.

Source-path evidence is attribution, not original source. Relevant records are:

- `0x56e9b40`: `l1/src/clearinghouse/margin_table.rs:107:105`, used by all
  three tier lookup/formula extents on the missing-tier panic path;
- `0x56e9b70`: `l1/src/qtys/impl_ntl.rs:26:1`, supplied to the unsigned
  saturation recorder;
- `0x56f1fa8`: `l1/src/clearinghouse/position.rs:204:57`, supplied when the
  signed price-size multiply rejects a negative price or overflows;
- `0x56f3a48`: `l1/src/clearinghouse/user_state.rs:87:60`, on the
  single-position cross/isolated assertion path.

## Tier admission and stored arithmetic

The check order at `0x3335590` is observable:

1. description byte length must be below 251, so the admitted maximum is 250;
2. tier count must be below 4 and nonzero, so it is 1 through 3;
3. the first lower bound must be below `0x0ccccccccccccccc`, then equal zero;
4. each leverage is an unsigned byte and must be at most 50;
5. the second lower bound is prechecked at most
   `1_000_000_000_000_000` and below the wire limit;
6. current leverage must be strictly smaller than previous leverage;
7. after the current prior-contribution arithmetic, the next lower bound (when
   present) is prechecked before the current lower bound is required to be
   strictly larger than the previous lower bound.

The literal errors at `0x58b826`, `0x58b84f`, `0x58b86c`, `0x58b892`, and
`0x5b66d3` agree with those branch predicates. They are corroboration rather
than the basis for the inequalities.

For a later tier at lower bound `B`, previous leverage `Lp`, and current
leverage `Lc`, the stored unsigned 64-bit prior contribution becomes:

```text
prior = sat_sub(sat_add(prior, floor(B / (2*Lc))), floor(B / (2*Lp)))
```

The two `div` instructions use unsigned 32- or 64-bit forms selected from the
dividend high word. Addition and subtraction call the recorder before using
`u64::MAX` or zero respectively.

There is no visible `leverage != 0` check in this routine. A single tier with
leverage zero reaches its success construction branch; a later zero leverage
reaches a zero divisor while computing the prior contribution. The requirement
helpers likewise divide by a value derived directly from the stored byte. This
packet records that gap and does not infer an earlier decoder constraint.
This ordering is also why the tests treat zero-divisor reachability as distinct
from an ordinary returned validation error.

## Exact requirement formulas

Tier selection returns the last record whose unsigned lower bound is no greater
than unsigned `notional`. Both formulas are unsigned 64-bit integer arithmetic.

Initial, entry `0x3333800`:

```text
floor(notional / (2 * leverage)).saturating_sub(prior_contribution)
```

Maintenance, entry `0x3333670`:

```text
numerator = sat_sub(
    sat_mul(notional, 2),
    sat_mul(prior_contribution, 4 * leverage),
)
floor(numerator / (6 * leverage))
```

`0x3333733` tests the high bit before doubling and saturates to `u64::MAX`.
The `mul` at `0x3333747` tests its high half and also saturates to `u64::MAX`.
The subsequent unsigned subtraction saturates to zero. Division floors; no
round-up instruction follows it.

The boundary fixture `(0,50), (1000,20), (1000000,10)` produces stored priors
`0`, `15`, and `25015`. At the final tier, maintenance for both `2^63` and
`u64::MAX` is `307445734561809183` because the doubled numerator has already
saturated. These and the exact boundary transitions are retained in
`boundaries.tsv`.

## Widths, modes, and cross/isolated behavior

At `0x3717480`, price is a signed 64-bit argument and is rejected if negative.
Position size is loaded as signed 64-bit from record offset `+0x10`. `imul` plus
`jo` checks their signed product. The code then uses `neg; cmovs` to obtain an
unsigned absolute notional; `i64::MIN` therefore becomes `2^63`, not an error.

The five-entry byte-indexed mode table is:

| Raw mode | Destination | Observed requirement branch |
| ---: | --- | --- |
| 0 | `0x3717888` | zero |
| 1 | `0x37174cb` | notional divided by record `u32` at `+0x04` |
| 2 | `0x371751f` | tiered initial formula |
| 3 | `0x37175b6` | tiered maintenance formula |
| 4 | `0x37174f0` | notional divided by the smaller of `+0x04` and a `u8` cap |

Modes 1 and 4 also have no visible zero-divisor normalization. Modes 2 and 3
use the `u32` selector at record offset `+0x38`: values below 50 construct a
single-tier table, while values at least 50 follow the custom-table lookup.

The byte at record offset zero selects the observed accounting branch:

- zero (cross): the output carries signed notional, the computed requirement as
  effective margin, and unsigned absolute notional;
- nonzero (isolated): signed position notional is saturating-added to the signed
  margin at `+0x08`; effective margin is `max(result, 0)`, and the output also
  carries previous margin and the computed requirement.

The fixed-point decimal exponents are not encoded in these operations. This
packet proves the raw widths and the absence of a scale conversion inside the
bounded path, not how many decimal places price, size, or notional represent.

## Liquidation eligibility and state effects

The caller at `0x36fff7e` supplies raw mode 3. Candidate collection has two
negative-only branches:

- cross: aggregate signed equity minus aggregate unsigned requirement is
  checked/saturated as signed 64-bit; `test; jns` skips zero and positive values;
- isolated: the single-position helper subtracts computed requirement from
  signed margin-after, then the collector again uses `test; jns`.

Thus the proved admission predicate is exactly `signed_surplus < 0`; zero is
ineligible. The candidate collector appends a 48-byte result record after its
growth helper succeeds. No instruction in the bounded call chain writes back to
the 64-byte position record, so no position mutation is claimed.

The concrete caller continues into liquidation selection/execution code, but
that continuation and its mutations are outside this packet.

## Validation and mutation controls

Seventeen focused tests pass. They cover:

- target hash, FDEs, source records, jump destinations, call slots and targets;
- all tier limits, error precedence, tier boundaries and zero leverage;
- signed `i64` price-size extremes, unsigned `u64` saturation, cross and
  isolated maintenance summaries, and negative/zero/positive surplus;
- byte-identical packet regeneration;
- adversarial changes to every one of the 30 instruction controls, a GOT
  relocation, an FDE range, the target digest, and both formula models.

The models are not independent proof of target behavior. Their admission is
conditional on all address-bound instruction and relocation checks passing;
mutated inputs fail closed.

The complete repository checks and their exit statuses are in
`required-checks.log`. `make doctor` is retained as an environment diagnostic:
the static checks pass, while exact rebuild readiness remains false because the
repository still lacks accepted recovered manifests/comparator inputs and this
host lacks the pinned Rust 1.95/Ghidra environment. No captured binary was
executed.

## Reference-lead comparison and limitations

Only after deriving the instruction behavior, the pinned `can1357-hl` lead was
compared. Its margin formulas and candidate naming are consistent with most of
the observations. It is not treated as proof. In particular, its apparent
source-level zero-leverage normalization is not present in the proved helper
instructions, so this packet does not copy that behavior.

No Rust component is added. Although the bounded arithmetic is strong enough
for a small model, the surrounding owned layouts, decimal scales, tier-tree
type, public errors, recorder semantics, and liquidation mutations are not
closed sufficiently for a production reconstruction.

Remaining unknowns:

- exact decimal exponents and unit conversions outside this call chain;
- the complete tier-tree type and all missing-table/error provenance;
- whether an earlier wire decoder excludes zero leverage;
- recorder side effects beyond the returned saturation behavior;
- candidate ordering, liquidation sizing, transfers, and persistent mutation;
- exhaustive callers, cold fragments, and node #115 drift.

No completion gate changes are requested. The best next action is to anchor the
raw price/size exponents at their serialization and oracle-conversion boundaries,
then follow one admitted candidate into the first persistent liquidation state
change.
