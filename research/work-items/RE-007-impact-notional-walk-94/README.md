# RE-007: node #94 impact-notional walk

The existing funding-premium packet takes `0x3c027d0`'s result as a stubbed
input. This packet qualifies that missing integer relation: tree entry and slab
quantity selection, whole-level product limits, a floored terminal quantity,
and the returned average. It then binds the result to the existing premium
caller's zero sentinel. It serves the approved bounded RE-007 risk/funding
reconstruction scope; no component gate changes.

Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Research base: `d3af75257a396c85d20857f421c370ddb8cb40e5`. Coordinates below
are linked ELF virtual addresses with exclusive ends.

| Complete FDE | Role | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x3c027d0..0x3c02db8` | New impact walk | 1,512 | 364 |
| `0x3750ce0..0x37511c0` | Credited premium caller context | 1,248 | 291 |
| Total | 135 structural blocks, 109 transfers, 15 calls | 2,760 | 655 |

## Result

Under readable stable well-formed tree/slab storage, terminating slot chains,
a stable positive target `T`, and the documented ordinary-return/noninterference
premises for opaque helpers, the walk visits entries in tree order. Each price
is the unsigned magnitude of its signed64 key. It saturates the sum of raw
quantity words in that level's slab chain.

The whole `price * quantity` must fit `0..2^63-2` **before** partial-fill
arithmetic. Levels below the target are accumulated. At the first crossing,
the terminal quantity is `floor((T - prior_cost) / price)`. The final result
is a floored integer average, returned only when total quantity is nonzero
and no greater than completed cost; otherwise the result is zero.

For example, the integer proof gives zero for one level `(price=7,quantity=2)`
and target6, and gives3 for levels `(3,2),(7,2)` and target10. These are
algebraic deductions from the instructions, not observed target executions.
The caller invokes both book offsets `+0x80` and `+0x98` before checking
either result. Either zero writes only output+8=0, the existing missing-premium
sentinel; output+0 and +16 remain inactive/unestablished on that path.

[PROOF.md](PROOF.md) gives the cursor/chain induction, saturation and division
lemmas, exact call/offset tables, and the separate zero-target domain. For
positive `T`, invariant `prior_cost<T` proves a zero price cannot reach the
partial division. For `T=0`, a positive-quantity zero-price first admitted
level reaches a zero divisor. This is a raw excluded domain, with no live
admission, endpoint reachability or vulnerability claim.

## Reuse and limits

The [prior premium/rate packet](../RE-007-funding-premium-rate-94/README.md)
([PR #860](https://github.com/lalalune/hyperliquid-source/pull/860)) owns the
floating formulas, target-map context and caller sentinel. Its explicit impact
stub is the new gap closed here. The
[top-order-clone packet](../RE-006-top-order-clone-94/README.md)
([#171](https://github.com/lalalune/hyperliquid-source/pull/171)) supplies tree
and slab layout context; this walk's tag test is independently read as **32-bit**.

The [configuration writer](../RE-004-funding-config-writers-94/README.md),
[bucket gate](../RE-001-funding-bucket-advance-94/README.md) and
[distribution/reset](../RE-007-distribute-funding-94/README.md)
([#899](https://github.com/lalalune/hyperliquid-source/pull/899)) remain separate
credited work. Their captured instruction evaluators were not run or imported.
No unlicensed inferred implementation was used. The local collector shares
only the existing pure ELF/FDE parsers; it has no unmerged-packet dependency.

The full bodies are decoded, but no complete caller hash-map or floating-point
semantic recovery is newly claimed. Helpers for diagnostics, failures and hash
lookup have bound identities/extents and explicit behavior assumptions.
Actual unwinding, malformed-memory behavior, tree construction, cyclic chains,
source types, public units, side labels, sample storage, rate application,
historical compiler identity and live funding behavior remain unresolved.
There is no Rust implementation, captured execution or instruction emulator.

## Evidence and reproduction

`observed/impact.gnu.txt` is the complete readable primary export;
`observed/premium_context.gnu.txt` retains the complete caller. The second
provider is losslessly compressed. To read it:

```sh
gzip -dc research/work-items/RE-007-impact-notional-walk-94/observed/impact.llvm.txt.gz
```

The packet's `.gitattributes` stores these small gzip files as real repository
bytes instead of LFS pointers. `records.json` retains raw and compressed hashes;
the verifier decompresses and compares every byte and instruction partition.
Both native tools read one private authenticated snapshot whose complete digest
is checked before and after export. Nearest-symbol annotations are not names
assigned to these functions.

From the repository root, with Python3, GNU objdump and LLVM objdump installed:

```sh
python3 -B research/work-items/RE-007-impact-notional-walk-94/verify.py
python3 -O -B research/work-items/RE-007-impact-notional-walk-94/verify.py
python3 -B research/work-items/RE-007-impact-notional-walk-94/collect.py --out /tmp/impact-review-new
```

The output directory must not exist. The native defaults are
`/opt/homebrew/opt/binutils/bin/objdump` and `/usr/bin/objdump`; override with
`--gnu` and `--llvm`. Retained text is tied to the recorded provider versions,
so another version can produce different formatting even with equal bytes.
`dependencies.json` pins the two shared parsers and credited READMEs.

`spec.json` contains 43 selected instruction obligations, 11 literal spans and
13 symbol-zero RELATIVE bindings. `observed/cfg.tsv` retains every structural
block; `-` denotes no structural successor. Calls have conditional normal-return
edges. `transfers.tsv` and `rip-references.tsv` are complete for the two bodies.
The impact's three LSDA call-site rows remain separate from the normal graph.
`verification.json` and `VALIDATION.json` record the exact validation and limits.
The author verification includes independent PT_LOAD mapping, below-digest
controls, 17 operative mutations freshly decoded by both native tools, and two
full regenerations. These checks bind the evidence; the semantic argument is
the manual proof and its review, not a count of tests.

The next independent question is how `0x251c420`'s raw result records reach
the actual funding-sample append path. This packet does not infer that storage
behavior from the caller's vector construction or from the bucket-gate label.
