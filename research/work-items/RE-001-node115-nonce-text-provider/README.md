# Node #115 nonce text provider and immediate caller

Task/component: **RE-001 / l1 nonce-container foundation**. This packet closes
one provider/caller gap explicitly left by [PR #1003](https://github.com/lalalune/hyperliquid-source/pull/1003)
and [the prior ordering packet](../RE-001-node115-nonce-ordering/README.md).
It qualifies the input and result contract of one concrete path; the five-body
strict-order theorem remains credited prior work.

Under the memory, allocator and normal-return premises in [PROOF.md](PROOF.md),
provider `0x1e29f50` reads a bracketed sequence of canonical unsigned decimal
integers in `0..u64::MAX`, builds a contiguous ring with head0, and passes it
to ordering body `0x2923da0`. Parse errors return raw sentinel `T=2^63`.
Duplicate or descending values instead reach the existing invariant-failure
branch. Immediate caller `0x1ddf3b0` consumes the ring as its second inner
element and distinguishes no-item, error and completed-pair results.

| Selected result | Active representation |
| --- | --- |
| Provider success | Four words C,P,H=0,N; `N<=C`, C=0 or a power of two 4..2^59 |
| Provider ordinary error | T plus error payload; remaining words inactive; selected later paths decorate it |
| Caller no next item | T at output+0x18 |
| Caller ordinary error | T+1 at output+0x18, error payload at output+0 |
| Caller completed pair | Opaque first20 bytes; C/P/H/N at +0x18/+0x20/+0x28/+0x30 |

The caller also copies four padding bytes whose initialization is not
established. Neither an original source type nor a public nonce policy is
assigned. Cleanup records describe calls and operands, not actual freeing.

## Evidence

Target: `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Research base: `d3af75257a396c85d20857f421c370ddb8cb40e5`. All addresses are
linked ELF virtual addresses; extents are half-open.

| Role | Complete FDE | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Provider | `0x1e29f50..0x1e2a28d` | 829 | 210 |
| Sequence | `0x1dbe700..0x1dbe82f` | 303 | 85 |
| Element | `0x1d772e0..0x1d77465` | 389 | 102 |
| Integer accumulator | `0x1d76380..0x1d76506` | 390 | 100 |
| Number classification | `0x1d75ea0..0x1d761e2` | 834 | 206 |
| Closing delimiter | `0x1d77cf0..0x1d77df0` | 256 | 70 |
| Growth wrapper | `0x4560af0..0x4560b7a` | 138 | 44 |
| Capacity reserve | `0x43bbcd0..0x43bbd34` | 100 | 27 |
| Allocation adapter | `0x43bd550..0x43bd639` | 233 | 74 |
| Prior ordering context | `0x2923da0..0x2923ee1` | 321 | 92 |
| Immediate caller | `0x1ddf3b0..0x1ddf7bf` | 1,039 | 236 |
| Error decoration | `0x2cf8390..0x2cf83e5` | 85 | 27 |
| **Total** | **12 FDEs** | **4,917** | **1,273** |

`observed/` contains full readable GNU exports, deterministic gzip LLVM
exports, 362 structural basic blocks, all315 control transfers, RIP-reference
inventory, original FDE/CIE bytes and all23 LSDA call-site rows. Both native
providers cover every selected byte and agree on instruction partitions.
`spec.json` holds 75 selected byte obligations, 17 required symbol-zero
RELATIVE bindings and three source-context literal records. Complete native
coverage binds instructions outside those selected obligations.

The 321-byte ordering body and its source Location are dependency context;
they are not newly recovered or an added compiled-byte match. The other
provider instantiations, first-field decoder, error factories and allocator
implementations remain outside the semantic scope. `scope-check.json` and
`dependencies.json` record the public overlap audit and credited inputs.

## Reproduce

From the repository root, with the pinned capture materialized:

```sh
python3 -B research/work-items/RE-001-node115-nonce-text-provider/verify.py
python3 -B -O research/work-items/RE-001-node115-nonce-text-provider/verify.py
python3 -B research/work-items/RE-001-node115-nonce-text-provider/collect.py --out /tmp/nonce-provider-fresh
gzip -dc research/work-items/RE-001-node115-nonce-text-provider/observed/number-classification.llvm.txt.gz
```

Use a fresh output path. Both scripts accept `--gnu` and `--llvm` paths; their
defaults name the installed macOS GNU and Apple tools. Exact export text
reproduction is qualified to the recorded native versions. Different native
formatting is not normalized into a claimed raw-equal export. The ELF/FDE
parsers are the repository's existing stdlib tools, with hashes recorded.
No third-party Python package, compiler or target execution is required.

The collector authenticates the full input before native invocation/output,
then both decoders read the same private read-only byte snapshot. Full
snapshot hashes are checked before and after. The verifier checks both raw
and compressed export hashes, decompresses LLVM, compares exact bytes and
partitions, and regenerates the complete `observed/` tree twice.

The final receipt records 168 rejection controls, including75 individual
anchor-clause controls (some spans overlap), 51 relocation kind/symbol/addend
controls, literal/FDE/index/LSDA controls, and15 real operative mutations
decoded again by both native tools. Operative controls first observe the
changed field, then reject below the full-input digest gate. A mutation
outside selected anchors intentionally passes that subset but fails complete
native-byte comparison. These checks bind a manual proof; they do not run
the target or establish semantic equivalence by sampled instruction execution.

## Limits

The proof requires valid disjoint memory, preserved parser mode/depth/live
locals, ABI-conforming normal returns and valid prefix-preserving allocator
results. Opaque error factories must return nonzero valid error objects;
otherwise the closer can forward zero and admit an invalid delimiter.
The opaque first-field decoder must preserve mode/depth and live outer locals
outside its designated effects. Nonzero pointers alone do not establish
storage validity. The grammar
is a selected prefix contract, not full document or endpoint admission.
Depth0/1, negative spellings including `-0`, fraction/exponent/overflow tags,
allocation failure and invariant failure are distinguished in the proof.
Unwind tables are structural evidence, not executed exception semantics.

No captured executable, instruction evaluator, transaction, signing, chain
API or live nonce action was run. No source implementation or component gate
is added. Public nonce windows/anti-replay policy, whole-program reachability,
original source/ABI identity, transitive ownership and hosted CI remain
unqualified. The unrestricted captured-execution test suite is outside this
static-only packet.
