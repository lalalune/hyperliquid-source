# RE-007: selected isolated leverage decrease

## Recovered decision

This extends the existing `node94-margin-risk` component with
`check_custom_isolated_decrease`. For the qualified same-table custom isolated
position, the native caller clones a one-entry positions leaf, preserves its
mode, signed size and margin, replaces leverage with the requested value, and
tests the resulting margin using the same price as the position cap. A strictly
negative surplus refuses with initialized tag `0x47`; zero reaches the cleanup
edge to `0x3709cfa`, named `EnterCommit`. That edge is not action success.

The new Rust function is a scalar decision projection. It does not implement
the native clone, allocator, destructor, status layout or complete action.
Existing public APIs and their implementations are unchanged.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Baseline: draft #1460 head `1e78e5ac1e1e7b6a2812a413f03e97cfe8c45470`.
Coordinates are ELF virtual addresses. No captured execution or instruction
interpreter was used; no financial action was performed.

## Native closure and conditions

[The reviewed native proof](pre-source/NATIVE.md) and
[frozen identities](pre-source/NATIVE-FREEZE.json) retain ten complete
FDE/CIE/LSDA/index identities, 8,450 body bytes and 1,856 identical GNU/LLVM
instruction partitions. The selected new closure is the one-leaf clone,
matching-row binding and decrease cleanup branch. Caller, position calculation
and surplus work are credited existing RE-004/RE-007 evidence, not ten newly
reconstructed functions.

Key native edges:

| Site | Observed relation |
| --- | --- |
| `0x370a09e`, `0x33eb877`, `0x33ebab9` | Clone positions; height zero chooses the selected leaf allocation path. |
| `0x33ebb18..0x33ebb87` | Preserve all 64 value bytes through four 16-byte copies. |
| `0x33bd525`, `0x370a21a..0x370a221` | Found cursor returns the selected clone; caller replaces only consumed table/leverage fields. |
| `0x370a228`, `0x370a25c`, `0x370a27a` | Same table skips mode 2; a strict decrease invokes mode 1. |
| `0x37d7908..0x37d7947` | Same asset price; isolated output uses `margin_after` and `computed_requirement`. |
| `0x370a280..0x370a28f` | Negative test; otherwise normal cleanup precedes `EnterCommit`. |
| `0x370a2eb..0x370a300` | Original cross=false yields tag `0x47`, then cleanup. |

The selected domain requires a resolved custom id at least 50, matching existing
position table, validated nonempty `MarginTable`, canonical mode DWORD 1,
cross=false, active position, positive requested u32 strictly below old u32,
valid prior metadata/price indices, positions tree height zero with one matching
key, and an empty companion tree. Price is a nonnegative signed i64; signed
price-times-size and the unsigned requirement's conversion to i64 must fit.
Price/size/margin remain raw integer words; no economic denomination is assigned.

Provider behavior is conditional. Ordinary return alone does not preserve
pending status or saved values. The precise reviewed hypotheses require
preserving every subsequently read source/table/metadata/price/status/saved
word, ABI callee-saved registers and control machinery. Each callee's own live
frame/control region must avoid external live objects. Explicit ancestor-frame
output slots remain allowed. Fresh allocated leaf Q is disjoint from other live
objects; only declared Q writes, later free(Q), designated outputs and disjoint
provider-private effects are permitted. Actual allocator/free/recorder behavior,
generic tree ownership and unwind behavior are not established.

## Independent numerical relation

The same table supplies the first-tier maximum and `position_leverage_cap`.
Request greater than the maximum refuses tag `0x43`; greater than the cap
refuses tag `0x50` with initialized u32 cap detail. These checks precede shadow
arithmetic. Native padding and other unknown output bytes are not modeled.

For passing prefix checks, let N be the checked signed price-times-size product.
The shadow uses the new divisor, original signed size and original margin:

```text
margin_after = signed_saturating_add(original_margin, N)
requirement = unsigned_abs(N) / requested_leverage
surplus = signed_saturating_sub(margin_after, signed(requirement))
surplus < 0 -> tag0x47; otherwise -> EnterCommit
```

Rust reuses `calculate_position_margin` with raw mode 1 and then the numeric
`assess_isolated_liquidation` relation. Its reused name does not turn this
caller into a liquidation action. `effective_margin` is not the consumed field.
Safe API errors for excluded inputs are chosen policy, not native refusals.

## Frozen expectations and actual compilation

The reviewed [pre-Rust semantic freeze](pre-source/PRE-RUST-FREEZE.json)
`602c9b09…49fb0` predates new Rust. Its 341 unique conditional cases contain
136 EnterCommit, 61 tag43, 48 tag50 and 96 tag47 decisions. Nine excluded-domain
examples are separately classified as safe API errors, with no native tag claim.
[Wire packaging](preparation/WIRE-FREEZE.json) was performed afterward and
explicitly preserves the original logical expected values; it is not represented
as a pre-source wire freeze.

An input-only client receives scalar fields and validated tiers, never expected
answers or an injected maximum/cap/surplus. Each of four independently compiled
clients (optimization 0 and 3, twice each) emits all 4,092 qualified output bytes
and, separately, 108 policy bytes matching external expectations. Eight operative
source controls are compiled at optimization 3 only and run only the qualified cases:

| Wrong relation | Changed decisions | Changed commit/refusal |
| --- | ---: | ---: |
| Old divisor in shadow | 30 | 30 |
| Tiered-initial instead of mode 1 | 31 | 31 |
| Absolute size in shadow | 25 | 25 |
| Reject zero surplus | 49 | 49 |
| Zero margin in shadow | 109 | 109 |
| Zero price in shadow | 49 | 49 |
| Skip position cap | 48 | 24 |
| Refusal tag46 instead of47 | 96 | 0 |

Seven controls change a commit/refusal branch; the eighth is a refusal-tag
control. Three exit-2 malformed-frame controls are separate client policy.
None is native execution. Two additional native-byte corruption controls are
identity checks against the authenticated target, not semantic CFG execution.

The approved Rust 1.94.1 toolchain compiled the combined component with 52 Cargo
tests passing per debug/release profile. All 48 commands and 96 raw channels are
retained. Baseline compiler diagnostics are empty; the deliberately zero-price
mutant has a retained 476-byte unused-variable warning. There was no
`-D warnings` claim. Invocation-local debug=0, strip=symbols and incremental=0
controls bounded disk use; no manifest/global compiler settings changed.
The 300 MiB floor was preserved (minimum recorded 376,893,440 bytes free).

## Immutable receipt and replay

[The archive](compiled.json.gz.b64) retains the original executed source/input
snapshot and actual command streams. Decoding is strict base64 then one gzip
member. [RESULTS.json](RESULTS.json) records full hashes. The source freeze has
43 conservative files, including all 25 current component files and external
`boundaries.tsv`. [Actual Cargo dependency records](COMPILER-READS.json) retain
20 raw `.d` texts; both profiles name the same 23 frozen project input files.
Compiler executable hashes are retained; exhaustive sysroot and system-library
closure remains unproved.

The build ran from ignored work before durable packaging.
[SOURCE-PATHS.json](SOURCE-PATHS.json) explicitly maps each historical receipt
path to a byte-identical durable payload or unchanged current component file.
The original builder is retained unchanged in `preparation/verify.py`; it is
historical executed evidence. [observed.py](observed.py) separately verifies the
entire frozen snapshot, current component, all operative mutant manifests,
actual complete output streams, exact command roles/exits and per-profile
project-source closure. No compiler rerun is needed for receipt replay fixes.

```sh
python3 research/work-items/RE-007-isolated-decrease-rust-94/native.py
python3 research/work-items/RE-007-isolated-decrease-rust-94/observed.py
python3 -m unittest discover -s tests -p test_isolated_decrease_rust94.py
```

## Credit, historical boundary and remaining work

Credits: [RE-004 update-leverage caller](../RE-004-update-leverage-path-94/README.md),
the existing position/surplus reconstruction, and #1460's same-table cap/increase
work. Original pre-review freezes and the precise premise overlay remain in
`pre-source/review-original`; numeric payloads were not refreshed.

Historical selector/hash/tier-cap/increase source and output archives remain
unchanged. Among existing component source files, only the shared export file
changes; the new module and its test are added. Old
manifest export lines remain current support-file integrity pins. The original
increase archive retains compiled lib SHA `ffb0ba0d…820908` and 48 tests/profile.
[Its boundary note](../RE-007-custom-leverage-increase-rust-94/SNAPSHOT-HISTORY.md)
preserves the initial strict-current failure and explains the minimal historical
test correction. This new receipt describes the expanded 25-file, 52-test tree.

External registry/user/row/price admission, provider preservation in the actual
runtime, generic clone/drop paths, other modes/table changes and postcommit
effects remain open. There are zero actual-chain admission vectors and no full
leverage-action, native ABI, compiled-byte equivalence or component-gate claim.
