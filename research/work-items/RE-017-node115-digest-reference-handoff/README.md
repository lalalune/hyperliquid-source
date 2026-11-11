# Node115 selected digest → replay reference handoff

This is a scoped contribution to [#3923](https://github.com/lalalune/hyperliquid-source/issues/3923), not closure of replay, state roots, or expected-root authentication. It recovers the selected timer-callback path from the digest tracker to the replay comparator and supplies an independently written Rust logical projection.

**Finding:** the comparator's incoming `(height, digest)` is preserved from a selected tracker entry through a registry remap, a queue drain, and the second vector returned by finalization. Its local comparison operand is a separate history lookup at context `+0x400`. The `abci_digest_quorum` descriptor at context `+0x280` is a sink on this path, not the source of the incoming bytes. Registry membership is re-resolved before the selected callback queues its row; the drain excludes rows with an empty first collection. None of these observations establishes a quorum threshold or substitutes for signature verification.

## Target and evidence

- Original `artifacts/node/115/hl-node`, 105,896,032 bytes.
- SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Static x86-64 inspection with Capstone 5.0.7. No target execution, emulation, signing, network participation, or captured code linked into the Rust crate.
- `records.json` retains 19 instruction-boundary windows, their enclosing FDEs and hashes, 12,587 bytes / 2,841 instructions, 2,853 checks, and 33 deliberate corruptions.
- `verification.json` records reproduction against the original target. Corruptions are checked after authenticating the original binary, with global/window digest checks bypassed for those controls, so their rejection exercises the recorded instruction/relocation checks.
- The static verifier proves the retained facts are present in the artifact. Dataflow interpretation and the logical abstraction are separately reviewable below; this is not a runtime equivalence result.

## Producer-to-consumer join

All offsets below belong to the named owner; equal-looking offsets in distinct objects are not treated as identities. Valid logical collections, normal returns from the named helpers, successful allocation, and absence of hidden alias mutation are premises.

| Stage | Native evidence | Recovered identity / condition |
| --- | --- | --- |
| Finalization owner | `0x54897fb`, `0x548bf2d..0x548bf4b` | Dereference caller's state pointer; drain tracker at state `+0x3e50` through `0x5afa030`. Current time comes from state `+0x60`; registry owner is state `+0x3f08`. |
| Selected timer callback | `0x5afa044..0x5afa0a0`, `0x4de0786`, `0x51525a8..0x51525bb` | Drain invokes pending-map processing with tracker, ready-vector `+0x48`, registry and time context. The selected tree route invokes `0x51520f0`, which calls `0x5377df0` with the tracker and pending entry's exact height key. Timer eligibility is not implemented here. |
| Selected digest lookup | `0x5377e19..0x5377ef9`, `0x5377f69`, `0x5378001`, `0x537819d..0x53781ac` | Exact height lookup in tracker `+0x18`; selector byte at height-value `+0x20` must be zero; selected digest is the following 32 bytes. Exact lookup of that digest in the candidate map returns two collection descriptors plus the same digest. Absent height, unset selector, or absent selected candidate returns None. |
| Registry remap | `0x5152650..0x5152716`, `0x5b7a9a0..0x5b7aa3d` and repeated loop arms | First collection has 32-byte keys and opaque 72-byte values. Resolve each key through slot `0x64e5068 → 0x36ca940`, with registry context from owner `+0x58`; only native result `0x1a2` survives. Output keys are 20-byte addresses; opaque values are retained by the native mapping. |
| Exact registry lookup | `0x36ca95a..0x36cab71` | Exact context u64 lookup, then exact 32-byte key lookup. Missing context: `0x9b`; missing key: `0x98`; success: `0x1a2`, with address at selected value `+0x20..+0x33`. This is a state lookup, not cryptographic recovery. |
| Collection materialization | `0x4dc0330..0x4dc041a`, `0x5b2d7c0..0x5b2d9b3` | Address-keyed collection construction removes equal 20-byte keys. The model preserves only the unordered membership set and emptiness, not sort stability, physical representation, or which duplicate signature value wins. |
| Queue record | `0x515271b..0x51527e5` | Callback prepends the same pending height to remapped first collection, unchanged second collection and unchanged digest. Appended row is `0x68` bytes: height `+0`, first collection `+8..+0x27`, second `+0x28..+0x47`, digest `+0x48..+0x67`. Even an empty first collection is queued here. |
| Drain filter | `0x5afa0a5..0x5afa1a5` | After callback processing, move tracker vector `+0x48/+0x50/+0x58` out and reset it. Stable compaction retains rows whose qword `+0x20` is nonzero: the first collection's logical length. A nonempty second collection does not satisfy this predicate. |
| Finalization output | `0x548bf35`, `0x548c033..0x548c04a`, `0x548c20c..0x548c239` | Drained vector at local `rsp+0x130` becomes result descriptor `+0x30/+0x38/+0x40`. |
| Replay consumer | `0x5a055a0..0x5a055b0`, `0x5a05ca1`, `0x5a05cc8..0x5a05e3c` | Caller result begins `rsp+0x160`, so second-vector data pointer is `rsp+0x198`. Same `0x68` rows, same height `+0`, same digest `+0x48`. Local history is context `+0x400`, searched at the exact row key. |
| Sink-before-comparison ordering | `0x5a05c14..0x5a05c6a`, `0x5a05ca1..0x5a05d35` | **The entire batch** is written to sink `+0x280` before comparison starts. Then replay reloads the batch start. An early mismatch can prevent later comparisons even though those rows have already reached the sink. |
| Comparison | `0x5a05d07..0x5a05d35`, `0x5a05df6..0x5a05e0b` | Missing exact local key skips; all 32 equal bytes advance; differing bytes enter `0x5a060ec` diagnostic. No current-height equality check is inferred. The model stops its observation prefix at that diagnostic and does not model diagnostic I/O or process outcome. |

Wrapped-container exact lookups `0x57f7210`, `0x57f93d0`, `0x4551810`, `0x4559a60` and `0x57f8bb0` are retained alongside inline tree paths. Their native physical layouts are not copied into the owned maps.

## Owned implementation and independently checked expectations

`src/node115-digest-reference-handoff` is a dependency-free `no_std + alloc` crate. It owns logical maps, a selected-digest extraction operation, registry resolution, queue draining, and a replay handoff observation. Inputs are already-populated tracker and registry state, not caller-supplied authorization booleans. The source does not return `authenticated`, invent votes, or accept a fake quorum result.

`extract_selected` is only the selected callback body, invoked for a caller-supplied eligible height. `drain_ready` begins after native timer processing. Composing these operations represents a selected path, not the complete native timer/drain routine. Signature payloads and the second collection are deliberately absent from the projection because they do not determine the modeled digest/key identity or first-collection emptiness. `members` is a set observation, not a vote count or threshold decision.

The 15 Rust tests contain literal, hand-derived expectations from the native branches above. They were independently checked against the target disassembly; they are synthetic contract tests, not captured native traces:

| Control | Expected observation |
| --- | --- |
| Existing height, selected candidate, resolvable member, equal local root | Same height/digest survives extraction, remap, drain and comparison. |
| Absent height / unset selector / selected digest absent from candidates | No row is appended; another available candidate is not substituted. |
| Different selected candidate also exists | Selected candidate's bytes are used exactly. |
| Missing current registry context, including a present different context | Selected row is appended empty, then dropped by drain. |
| Missing exact member ID, with each of all 32 ID bytes changed separately | Member is excluded; no prefix-only identity match. |
| Some members resolve; others do not | Surviving keys become their resolved 20-byte addresses, including distinct final address bytes. |
| Different member IDs resolve to one address | Membership projection contains that address once; no threshold inference. |
| Selected candidate's first collection is empty | Callback queues empty row; drain removes it. |
| Empty rows interspersed with nonempty rows, unsorted heights | Stable retained order; queue emptied, including when every row is filtered. |
| Missing local reference followed by an equal one | Missing entry is skipped and comparison continues. |
| Older exact history key vs different absent key | Exact existing key compares; absent key skips. No invented current-height requirement. |
| Each of 32 digest bytes changed independently | Mismatch diagnostic boundary reached; subsequent comparisons omitted. |
| Same selected callback invoked twice | Two rows can be queued; extraction does not invent timer deduplication or mutate the height map. |
| Heights zero and u64 maximum | Exact lookup and preservation, without inferred height arithmetic. These synthetic states do not claim ingress reachability. |
| First comparison mismatches, later row remains | All sink pairs are recorded first; only the first comparison is observed. |

## Trust boundary and remaining work

This closes a selected producer-to-comparator **data identity** gap. It does not close the top-level expected-root provenance/trust problem:

- Selector production, vote admission, quorum weight/threshold, equivocation rules and all producers of the ready vector remain open. `0x537aa60` and `0x5373e40` are candidate follow-up boundaries, not implemented contracts here.
- Timer eligibility, duration arithmetic, pruning and alternate callback routes remain open. No arbitrary pending height is asserted to be eligible.
- Registry lookup proves only membership in the supplied current registry projection. Registry provenance/rotation and whether a later remap changes eligible support require separate closure.
- Existing signer/preimage work documents upstream checks, but full hash/domain separation and cryptographic backend equivalence are not established by this contribution. Absence of a fresh crypto call at this extraction boundary does **not** mean the upstream vote was unauthenticated.
- Row height is bound to its selected tracker key and preserved through the handoff. Its identity with a proposed `H+1` rule or the current replay state's height is not established. Changing the row key selects a different local history entry or a missing entry; there is no universal “wrong height rejects” result here.
- Missing local history skips comparison. A stale entry can compare equal if present under the exact row key; this boundary supplies no independent freshness policy.
- Altered digest bytes mismatch when a differing local reference exists; if the local key is absent, comparison is skipped. This is not a cryptographic integrity proof.
- Allocator failure, unsafe ABI layout, balancing/sorting implementation, opaque values, native diagnostic side effects and full block-application integration are excluded.

Component completion, native runtime equivalence, full replay acceptance, and security/authentication gates remain **false**. No binary boundary inventory or coverage count is promoted by this packet.

## Prior art and overlap

The initial live comparison used main `0781ce04826eeefd89fe336cb8ea073be0c1de30`, an 808-open-PR title/path screen, all-state metadata queries for expected/reference roots, the named tracker, and the newly traced helper addresses, plus relevant existing source/packets. No precise extraction/remap/finalization successor was found. This is a documented search, not a claim to have proved uniqueness across every historical diff.

- [#4157](https://github.com/lalalune/hyperliquid-source/pull/4157), `RE-017-node115-raw-reference-origin`: local context `+0x400` history and later root insertion. Reused as local-history context, not claimed as new.
- [#4117](https://github.com/lalalune/hyperliquid-source/pull/4117), `RE-017-node115-digest-quorum-owner`: named descriptor construction/publication. Reused to distinguish sink ownership from input provenance.
- `RE-017-node115-compact-digest-reference-lookup`: row shape, exact local lookup and compare/missing behavior. The new contribution connects that consumer to the selected tracker producer and remap/filter, rather than relabeling the existing comparator.
- [#4114](https://github.com/lalalune/hyperliquid-source/pull/4114), `RE-010-node115-digest-vote-handler-tracker`; `RE-005-node115-vote-digest-preimage`; `RE-005-node115-signer-result`: upstream ingress/hash/recovery boundaries. Their authentication findings are credited; crypto is not reimplemented here.
- `RE-017-hash-signature-record-115`: earlier record variants and opaque insertion helpers. This packet does not assume those variants are interchangeable with rescheduled variants or declare their unresolved helpers closed.

## Reproduce

From the repository root, with the pinned artifact and existing documented Capstone 5.0.7 environment:

```sh
python research/work-items/RE-017-node115-digest-reference-handoff/verify.py
cargo test --offline --manifest-path src/node115-digest-reference-handoff/Cargo.toml
cargo test --offline --release --manifest-path src/node115-digest-reference-handoff/Cargo.toml
cargo clippy --offline --manifest-path src/node115-digest-reference-handoff/Cargo.toml --all-targets -- -D warnings
```

The verifier reuses the repository's audited ELF/FDE reader from `RE-001-node115-registry-row-labels`; it reads bytes only. Manifest and catalogue integration are handled through the repository's normal offline checks. Do not substitute target execution for the static evidence claim.
