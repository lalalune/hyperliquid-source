# RE-003: late node #115 PR validation

- Target SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `9f6c8daf05f9146f8e6a5759b7381c2cf35b1a03`.
- Scope: 11 new PRs and five updated PR heads. Exact heads and final hashes are
  retained beside this record. No full component gate is changed.

Nine new static packets pass 106 model tests, all nine packet verifiers and
100 manifest entries. Independent native checks cover 19 unique FDE ranges,
47,862 bytes and 9,389 instruction rows; 695 retained rows and 24 byte atoms
match the authenticated target. These bounds do not establish full caller,
dependency or component closure.

The five updated PRs change validation metadata only. Their implementation,
test and tool bytes match the preceding reviewed versions. New nonce-text Rust
passes both host profiles against 71,175 frozen frames plus 27 CLI controls per
profile; all 12 library mutants are rejected in both profiles. The existing
provider's normal and optimized validators pass 168 controls per mode. The new
ready-vector Rust passes 23,618 host cases per profile, including its two domain
refusals, and rejects seven compiled mutants. Its complete six-method Python
test file also passes with the explicit pinned own-Rust compiler.

Six packets referenced a shared generated README and SVG using manifest paths
that drifted or resolved to their own README. Their original manifests and
original shared files are preserved in `review-inputs/`; only those manifest
paths are redirected, keeping all 12 recorded hashes unchanged. Current
generated tables are regenerated normally. No imported bytes are changed.

The prior full 573-file regression remains valid: every existing test source
hash is unchanged. Ten new focused modules bring the current inventory to 583
files, with zero failing modules and 24 explicit skips. This is a complete
prior sweep plus focused late validation, not a second full sweep. Independent
nonce Rust/provider checks are retained separately. Artifact/import/packet
verification and catalogue checks pass locally; hosted CI is separate.

No captured code or target-instruction interpreter was run. New compiled
programs are independently authored Rust. Protocol, allocator, runtime and
whole-node identity limitations remain as stated in each original packet.

Next question: join a bounded implementation to its actual #115 caller and
data/ABI contract before assigning broader reconstruction credit.
