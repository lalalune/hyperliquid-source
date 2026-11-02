# RE-007: compiled conditional posthash row selection

This follow-on adds one independently authored module to the existing
dependency-free `src/node94-margin-risk` component. It reconstructs the owned
bucket/default choice and late-state nonzero predicate established by #1460.
It does not implement the native hash, Once, row references or a whole lookup.

- Target: Linux x86-64 node94, SHA256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Credited native proof: #1460 at `f9d8906d9334e5f9297c81d4c211bfcdcf50f050`,
  `RE-007-row-lookup-default-94`; base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Native FDE: `0x36f57f0..0x36f5948`, 344 bytes, body SHA256
  `249708344e03cc11fe998076896e3915f03bb331dbad4522d62f724125975fa1`.
- Coordinates are linked ELF virtual addresses. Native bytes, FDE/CIE and
  21 named operand/opcode controls are rebound; no captured code or emulator runs.
- New code is MIT. Artifact/disassembly evidence retains upstream rights.
  No inferred unlicensed implementation was read or copied.

## Native relation and explicit premises

The public `row_selector::select_row_after_hash` returns an owned bucket index
or shared-default marker and the supplied late-state word's nonzero predicate.
The private core retains these native observations:

| Observed relation | Native coordinate |
| --- | --- |
| Count0 skips hash/table/key element reads | `0x36f57f7..0x36f5802` |
| Externally returned H yields fingerprint H>>57 | `0x36f580f..0x36f581b` |
| Masked 16-byte groups; ascending fingerprint candidates | `0x36f5841..0x36f5866` |
| Exactly20 key bytes, as16+4 | `0x36f586d..0x36f589b` |
| All candidates precede empty0xff group termination | `0x36f589d..0x36f58be` |
| Triangular group step grows by16 | `0x36f58be..0x36f58c9` |
| Bucket i maps to entry C-(i+1)*120 and row entry+24 | `0x36f5869`, `0x36f58ce..0x36f58db` |
| Late state load is checked on hits and misses | `0x36f58df`, `0x36f5901` |

For nonzero count, capacityN is a power of two at least16, native map+8 equals
N-1, and native byte at C+j equals `controls[j & (N-1)]` for0<=j<N+15.
The last15 positions are the physical mirrored prefix needed for unaligned
16-byte group loads. Each Rust key contains exactly the first20 native entry
bytes. Entry padding20..23 and value bytes24..119 are absent from this API.
Stable valid storage and normal hit/empty termination are native premises.
Read-only slices do not establish original memory provenance or read footprint.

All synthetic vectors are **conditional posthash states**. H is supplied at
the native hash-return boundary; its equality to the actual native hash for
the query/view is unproved. The whole-lookup hash-admissible denominator is0.
Fixed-H query mutations isolate equality after hashing, not real wire inputs.
`observed_state` means the word at the late load0x36f58df/0x36f5901; using an
entry snapshot additionally requires stability through that load. Its early
calculation from a supplied Rust integer makes no physical timing claim.

## Separately chosen checked-entry policy

The wrapper first preserves the count0 shortcut. For nonzero count it checks
control shape and key coverage. It bounds the private probe to N/16 groups,
then returns the new `NoNormalExit` label if no match or empty was encountered.
`ControlShape`, `KeyCoverage` and `NoNormalExit` are safe-API policy labels,
not recovered native errors, panic payloads or fault/nontermination behavior.

The cap does not truncate an admitted native normal selection. With N=16M
and M a power of two, triangular offsets permute all M groups: for distinct
0<=a,b<M, equality would require `(a-b)(a+b+1)` to be divisible by2M.
Exactly one factor is odd, while the even factor is nonzero with magnitude
below2M; it cannot contain the required power of two. Each group has the same
start residue modulo16, so these visits cover every logical control byte.
Any normal hit/empty must therefore be seen within that cycle.

## Frozen oracle, compiled comparison and controls

Ten synthetic expectations were frozen before Rust source; `PRE-RUST-FREEZE`
binds their exact bytes and native exports. The884 later additions are labeled
post-source: fixed-H query-byte/bit changes, all128 fingerprints, all32 starts
times16 lanes, later triangular groups through capacity256, state boundaries,
decoys and ignored count0 arguments. New expected choices use an independent
dictionary keyed by (fingerprint,20-byte key), not a probe walk. A separate
bounded walk only admits their constructed normal placements.

The observed pinned Rust1.94.1 builds compare894 qualified posthash cases and
seven separate chosen-policy cases at opt0/3, twice each:3576 posthash and28
policy observations. All outputs match. Existing component tests pass40/40 in
each profile; doctest count is0. Compiler warnings are denied for baseline
library/driver builds. Repeated driver/output hashes agree within each profile;
library archive hashes are retained separately and byte reproducibility is
not asserted.

Ten compiled source mutants each return normally with a different owned choice
or predicate on a frozen admitted posthash witness. No compile error, panic,
timeout or new API refusal counts toward those ten distinctions. Three further
mutants change only chosen API error labels and count solely as policy controls.
Five malformed-driver controls require exit2 and empty stdout. Fourteen
comparator/source/input-integrity controls reject; all21 named native anchor
corruptions reject below whole-body identity admission. Unique-key value
outputs cannot prove the physical order of candidate reads.

The input-only driver receives IDs,count,H,late state,controls,keys and query.
It receives neither names nor expected answers. The separate Python comparator
checks every output record. `prepare_selector.py` preserves the actual existing
component layout and its base-pinned external integration-test fixture. Every
compiler input, corpus byte, expected byte and source mutant is hash-bound in
the immutable recorded snapshot; every command/exit/stdout/stderr and tool identity is retained
in the observed report and lossless stream archive. No Cargo dependency or
manifest change is made.

## Reproduce

Use the existing official Rust1.94.1 compiler/std/Cargo installation; nothing
here downloads or installs tools. From the repository root:

```sh
python3 -B research/work-items/RE-007-row-selector-rust-94/check_freeze.py
python3 -B research/work-items/RE-007-row-selector-rust-94/observed.py --extract-snapshot work/selector-fixed
python3 -B research/work-items/RE-007-row-selector-rust-94/compare_selector.py --snapshot work/selector-fixed --freeze-sha256 <observed-freeze-digest> --self-check
python3 -B research/work-items/RE-007-row-selector-rust-94/run_selector.py --snapshot work/selector-fixed --freeze-sha256 <observed-freeze-digest> --out work/selector-built --rustc <approved-rustc> --cargo <approved-cargo>
python3 -B -m unittest discover -s tests -p test_row_selector_rust94.py -v
```

`observed/FREEZE.sha256` records the exact freeze digest. Fresh output paths
are required. The archived original source/input tree is reconstructed without
depending on current component modules or shallow Git history. Snapshot and
compiler identities are checked before success. Later modules require their
own explicit source-tree receipts; the original freeze and outputs are not refreshed.
The verifier/stream replay needs Python only; it never substitutes a stored
expected file for an actual compiled result.

## Remaining limits

Hash implementation/admission, actual Once/callback effects, constructor success,
native row address/lifetime/alias validity, concurrency and later caller mutation
remain outside this source. Checked-wrapper refusals, borrowed-slice validity
and the driver protocol are new research API choices. Physical loads/stores,
native ABI, machine-code identity, target execution, full risk reconstruction,
hosted CI and component acceptance gates are not claimed. No gate advances.
