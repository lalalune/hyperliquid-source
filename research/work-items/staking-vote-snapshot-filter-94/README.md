# staking: validator vote snapshot filtering and tree construction in node 94

This packet establishes that the vote snapshot selects current validator rows by profile signer membership in the calculated signer-power map, copies each selected row's **target** stake rather than its effective stake or calculated signer power, and transfers the selected keys and values into a tree when given the sorted vector.

- Component ID: staking (staking and validator lifecycle; validator L1 vote snapshot).
- Target release and full SHA-256: node 94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519` / `999556f6e0a474b8312db96ec3149e1c44e97c23`; the unlicensed reference is a lead only and no reference code is copied. The x86 interpreter is adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`.
- Claim status: observation for the ELF bytes, relocation, FDE records, and stated results of the bounded interpreter; inference for semantic names supplied by earlier packets. Actual chain reachability of synthetic states, external hooks, and uncovered branches remain unresolved.
- Scope included and excluded: the complete FDE extents of the vector filter, its initial predicate and iterator, and the sorted-vector tree builder, entered with an empty leaf. Incoming instruction sites are context only; their enclosing caller, the sort between the filter and builder, and later vote-row writes are excluded. The signer-power calculation and validator vote handler are established context from `staking-stake-accounting-94` and `staking-validator-l1-vote-94`, respectively, and are not claimed or reanalysed here. Allocator, vector growth, comparator, memory operations, status logging and status destruction are hook boundaries. Neither the whole component nor node 115 is covered.

## Reproduce

From the repository root, using Python 3 and the standard library (tested on Python 3.12.3, Linux x86-64):

```sh
python3 tools/staking_snapshot_filter94.py --out research/work-items/staking-vote-snapshot-filter-94
python3 -m unittest tests.test_staking_snapshot_filter94
(cd research/work-items/staking-vote-snapshot-filter-94 && sha256sum -c MANIFEST.sha256)
```

For a reproducibility comparison, choose an empty directory at `work/snapshot-repro`:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_snapshot_filter94.py --out work/snapshot-repro/a
PYTHONHASHSEED=27 TZ=Pacific/Honolulu python3 tools/staking_snapshot_filter94.py --out work/snapshot-repro/b
diff -r work/snapshot-repro/a work/snapshot-repro/b
```

The generator first verifies the full input digest, reads ELF and FDEs with `tools/elf_index.py` and `tools/fde_extents.py`, refuses duplicate FDE starts and changed instruction anchors, and generates every TSV and JSON file in this packet. It calls no external executable. The four target functions are interpreted from their bytes in a bounded x86 subset interpreter; the captured node is never executed. The output has no time, random seed, host path or binutils dependency. `MANIFEST.sha256` records the output and this README.

## Evidence

All code coordinates are ELF virtual addresses, with exclusive FDE ends; file offsets and complete body hashes are in `functions.tsv`. `instructions.tsv` is the in-tool byte decoder's complete linear export of the four FDEs. It is not a statement that every instruction is dynamically reachable. `branches.tsv` records taken and fallthrough coverage, and `calls.tsv` records direct calls, slots and relocation details.

| Role | FDE extent | Bytes | Decoded instructions / reached |
| --- | --- | ---: | ---: |
| Filter and output vector | `0x3bcfd70..0x3bd0521` | 1969 | 431 / 322 |
| Initial membership predicate | `0x33755f0..0x33757b7` | 455 | 114 / 112 |
| Stake iterator next | `0x330f550..0x330f758` | 520 | 122 / 84 |
| Sorted-vector tree builder | `0x2fb8dd0..0x2fb975b` | 2443 | 477 / 353 |

### Connection and inputs

`incoming-context.tsv` preserves selected incoming instructions only. At call site `0x336d645`, the argument in `rsi` points to an iterator assembled from the state pointer's root, height and length at `+0x10`, `+0x18`, and `+0x20`; iterator `+0x48` points back to the state and `+0x50` points to a map produced by the preceding slot call. `incoming-slot.tsv` resolves that slot's actual `R_X86_64_RELATIVE` relocation. The preceding `staking-stake-accounting-94` packet identifies these state words as `stakes.current.validator_to_stake`, its two values as `effective` and `target`, and the slot result as a signer-to-power map. Those names and the connection to the vote handler in `staking-validator-l1-vote-94` are inherited inferences, not fresh claims about either excluded function.

At the other end, the context sites show an empty-vector branch, creation of an empty `0x140`-byte leaf for a nonempty vector, a tagged iterator with 32-byte elements, and the builder call at `0x336d6e4`. They also show a sorting decision between the filter and builder, but the sorting functions are outside this packet. The combined fixtures rely on their filter output already being ordered by unique validator key and pass those rows directly to the builder; they do not claim the behavior of the omitted sorting call.

### Selection and output

Within the selected functions, the state profile tree root and height are at `+0x150` and `+0x158`. Both searches use 20-byte comparisons through a `R_X86_64_GLOB_DAT` relocation to `memcmp` (`calls.tsv`). The profile tree stores keys at node `+0x3d0`, stride 20, and the selected profile's signer bytes at node `+0x40 + index*0x58`. The signer map uses keys at node `+0x60`, stride 20. Fixture trees are checked for parent links, key order, occupancy and length before interpretation.

| Condition for a source row | Observed continuation, if hooks return normally |
| --- | --- |
| No profile for its 20-byte key | A call with status `0x91`; skip the row. `status.tsv` independently binds that tag to `Unknown validator`. |
| Profile exists, signer absent from the supplied map | Skip the row; the profile-result destruction hook is called. |
| Profile exists, signer present in the supplied map | Append the original validator key and the source value's second 64-bit word. The map's associated power value is not copied. |

The first candidate is checked by the separate predicate. Once one row is accepted, the filter uses an inlined continuation for remaining rows; both have separate anchors and both are exercised. `0x3bcfdc0` and `0x3bd00db` load the second word in those two paths. Each returned vector element is 32 bytes: the 20-byte validator key, four bytes outside the claimed fields, and the 64-bit word at `+0x18`. Padding is not asserted. No addition or rounding of the value is performed in this filter.

For example, the `duplicate-signer` fixture supplies rows `(validator, effective, target)` of `(1,111,999)` and `(2,222,888)` with both profiles pointing to signer 101, and a single signer-map entry with value zero. The interpreter returns and stores `(1,999)` and `(2,888)`. This is a conditional result for a synthetic input, not proof that this input arises in a real state. The `one-target-zero` and `target-u64-max` cases preserve both ends of the u64 value domain. A missing or zero-valued signer entry is distinguished by membership, not by its value.

### Tree builder

The separately interpreted builder receives a nonempty, sorted vector and an empty leaf. Its input advances by 32 bytes per row; the output tree holds 20-byte keys at node `+0x60` and u64 values at node `+0x08`. It writes a node key count at `+0x13e` and updates the map length. The `tree-011`, `tree-012` and `tree-144` fixtures exercise output heights 0, 1 and 2, respectively, and preserve every selected key/value pair. The empty-vector branch is context only and is not interpreted as part of the builder.

For separately supplied **sorted synthetic** vectors with adjacent duplicate keys, all 37 `bulk-cases.tsv` controls agree with the rule that the last value for a key is kept. They include duplicates at 13 positions around a leaf split and keys differing in each of their 20 bytes. A well-formed source B-tree supplies unique validator keys, so these controls do not establish that duplicate rows reach the builder through the staking path. Unsorted input is rejected by the fixture, and no claim is made about the binary's behavior for it.

The free hook checks that the builder passes the owned vector pointer and allocation size on normal completion; it does not actually free memory. Allocation, growth and copy hooks are bounded fixture implementations. In particular, the builder's first empty leaf is supplied by the fixture according to the incoming context, and the fixture's vector growth policy is not asserted to be the node's policy.

### Checks and controls

The separately written rule predicts output keys and target words, stored tree rows, missing-profile status calls, profile-result destruction calls, owned-vector free size, and unchanged synthetic input trees. All **309** end-to-end fixture cases and **37** additional sorted bulk controls agree. The former include all 81 three-way presence combinations for four rows, 80 byte-position controls for both 20-byte key types and both filter forms, fixed mixed cases, and trees up to 144 entries with the first match at different positions.

Of 1,144 decoded instructions, 871 are reached; 57 of 115 conditional branches take both edges and 24 are not reached. `branch-mutations.tsv` flips each conditional once and runs up to six already passing, reaching fixtures: 29 flips produce a different observed result or hook event, 61 hit an interpreter or hook fault, one survives and 24 have no reaching witness. The survivor is the initial tree-height branch at `0x2fb8df1`: every fixture starts at height zero, and the flipped branch rejoins the same location through the alternate zero-height check (`anchors.tsv`). A fault is not proof of how the node would behave, and these edits do not establish equivalence. Unit tests also reject a bad digest, altered instruction bytes, bad FDE entry, non-file-backed or out-of-range addresses, malformed fixture trees, duplicate source keys and unsorted bulk fixtures; they demonstrate changed outputs or rejected results when a branch, each target-word load, and a builder value slot are altered.

## Implementation and comparison

not yet implemented. No independent Rust build, binary comparison, relocation closure, normalization mask, or native differential execution is claimed. The Python evaluator is a static byte analysis with synthetic memory and checked hook arguments. The separately written rules and fixtures do not prove the behavior of untested instructions or external calls.

## Results and limitations

The 20 focused unit tests pass without binutils on `PATH`. The static packet covers the four listed FDEs and the stated ordered-input-to-tree path only; it requests no progress gate. The intervening sort, allocation failure, unwind behavior, other code paths in the external logger and destructor, the real growth policy, malformed native trees and later insertion into the vote row are not established. Power-map contents are fixture inputs, so shared-signer and zero-power examples do not establish real-chain reachability. Source field names rely on the earlier accounting packet; the selected functions themselves expose offsets and bytes.

Next question: validate the omitted sort and vote-row integration and establish which real power-map and target-stake boundary states reach this snapshot.
