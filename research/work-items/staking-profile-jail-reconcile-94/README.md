# staking: profile signer changes and jailed-signer reconciliation in node #94

This packet establishes that the profile-change cleanup builds the set of signers from all validator profiles and passes exactly the jailed signers absent from that set to the removal boundary, so a reconstruction can preserve a jailed signer shared by another profile while removing an orphaned one.

- Component ID: staking, validator lifecycle and jailing.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference was used only as a lead, and no code was copied from it.
- Claim status: observation for the pinned ELF bytes, FDE records, decoded branch destinations and bounded interpreter results. Field names and the relation to the previously mapped profile and jailed state are supported by the serializer and earlier packets; the unrecovered triggering conditions and external calls are listed below.
- Scope included and excluded: nine previously unreported functions, the profile write and cleanup call sites, and the removal-loop slice. The existing profile-action host is context, not a claimed function. The profile validation and authorization gates, removal callee, large-input sort implementation, allocator, iterator boundary and full node behavior are excluded.

## Reproduce

Run from the repository root with Python 3.12 or later and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/staking_profile_jail_cleanup94.py --out research/work-items/staking-profile-jail-reconcile-94
python3 -m unittest tests.test_staking_profile_jail_cleanup94
(cd research/work-items/staking-profile-jail-reconcile-94 && sha256sum -c MANIFEST.sha256)
```

The tool verifies the complete target digest before parsing. It uses `tools/elf_index.py` and `tools/fde_extents.py` for ELF sections and FDE records. Every selected FDE is also checked against a fixed body hash; reviewed instruction encodings are checked before interpretation. The instruction interpreter is adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`. It interprets bytes in Python and does not execute the target or start external programs. Each emitted file is deterministic and is listed in `MANIFEST.sha256`; this README and the manifest are not generator outputs.

`functions.tsv` contains FDE bounds, file offsets, body hashes and instruction counts. `instructions.tsv` retains decoded instruction bytes and observed reachability. `branches.tsv` records direct conditional destinations and which edges the ordinary scenarios reached. `witnesses.tsv`, `fields.tsv` and `relocations.tsv` bind the important calls, operands and field names. `scenarios.json`, `transitions.json`, `failure-controls.json`, `profile-copy-control.json`, `mutations.json` and `summary.json` contain the fixture inputs, results and controls.

## Evidence

All code and data addresses below are ELF virtual addresses; file offsets are in the generated tables. FDE ends are unwind-described exclusive bounds, not a whole-program function census. All nine subject starts are absent from earlier work-item evidence; the previously mapped host contributes only the specified call sites and loop slice.

| Role | FDE start | Exclusive end | What is established here |
| --- | --- | --- | --- |
| Profile map write | `0x33a4600` | `0x33a4991` | Replace an existing value or insert a new key; return the old value or a None niche |
| Profile insertion | `0x2f65a00` | `0x2f66e32` | Insert in a nonempty map, including a full-leaf split in the bounded fixtures |
| Signer projection entry | `0x39966b0` | `0x3996725` | Read the profile-map root, height and length and pass an iterator to the collector |
| Signer collector | `0x3bb27c0` | `0x3bb29bd` | Allocate the vector, choose sort path and build the set |
| Profile iterator | `0x3be3fd0` | `0x3be4221` | Walk profile values and copy a 20-byte field from each |
| Jail difference | `0x3babfb0` | `0x3bac6e0` | Collect jailed keys absent from the projected set |
| Small sort | `0x3386ec0` | `0x3386fae` | Sort the bounded vector for the small-count branch |
| Set bulk build | `0x2fba3b0` | `0x2fbaa61` | Build the ordered set and collapse duplicate projected values |
| Build rebalancing | `0x2fa5270` | `0x2fa5514` | Rebalance the set build when the rightmost node is underfull |

### State and path

Let `S` be the staking state. The serializer pairs the text `validator_to_profile` with `S+0x150`, and `jailed_signers` with `S+0xb0`. The cleanup reads the current jail-set root at `S+0xd8`, an offset of `0x28` inside the latter tracker. The profile map contains 20-byte keys and 0x58-byte values. The iterator copies 16 bytes at node value-array `+0x40` and four bytes at `+0x50`; the map's first value begins at node `+8`. Thus the copied field is value `+0x38`, the signer field identified by the profile serializer and the earlier profile-gate packet. `fields.tsv` and `witnesses.tsv` retain the byte coordinates.

The profile-change caller saves the profile-map pointer, calls the profile write, and later calls the projection through a RELATIVE relocation. After that, its cleanup slice uses the current jail set:

```text
profile map write -> projection -> collect each profile's signer
                                  -> sort -> ordered set (duplicates collapse)
current jailed set -> ordered difference against that signer set
                   -> one removal-boundary call per difference key
```

The projection call is at `0x3995d59`; its relocation targets the projection entry. The difference call is at `0x3995ded`. The loop at `0x3995df2..0x3995e5e` passes `S+0xd8` and each 20-byte result to the call at `0x3995e50`. These are site coordinates inside a previously mapped host; the packet does not claim that entire host or all paths leading to the slice.

### Branches and boundaries

| Condition | Observed path |
| --- | --- |
| Existing profile key | Copy the previous 0x58-byte value to the return area and replace it with the incoming value. The modeled map length stays unchanged. |
| New profile key, empty map | Allocate a leaf, place the key and value, and return the None niche. |
| New key, nonempty map | Enter the profile-insertion helper. A full 11-row leaf takes the split path; an 11-to-12-row fixture produces height one. |
| Null profile root | Collect an empty set, even if the accompanying count word is stale. |
| Projected count 0 or 1 | No sort call. |
| Projected count 2 through 20 | Call the small-sort function. |
| Projected count at least 21 | Call the large-sort slot, modeled at the boundary in these fixtures. |
| Projected value repeated | The resulting set contains one key for the repeated 20-byte value. |
| Jail key in projected set | Retain it and continue to the next jail key. |
| Jail key absent from projected set | Append it to the result vector. The caller slice passes each result to the removal boundary in order. |
| No difference keys | The caller slice makes no removal call. |

For example, if profiles map `X` and `Y` to signer `A` and `Z` to signer `B`, a jail set containing `A` and `C` produces only `C` at the removal boundary. If `X` changes from `A` to `D` while `Y` still maps to `A`, `A` remains in the projected set. If `X` was the last profile with `A`, `A` becomes a removal candidate. These are fixture results for the bounded path, not a claim about when a live validator is jailed.

The collector multiplies its row count by 20 and rejects a u64 multiplication overflow or a result with the high bit set before allocating. The accepted arithmetic boundary is 461168601842738790 rows; the next count is rejected. These are arithmetic limits, not feasible fixture sizes. The first difference-vector allocation is 0x50 bytes, sufficient for four 20-byte keys; the fixture growth boundary is checked separately.

### Method and controls

A separate patterned-value control checks all 0x58 bytes of both the returned old profile and the replacement stored in the leaf. The independent rule compares profile-map values and the set difference with the interpreted target instructions. It checks the old returned profile, projected signers, ordered difference, arguments passed to every removal-boundary call and fixture state around that boundary. There are 240 projection/difference cases and 70 write-to-cleanup cases, including empty trees, 1 to 23 input profiles, duplicate and shared signers, insertion and replacement, a profile-node split, and jail trees with up to 23 keys. The profiles and keys are synthetic and deterministic.

The seven directly interpreted path and sort/build functions and the two profile-map functions use real instructions. Allocation, deallocation, byte comparison and copying are checked fixture boundaries. The jail iterator's initial next operation and result-vector growth are checked models; a large-sort call is modeled for counts of 21 or more. The removal call is a recording boundary: **no target tree deletion is executed or claimed**. For target instructions, the 310 ordinary cases reach 1553 of 2444 decoded subject rows; 58 of 182 conditional rows, including the separate loop slice, have both edges observed. A reached row or edge is not proof of complete control flow.

Three separate byte mutations change a profile write, a signer load, and a jail membership branch; all are detected against the independent expectations. Five failure controls reach the hooked failure boundaries: high-bit size, multiplication overflow, collection-vector allocation, set-node allocation and profile-node allocation. The last three deliberately return null from the fixture allocator. These controls do not execute panic or allocator implementations.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker settings, two-build comparison, raw and normalized byte matches, masks, relocation closure and behavioral comparison to a running node: not yet measured. No original machine code is transplanted. The earlier packets `staking-delegate-entry-94`, `staking-c-signer-jail-94`, `staking-cstaking-state-wire-94`, and `RE-004-validator-profile-gates-94` establish neighboring context; the functions selected here have distinct starts.

## Results and limitations

The generator reports 310 matching bounded scenarios, three detected mutations and five reached failure boundaries. `python3 -m unittest tests.test_staking_profile_jail_cleanup94` passes 25 tests with no skips. No component progress gate is requested.

The large-sort implementation, allocator, comparison routine, iterator boundary, vector growth and removal function are modeled or recorded, not recovered. Fixture trees have at most two levels and do not cover deeper splits, all unwind cleanup or every allocation-failure site. The captured executable was not run. The profile-action host is not evaluated from entry, so its authorization, timing and conditions for reaching this cleanup are not established by these tests. `instructions.tsv` is a linear FDE decode, not a proof that every byte is reachable or every helper is closed.

Next question: independently reconstruct and validate the removal callee on multilevel jailed-set trees, then determine all profile-action conditions that reach the cleanup slice.
