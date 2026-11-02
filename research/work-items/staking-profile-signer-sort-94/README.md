# staking: profile-signer long sort in node 94

This packet resolves the previously modeled large-input sort in profile-signer reconciliation: a reconstruction can order the projected 20-byte signers lexicographically, including repeated signers, and reproduce the observed small-partition, pivot and depth-fallback boundaries.

- Component ID: staking, validator lifecycle and jailed-signer reconciliation.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference was used only as a lead; no implementation was copied from it.
- Claim status: observation for the pinned bytes, FDE records, relocation rows, and bounded instruction-interpreter results; inference for the relationship between this general sorting machinery and the signer semantics established in the related profile-reconciliation packet. Unreached and modeled behavior is described below.
- Scope included and excluded: four previously unreported sorting functions reached from the large-input branch of the signer projection; the earlier profile host, projection, collector, outer sort entry, set builder and removal loop are context only. The short sort, allocator, libc implementation, real panic and unwind, other callers, and node #115 are excluded.

## Reproduce

From the repository root, with Python 3.12.3 on Linux x86-64 and the standard library:

```sh
python3 tools/staking_profile_signer_sort94.py --out research/work-items/staking-profile-signer-sort-94
python3 -m unittest tests.test_staking_profile_signer_sort94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For independent byte comparisons, substitute a writable relative directory for the placeholder:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_profile_signer_sort94.py --out <tmp-dir>/first
PYTHONHASHSEED=391 TZ=Pacific/Honolulu python3 tools/staking_profile_signer_sort94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
```

The generator checks the full input digest first, reads ELF sections and FDEs using `tools/elf_index.py` and `tools/fde_extents.py`, rejects non-file-backed mappings, validates body hashes and relocation identities, and interprets selected machine-code bytes in Python. It invokes no external programs and does not execute the captured node. The decoder and interpreter are adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`. The generated files are `functions.tsv`, `instructions.tsv`, `branches.tsv`, `calls.tsv`, `context.tsv`, `relocations.tsv`, `sort-cases.tsv`, `sort-witness.tsv`, `scratch-cases.tsv`, `partition-cases.tsv`, `pivot-cases.tsv`, `mutations.tsv` and `summary.json`. `MANIFEST.sha256` records the hashes of those files and this README.

## Evidence

Addresses are linked ELF virtual addresses; file offsets, exclusive FDE ends, and body hashes are in `functions.tsv`. FDEs describe unwind ranges, not a complete function census. The decoded rows are linear over each selected FDE; reachability is recorded separately in `instructions.tsv`. The direct and RIP-relative call sites are retained in `calls.tsv`; calls through registers are not claimed as a complete census.

| Role | FDE start | Exclusive end | Bytes |
| --- | --- | --- | ---: |
| Small partition | `0x3389dc0` | `0x338a498` | 1752 |
| Pivot selector | `0x3860890` | `0x386095b` | 203 |
| Sort driver | `0x386a1e0` | `0x386a903` | 1827 |
| Partition | `0x3879d30` | `0x387a320` | 1520 |

### Path from profile reconciliation

The related open profile-reconciliation work identifies the map at `CStaking+0x150` and the copied value field as profile signers. Its large sort was a modeled boundary. The retained context bytes and relocations bind the following chain without claiming those previously studied functions as new subjects:

```text
profile-change site 0x3995d59 -> projection -> collector
  iterator copies 16 bytes plus 4 bytes for each projected field
  collector count >= 21 -> slot 0x5776298 -> outer sort entry
    direct call 0x3bc131a -> driver 0x386a1e0
      slot 0x5775f58 -> partition 0x3879d30
        under 33 rows -> small partition 0x3389dc0
        larger partition -> pivot 0x3860890
        exhausted depth -> driver 0x386a1e0
```

`context.tsv` contains the original caller, iterator, threshold and call bytes; `relocations.tsv` binds both slots. A direct call and a relocation are evidence of the link, not evidence that every host input reaches it. In the direct driver fixtures, the outer entry is not interpreted. The fixtures supply its observed `n < 65` flag and a scratch buffer of 204 rows for smaller cases and `n` rows for cases of at least 205; the outer allocation and free are not tested here.

### Ordering, decisions and failure boundaries

For each of 122 deterministic driver fixtures the result equals a separate Python lexicographic ordering of the input 20-byte rows. Inputs cover ascending, descending, equal and repeated rows, mixed rows, deterministic mixed-byte rows, every individual byte position, high-bit bytes, and counts from 21 through 4097. In particular, changing only the last byte changes the observed order. Repeated rows remain repeated at this stage; their later collapse into a set is outside this packet. Equal 20-byte rows have no separate payload here, so these tests do not establish stable ordering.

| Decision | Observation |
| --- | --- |
| Driver count below 2 | Direct branch to return; the reconciliation caller's large-sort branch starts at 21. |
| Partition count below 33 | Calls the small-partition function. |
| Partition count at least 33 with depth budget 0 | The direct synthetic probe takes the fallback call to the driver; it then sorts the test data. This does not establish that the real caller supplies this combination. |
| Partition count 65 with budget 5 | The tested path reaches the pivot without the fallback. |
| Pivot stride count below 8 | The tested selector returns the median value of its three 20-byte inputs. |
| Pivot stride count at least 8 | Three recursive selections feed the same three-way selection; direct probes cover stride counts 8 and 64. |
| Small partition with fewer than 2 rows | Returns in the direct tests even with zero scratch capacity. |
| Small partition with 2 or more rows | Direct tests trap at the `ud2` boundary when scratch capacity is below `n + 16`; `n + 16` passes for the tested sizes. |

`sort-witness.tsv` retains 221 complete input, actual and independently expected rows from four fixtures. `partition-cases.tsv` and `pivot-cases.tsv` retain the direct synthetic inputs and outcomes. These probes exercise internal argument combinations, not necessarily combinations reachable from a valid profile update. `scratch-cases.tsv` records the small-partition checks. The unmodified runs use canaries on both sides of driver input and scratch; no overrun is observed in these fixtures.

The interpreted external boundaries are modeled: `memcmp` compares exactly 20 unsigned bytes and returns the sign, `memcpy` rejects overlapping fixture ranges, and `memmove` permits overlap. Four byte mutations affecting the small comparison, partition destination, scratch guard and pivot direction are detected (`mutations.tsv`). They are individual corruption controls, not an exhaustive mutation score.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler and linker settings, two-build comparison, raw and normalized byte matches, normalization masks, and whole-ELF comparison are not yet measured. The Python ordering rule is an independent fixture oracle, not a Rust reconstruction or evidence from running the captured executable. `instructions.tsv` retains the original selected bytes without operand masks; call targets and relocations outside the modeled boundaries remain separate gaps.

## Results and limitations

- The selected four FDE windows total 5302 bytes and decode to 1307 instruction starts. The 122 driver fixtures reach 1209 of those starts; both edges are observed at 60 of 87 conditional sites. These are local fixture counts, not component coverage or a function denominator.
- All 122 sort fixtures, 18 direct scratch probes, 6 partition probes and 17 pivot probes match their stated expectations. Four selected instruction mutations are detected. The focused suite passes 14 tests with no skips, including wrong digest, invalid address, corrupted context and body bytes, wrong or duplicate relocations, and changed comparisons and branch bytes.
- The helper calls through registers and remaining failure paths are not completely enumerated or interpreted. The modeled comparison, copy, panic and unwind boundaries do not prove libc or runtime behavior. Neither host authorization nor the full update-to-jail loop is executed from its entry here. Synthetic rows are not evidence of a reachable chain state. Sorting behavior for every possible length and buffer shape remains open.
- No component progress gate is requested. Next question: independently implement and compare this signer ordering and its caller's real allocation and cleanup paths, including allocation failure and valid-state reachability of the fallback.
