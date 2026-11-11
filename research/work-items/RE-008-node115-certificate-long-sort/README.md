# Node115 long certificate sort: equal-key order and duplicate winner

Scoped work toward [#3926](https://github.com/lalalune/hyperliquid-source/issues/3926) and backlog **HL115-020**. This extends [#2913](https://github.com/lalalune/hyperliquid-source/pull/2913), `RE-001-node115-certificate-voter-normalization`, which established short insertion sorting, last-sorted-row compaction and the retained-count container threshold, but explicitly left the ≥21-row sort's stability open.

**Recovered result:** on the valid, normally completing QC and TC normalization paths, equal 20-byte keys preserve their original relative order through the long sort. Combining that result with the existing whole-row compactor makes the **last original row for a key** the retained row, including conflicting opaque signatures and TC extra fields. The 20/21 sorting boundary does not change the winner. The 64/65 container choice uses the number of retained keys, not the input row count.

This is a normalization contract, not certificate validity. No claim about a quorum, signer authorization, signature verification, or full consensus completion follows from accepting a row into this collection.

## Target and method

- Original node #115 Linux x86-64 ELF, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes.
- Base main: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Static disassembly with Capstone 5.0.7, decoded from recorded FDE boundaries; 16 complete function windows, 17,137 bytes, 4,004 instructions, 4,018 retained instruction/import/relocation/edge checks and 58 deliberate corruptions.
- `verify.py` authenticates the original digest, FDEs, instruction boundaries and retained bytes. Its controls bypass the original/window digest checks after authentication, so corruptions must fail specific recorded facts.
- `proof_checks.py` checks the recovered four-key selection formula against all 256 assignments over four ordered key values, and stable partition order in 19,682 finite cases. These are high-level logical checks, not execution or emulation of captured instructions.
- No captured target or machine-code transplant is executed. The embedded Rust `stable/quicksort.rs` source-path string is a provenance clue, not the proof of stability.

## Exact call graph and prior-work boundary

| Role | QC (96-byte rows) | TC (104-byte rows) |
| --- | --- | --- |
| Constructor after successful decoded row input | `0x4de6470` | `0x4dbf950` |
| ≥21 dispatch slot → wrapper | `0x64e88d8 → 0x4f39140` | `0x64e88e0 → 0x4f3ada0` |
| Run discovery / merge core | `0x4fab020` | `0x4fa2c00` |
| Recursive stable partition slot → body | `0x64eb988 → 0x4ec1a80` | `0x64eb3a8 → 0x4e71d90` |
| Pointer-only pivot selection helper | `0x4e62f90` | `0x4e68420` |
| ≤32 small-sort helper inside long path | `0x53fe830` | `0x541ba50` |
| ≤20 insertion sort (credited prior work) | `0x53e6aa0` | `0x53ea3d0` |
| Whole-row compaction (credited prior work) | `0x5b2d7c0` | `0x5b2e330` |

All comparison sites use imported `memcmp` at slot `0x64dfb50` with length 20. The remaining bytes travel with the record. Imported `memcpy` at `0x64df508` moves contiguous whole-row regions; no comparison of the opaque tail is used to break a key tie. The wrappers allocate scratch for at least 48 rows, using the larger of `ceil(n/2)` and `min(n, floor(8,000,000 / row_size))`; allocation and valid buffer-size premises remain explicit.

The old wire readers and physical flat/tree builders are credited rather than reconstructed again. This packet starts with valid decoded logical rows. The Rust implementation labels the selected storage class but does not reproduce native allocation, node layout or ABI.

## Stability argument from the original paths

The invariant is that each transformation preserves the relative order of rows with equal keys and moves the entire row. Apply the invariant to the small-sort base cases, then to partition recursion and adjacent-run merges. Successful completion of the surrounding sort places equal keys together; the credited compactor's later-whole-row replacement then selects the last original row.

| Step | QC evidence | TC evidence | Tie behavior and invariant |
| --- | --- | --- | --- |
| Natural run discovery | `0x4fab1ee..0x4fab2db` | `0x4fa2df0..0x4fa2ec6` | Nondecreasing runs admit equality. Descending runs continue only on a negative comparison and stop on equality. Reversing a strictly descending run cannot reverse two equal keys. |
| Four-row seed | `0x53fe87a..0x53fea45` and second seed | `0x541ba9a..0x541bc87` and second seed | Both pairs choose their earlier row on equality; the middle selectors retain earlier-pair precedence on equal keys. The independently checked selection formula in `proof_checks.py` covers every four-key weak ordering. |
| Insertion into each small half | `0x53fed94..0x53feea6`, `0x53fef61..0x53ff0aa` | `0x541c010..0x541c145`, `0x541c1ef..0x541c358` | A row moves left only while strictly smaller. Equality terminates shifting, preserving earlier equal rows. |
| Small bidirectional merge | `0x53ff105..0x53ff1f2` | `0x541c3b4..0x541c4a8` | Forward output chooses the left half on equality; backward output chooses the right half on equality. These are complementary stable choices. Full records, including opaque tails, are copied. |
| Large forward merge | `0x4fab680..0x4fab6fb` | `0x4fa32b0..0x4fa332d` | Compare right with left; a nonnegative result selects left for the next output position. |
| Large backward merge | `0x4fab5e0..0x4fab66a` | `0x4fa3200..0x4fa328c` | Compare right with left; a nonnegative result selects right for the last remaining output position. |
| Strict partition | `0x4ec1c50..0x4ec1ec9` | `0x4e71f60..0x4e721db` | Scan input forward. `< pivot` rows are written forward; the other rows are written backward and read back in reverse storage order. Both resulting subsequences preserve original order. The saved pivot row is routed with its equal-key partition in its original scan position. |
| Equal partition | `0x4ec1f60..0x4ec21ee` | `0x4e72260..0x4e724f0` | The comparison is reversed, yielding a `<= pivot` partition. The same forward/backward write and reverse-read discipline preserves ties. Equal values are not shuffled by pivot selection. |
| Recursion and fallback | `0x4ec1f07`, `0x4ec2207..0x4ec2234` | `0x4e72218`, `0x4e72504..0x4e72530` | Recursive calls operate on ordered subsequences. Exhausted depth calls the same run/merge core with eager small sorting enabled, rather than an unstable fallback. |
| Compaction and layout choice | `0x4de64da..0x4de64f2`, `0x5b2d7c0` | `0x4dbf97e..0x4dbf992`, `0x5b2e330` | Adjacent equal keys retain the later complete sorted row. The updated length is checked against 64 after compaction. These observations agree with, and credit, #2913. |

The 21–64 path enables eager small sorting. Larger inputs can use partition recursion and a fallback to eager run/merge sorting. The argument covers both paths; it does not infer long-sort behavior solely from the already known ≤20 insertion helper.

Premises: valid decoded vectors and native buffer bounds; successful allocation; normal `memcmp` unsigned byte semantics and standard copy semantics; no hidden alias mutation or comparator inconsistency. Allocator failure, unwinding, memory corruption and invalid buffer descriptors are not modeled. The argument concerns ordering and retained row identity, not native resource consumption or exact instruction scheduling.

## Owned implementation and validation

`src/node115-certificate-long-sort` implements a separate recursive stable merge sort and last-row compaction in dependency-free `no_std + alloc` Rust. `QcRow` and `TcRow` preserve the first 20 key bytes and opaque tails of 76 and 84 bytes respectively. The tails include bytes whose individual semantic roles are outside this contract; their presence does not authorize decoding them as valid signatures.

The implementation's expected results come from an independent key-indexed overwrite ledger, not from another merge sort. Eight test groups exercise:

- Empty/single rows and conflicting duplicates across 19/20/21, 31/32/33, 63/64/65 and larger lengths, with increasing, decreasing, all-equal, interleaved and mixed-run inputs.
- Descending runs containing equal groups, duplicates across run boundaries, exact final-key-byte distinctions, and every opaque-tail byte changing independently.
- 65 input rows with 64 retained keys versus 65 distinct keys, proving the storage observation uses the post-compaction count.
- All three-key sequences through length seven and all four-key seed assignments.
- Sizes around 4096 and the two native scratch-cap transition constants, checking logical results without claiming target allocation behavior.
- Idempotence, whole-row retention, and the fact that reordering conflicting duplicates can change the retained row. Equivalent signer sets alone do not determine a unique signature payload.

The static corruption controls alter constructor thresholds, key width, long-sort and recursive targets, strict-run decisions, seed/insertion/merge tie decisions, partition classification, compactor record addressing and retained-count publication. The logical proof check also deliberately reverses equal-key order and rejects that alternative.

Passing owned tests is not a measured native differential test. The target binding and original-dataflow argument provide the native evidence; the tests provide an independently authored usable implementation and explicit counterexamples to first-wins, prefix-key and pre-compaction-count alternatives.

## Overlap and remaining dependencies

The live screen covered 1,071 open PR titles and changed-file lists, targeted all-state searches for the long-sort helpers and normalization question, and the nearest prior packet #2913. No matching long-sort stability successor was located. This is not a claim that unavailable or unpublished work was inspected.

`RE-001-node115-certificate-voter-normalization` remains the credited source for decoder/constructor linkage, ≤20 behavior, compaction and container thresholds. This contribution closes its explicit long-sort ordering gap; it does not republish the older packet as new work. It can support backlog HL115-019's normalization-to-quorum composition, but actual stake-view coherence and certificate verification remain independent prerequisites.

Full consensus, cryptographic correctness, native runtime equivalence and component completion gates remain false. No global function coverage or boundary inventory is advanced by this result.

## Reproduce

With the pinned artifact and existing Capstone 5.0.7 environment, from the repository root:

```sh
python research/work-items/RE-008-node115-certificate-long-sort/verify.py
python research/work-items/RE-008-node115-certificate-long-sort/proof_checks.py
cargo test --offline --manifest-path src/node115-certificate-long-sort/Cargo.toml
cargo test --offline --release --manifest-path src/node115-certificate-long-sort/Cargo.toml
cargo clippy --offline --manifest-path src/node115-certificate-long-sort/Cargo.toml --all-targets -- -D warnings
```

The ELF/FDE reader is the existing audited `RE-001-node115-registry-row-labels` helper. The packet is registered through the existing catalogue; pinned inputs and full-scope component gates are unchanged.
