# RE-017: ordered hash jobs and the digest-list input

The local-state host's task table can lead to low-lane block application, whose 41 hash-job results retain input order and form a 2,791-byte digest-list input under the normal-path conditions below.

- Component ID: `abci`, RE-017, bounded state-root input question.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied.
- Claim status: raw ELF bytes, FDE records, selected branch and transfer destinations, and LSDA rows are observations. Role names and the composition of these observations into ordered results are conditional inferences. Runtime ownership and scheduling are unresolved.
- Scope included and excluded: 20 previously unclaimed FDE ranges in the task handoff, low-lane job and finalization paths, plus selected context windows in earlier host, bridge, builders and encoders. The original state loader, its GOT/call sites, prior host and bridges, builders, digest-list writer, and hash functions are boundaries, not newly owned functions. The two other builder lanes, individual state-field serializers, node #115 and visor are excluded.

## Reproduce

Run from the repository root with CPython 3.12.3, the standard library and the #94 artifact available:

```sh
python3 tools/artifacts.py verify
python3 tools/abci_hash_jobs94.py --out research/work-items/RE-017-hash-job-order-94
python3 -m unittest tests.test_abci_hash_jobs94 -v
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-hash-job-order-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_hash_jobs94.py --out work/hash-order-a
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_hash_jobs94.py --out work/hash-order-b
diff -r work/hash-order-a work/hash-order-b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-hash-job-order-94 work/hash-order-a
```

The independent output directories must be absent or empty. The eleven generated files are `functions.tsv`, `windows.tsv`, `branches.tsv`, `transfers.tsv`, `lsda-headers.tsv`, `lsda.tsv`, `failure-links.tsv`, `result-slots.tsv`, `task-relocation.tsv`, `task-dispatch.tsv` and `summary.json`. The manifest covers those files and this README. The generator authenticates the entire input before parsing, uses the repository's `tools/elf_index.py` and `tools/fde_extents.py`, rejects ambiguous and NOBITS file mappings, matches only specified machine-byte forms, and obtains relative destinations from signed ELF displacements. FDE and call-site ends are exclusive. No normalization is applied.

Development used Linux x86-64 and GNU objdump 2.42 for human inspection of bounded disassembly only; generated numbers, lists and bytes come from the ELF and the Python readers. Neither generator nor tests invoke an external program, execute the capture, read a clock or use networking, chain data or keys. The target is opened read-only; mutation controls use a private copy-on-write mapping. Tests require the artifact and have no skip path.

## Evidence

Addresses below are unrelocated ELF virtual addresses (VA). The tables separately record file offsets, full selected FDE bytes and SHA-256 hashes. An FDE is an unwind-described interval, not proof of an exact function boundary or of component coverage. Tables of branches and transfers contain selected sites, not a whole-node census. Descriptive names are local labels.

### Prior boundaries and entry

The earlier [state link](../RE-017-abci-state-link-94/EVIDENCE.md) binds the `state.rs` Location-bearing loader, and the [round-clock study](../staking-round-clock-94/README.md) follows its reloader into a host and records the reloaded object. The [app-hash builder study](../RE-009-app-hash-builder-94/README.md) identifies the low builder `0x2755dc0`, 41 capture descriptors and their state-field offsets, and the result vector's later digest-list hash; it explicitly left runner internals and result order open. Those earlier findings are dependencies, not a proof that the object received by the builder is the object returned by that loader.

The [startup inventory](../startup-inventory-94/inventory.json) records a host call at `0x22b55fa` to the existing constructor `0x2020c70`, and a call from the existing bridge `0x2017c80` to the low apply FDE `0x2209d40`. This host also contains the original reload route, but the selected constructor lies in a bootstrap-side path; the route from the original reload result to that constructor is not established. The following table and byte windows therefore establish a possible static task-to-apply connection, not a definite loader-to-root lifecycle.

| Step | Selected observation |
| --- | --- |
| Host input | The host stages an aggregate and copies `0x3ec0` bytes to the constructor argument. Its already inventoried call is a boundary. |
| Constructor | The existing constructor retains its argument, stages `0x3ec0` bytes, places state word `0xcc` and table address `0x5696da0` in a `0x3f80`-byte task allocation, and copies the staged bytes at task offset `+0x40`. The input pointer's survival through intervening calls assumes the ABI's callee-saved-register rule and no aliasing. |
| Submission | The constructor passes the task pointer and flag 1 through slot `0x5773580`, whose type-8, symbol-zero relocation targets newly selected `0x4f7c290`. Under its zero state-byte arm, that function writes the task pointer and flag into a 16-byte queue entry after an optional grow call. A nonzero state byte instead subtracts `0x40` from the task word, branches on carry and calls the table's `+0x30` entry; lock contention takes a separate slow path. |
| Table and thunk | The unique type-8, symbol-zero relocation at `0x5696da0` has addend `0x22a4500`, whose five-byte FDE tail-transfers to newly selected `0x1d8b750`. `task-relocation.tsv` retains the actual relocation bytes; this is not the original loader GOT. |
| Uncontended poll | For the constructed word `0xcc`, the selected task bit tests and compare-exchange request `0xc9` and choose index 0 of the four-entry table at `0x3bc94c`, which points at `0x1d8b7e7`. This is conditional on the state being unchanged and the compare-exchange succeeding. |
| Apply input | The selected poll calls `0x2017c80` with the task at `+0x20`. The bridge takes the word at its own `+0x20`, copies `0x3eb8` bytes from its `+0x28`, rebuilds the `0x3ec0`-byte span, and passes it to the prior low apply call. The word value 2 takes a distinct failure branch. |

The copy interpretation uses the previously established [memory-copy import binding](../foundation-reserve-grow-94/README.md). Under the relocation, dispatch, successful-copy, nonaliasing and no-intervening-mutation assumptions, that reconstructed span matches the host's constructor input; this does not prove that the input is the earlier loader's output. The task poll treats bridge tag 2 as a separate wait/state path, tag 3 as another route, and otherwise stages `0x3ac0` returned bytes and calls a result-publication boundary. The four targets and selected failure branches are retained without assigning source-language enum names or proving the scheduler's dynamic choices.

The builder's observed setup contains three agreeing count witnesses for 41, places the descriptor pointer in a vector, and initializes the result vector with length zero. The earlier builder's call to `0x25b7ef0` is a boundary. Selected continuation windows show its result-vector header copied from stack `+0x58` to `+0x230`, and the latter address supplied to the already identified digest-list hasher. The runner sets the output start to its current length times 32, constructs an input adapter, and calls `0x255d270`. The adapter passes minimum 1 and calls the newly studied `0x2289e30`. `transfers.tsv` records the new connection from the adapter to the partitioner; existing original-loader calls are not reproduced.

### Selected unwind ranges

| FDE start | Exclusive end | Bounded role on this path |
| --- | --- | --- |
| `0x4f7c290` | `0x4f7c83d` | Task submission, queue insertion, alternate state-byte and lock paths. |
| `0x22a4500`, `0x1d8b750` | `0x22a4505`, `0x1d8bbf1` | Task thunk and state-dependent poll into the prior bridge. |
| `0x2289e30` | `0x228a084` | Decide serial or split, construct two ranges, join their returned descriptors. |
| `0x251c2e0` | `0x251c415` | Visit 16-byte input pairs and write 32-byte callback results in order. |
| `0x1eacd90` | `0x1eace35` | Indirect callback at vtable offset `+0x18`, optional drop and free. |
| `0x2428460` | `0x24284e7` | Select a join path using the thread-local and pool checks. |
| `0x2404010` | `0x240468c` | Queue or run the other branch, wait for it, and return the two descriptors in their original positions. |
| `0x24a8800` | `0x24a8a4f` | Other-branch callback, result publication and status notification. |
| `0x241bd40`, `0x24276f0` | `0x241c033`, `0x24279d6` | Alternate dispatch wrappers. |
| `0x2490b20`, `0x24a59d0` | `0x2490df1`, `0x24a5d1d` | Wrapper callbacks that re-enter the join. |
| `0x2505660`, `0x2452e50` | `0x2505748`, `0x2452ec6` | Drop remaining pairs and the two split ranges. |
| `0x2456fa0`, `0x2456250` | `0x24570bc`, `0x2456368` | Cleanup of the two alternate-dispatch contexts. |
| `0x245f590`, `0x2453ce0` | `0x245f65e`, `0x2453d69` | Queued-job and tagged-result cleanup. |
| `0x1dd1db0` | `0x1dd1f6d` | Finish the list; the direct sentinel path returns without adding bytes. |

`functions.tsv` preserves all 10,864 bytes across these 20 intervals. The task thunk has no LSDA; the other 19 ranges do. The complete text of each range is evidence for the selected analysis, not a claim that all its operations and indirect callees are understood. `windows.tsv` distinguishes these ranges from the small `prior-context` windows.

### Partition, collection and failure choices

For input count `n`, `0x2289e30` computes `k = n >> 1`. If `k` is below the passed minimum, it uses `0x251c2e0`; on the non-thief arm, zero budget also selects that serial route. Otherwise it forms input ranges at the original pointer and at `input + 16*k`, and corresponding output regions at the original pointer and at `output + 32*k`. The selected underflow branches check the remaining input and output counts. For the initial 41 jobs, a taken split forms counts 20 and 21; the code need not take a split in every environment.

`0x2428460` uses an existing thread-local value directly when present; after its default lookup it either reaches the same join or one of the two wrappers. The join publishes the `0x24a8800` callback, calls the left partition and waits or works on queued callbacks. On the selected status-1 return, `0x2404318..0x2404342` places the left three-word result first and the other result second. The worker publishes its three-word result and a status before its notification branch. Scheduler identity, exactly-once dispatch, all concurrent interleavings and the semantics of the generic queue helpers are not proved.

The serial collector loads each input pair, invokes `0x1eacd90`, and then tests output capacity at `0x251c35a`. Thus a callback may have run before the capacity failure. On its successful arm two 16-byte stores write the callback's 32-byte result, the input advances by 16 and the output index by 32. A zero input count bypasses the callback. The indirect callback target is not resolved by this packet. The helper tests and may call a destructor and free the allocation; the remaining-pair cleanup handles unconsumed input on selected unwind paths.

After join, the partitioner compares `first_pointer + 32*first_third_word` with the second pointer. If equal, it adds the second and third words with separate unsigned-carry failure branches. If unequal, it returns the first three-word descriptor without those additions. Independently, the enclosing runner compares its returned count with the requested count at `0x25b7f97`; a mismatch takes the diagnostic path at `0x25b8002` instead of updating its vector length. This is not a claim that every malformed or nonadjacent descriptor necessarily trips that check.

**Conditional inference:** when the 41 input pairs and output ranges are valid and disjoint, each branch is dispatched and completes once, each callback returns normally, and the resulting descriptors are adjacent without word overflow, recursive splitting and the serial stores place input job `i` at output bytes `[32*i, 32*(i+1))`. The direct and reverse completion-order models in the tests check this positional arithmetic; they are synthetic and do not model the scheduler. `result-slots.tsv` lists the 41 resulting relative offsets, derived from the byte-read count and strides.

### Digest-list bytes and finalization

The [existing prefixed-hex proof](../RE-005-prefixed-hex-rust-94/README.md) binds the helper used by the prior list writer to lowercase `0x`-prefixed hex and a returned pointer/length. That proof requires valid disjoint buffers, nonempty input and sufficient capacity. Here the selected context establishes a 32-byte input, capacity 66, and mode zero; it then forwards the returned span to `0x25aa7f0`. The list input pointer advances by 32 for each successful entry. The [earlier marker study](../RE-009-evm-state-wire-94/README.md) supplies the array and string helper boundary; the selected bytes also expose their relevant marker decisions and stores.

For count 41, the array marker path chooses `dc` followed by the two-byte big-endian count. A 66-byte string takes the `d9` one-byte-length path; the helper's passthrough branch retains both marker bytes. Given the prior hex helper binding and successful nonaliasing writer calls, the complete digest-list input is therefore:

```text
dc 00 29 | (d9 42 30 78 <64 lowercase ASCII hex digits>)*41
```

It has `3 + 41*(2 + 66) = 2791` bytes. `result-slots.tsv` records each entry's relative offsets; it does not contain actual digests or a claimed captured preimage. The last entry ends at offset `0xae7`.

This is a complete byte shape only for the selected success path. The list writer checks the array-header result and every string-writer result before continuing. With count 41 it selects the direct path and initializes a local word to `0x8000000000000000`. The final handoff copies that word into the `0x1dd1db0` argument. At `0x1dd1dd1`, negating that word sets overflow, so the `jno` at `0x1dd1dd4` is not taken: the finisher writes result word `0x8000000000000004` and returns without a vector write. Its other arm calls the array helper and copies a buffered payload, with separate size, growth and error branches; that arm is not asserted for the 41-entry direct path. This distinction rules out an extra final marker only under the stated direct-path and nonaliasing assumptions.

The earlier [storage-root hash-site inventory](../RE-009-storage-state-roots/hashers.json) identifies the digest-list hasher's update and finalization calls. New context windows show the successful writer result check, the resulting buffer pointer and length passed towards that update, and the 136-byte rate and delimiter 1 setup. The prior builder study records how the resulting digest contributes to the computed app hash. This packet does not supply field values, a computed digest, or a target-execution fixture.

### Exception records

`lsda-headers.tsv` and `lsda.tsv` retain the 19 selected LSDA headers and 161 ULEB call-site rows. `failure-links.tsv` connects 17 selected call addresses to their actual covering ranges. Examples include the serial callback at `0x251c350` with landing `0x251c3e5`, the indirect callback at `0x1eacda1` with landing `0x1eace19`, the queue-grow call at `0x4f7c31f` with landing `0x4f7c77b`, and the finisher's buffered header call at `0x1dd1e02` with landing `0x1dd1f48`. Those landing paths contain cleanup and resume instructions. The task-poll, left-join and worker call rows have nonzero action selectors 5, 3 and 7; action tables, personality behavior and which landing paths execute are not decoded. These records do not establish transactional rollback or complete failure semantics.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo scope, compiler/linker settings, two-build result, binary comparison, masks, full helper/call-target/relocation closure and whole-ELF comparison: **not yet measured**. The static arithmetic examples are not target-generated data. No node or visor was executed. Existing Rust work on the separate hex helper is a cited dependency, not an implementation of this packet's runner or builder.

## Results and limitations

`summary.json` reports 20 selected FDEs, 84 byte windows, 64 selected conditional branches, 48 selected transfers, two task relocations, four task-table entries, 19 LSDA headers with 161 call-site rows, 17 selected failure links and 41 derived slot rows. These denominators describe the selected packet, not coverage of `abci` or of all branches in any FDE. The focused suite has 18 passing tests and no skips. It checks missing and wrong target inputs, the full artifact digest, every selected FDE body and window, each selected branch guard/opcode/displacement and transfer, task relocation and table corruption, FDE/index disagreement, LSDA corruption, invalid or NOBITS mappings, partition gaps and overlaps, carry boundaries and the successful preimage layout. Two independent hash-seed/time-zone regenerations under a Python-only PATH are byte-identical. Artifact verification and catalogue checking pass; the repository-wide unittest suite was not run under the stated memory constraint.

No ABCI progress gate is requested; the component remains 0/4. The original loader-to-builder object identity, intervening field mutations, actual scheduling and callback targets, complete exception actions, all 41 serializers, both other lanes, and begin/action/end-block behavior remain open. **Next question:** can a new, non-overlapping state and task handoff prove that the same successfully reloaded object reaches the low builder with the relevant fields unchanged?
