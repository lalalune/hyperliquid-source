# RE-017: fast-worker nonce view and conditional queue delivery

This packet shows how the state-pointer argument of the previously identified fast worker produces a filtered address-to-nonce view, places it in a queued record, and can be read by a matching queue receiver when both sides share the same object; this gives a reconstruction concrete selection, empty-value, ordering, and delivery rules.

- Component ID: `abci`, RE-017; one partial state-loader result-handoff path.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: project `e5c9b6436876b2a4a39daef813171f9879317699`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not copied implementation or evidence.
- Claim status: the instruction and data facts below are observations; named application fields, set interpretation, and cross-object links are explicitly conditional inferences. The node was not run.
- Scope included and excluded: 14 newly selected FDE extents and seven short context windows in the previously studied worker. The original Location-bearing loader, its calls and GOT entries, the original parent worker, and previously owned helpers remain boundaries. This does not claim the complete begin/action/end-block path or state-root algorithm.

## Reproduce

From the repository root, with Python 3.10 or newer, the shared repository parsers, and the authenticated #94 capture present:

```sh
python3 tools/artifacts.py verify
python3 tools/abci_reload_nonce_view94.py --out research/work-items/RE-017-abci-fast-nonce-delivery-94
python3 -m unittest tests.test_abci_reload_nonce_view94
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 -c 'import os,sys; os.environ["PATH"]=""; os.execv(sys.executable,[sys.executable,"tools/abci_reload_nonce_view94.py","--out","work/nonce-delivery-a"])'
PYTHONHASHSEED=719 TZ=Pacific/Honolulu python3 -c 'import os,sys; os.environ["PATH"]=""; os.execv(sys.executable,[sys.executable,"tools/abci_reload_nonce_view94.py","--out","work/nonce-delivery-b"])'
diff -r work/nonce-delivery-a work/nonce-delivery-b
(cd research/work-items/RE-017-abci-fast-nonce-delivery-94 && sha256sum -c MANIFEST.sha256)
```

The evidence was generated on Linux x86-64 using Python 3.12.3. The script verifies the entire input digest before creating output, uses `tools/elf_index.py` and `tools/fde_extents.py`, and reads the selected instructions, section records, relocations, LSDA call-site records, and data directly from ELF bytes. It rejects NOBITS or ambiguous VA mappings, unsupported LSDA encodings, changed extents, bytes, transfers, operands and relocations. It neither executes the capture nor invokes an external program. The test uses private copy-on-write mappings for corruption controls. Human inspection used GNU objdump 2.42 with `-d -M intel` and explicit ranges; its output is not parsed by the producer or tests.

The ten generated evidence files are `functions.tsv`, `windows.tsv`, `transfers.tsv`, `relocations.tsv`, `operands.tsv`, `data.tsv`, `lsda-headers.tsv`, `lsda.tsv`, `lsda-witnesses.tsv`, and `summary.json`. Full selected extent bytes are in `functions.tsv`; short relevant slices, including the prior-work connections, are in `windows.tsv`. The manifest also covers this README. VAs throughout are unrelocated ELF virtual addresses; the TSVs separately give file offsets resolved through file-backed sections. FDE and LSDA ends are exclusive. Curated instruction starts are not a census of all calls or control-flow edges.

## Evidence

### Boundaries and selected function map

The [original state-link packet](../RE-017-abci-state-link-94/README.md) binds the `state.rs` Location-bearing path. The [round-clock packet](../staking-round-clock-94/README.md) follows its reload into a host. Open PR #1684 traces the conditional loader-derived aggregate, closure and guard into worker `0x4548cc0`; those previously recorded calls and GOT entries are dependencies, not re-owned here. The seven `prior-context` windows merely show new input and output connections in that worker. In particular, the connection assumes the earlier copies, callback dispatch and guard reach this path with the intended object.

| Selected FDE start | Exclusive end | Observed role |
| --- | --- | --- |
| `0x3423840` | `0x34239a8` | 20-byte key hash-table probe and lazy default selection |
| `0x3431820` | `0x343186e` | lazy-descriptor method and indirect initializer call |
| `0x3432790` | `0x34327de` | second lazy-descriptor method and indirect initializer call |
| `0x3438e50` | `0x3438e63` | write zero to initializer result words 0 and 2 |
| `0x428c750` | `0x428d07a` | build a 20-byte-keyed tree of 24-byte values |
| `0x4451aa0` | `0x4451e7a` | collect 20-byte keys and construct the exclusion tree |
| `0x4488d70` | `0x4488e8b` | large-record-sort buffer wrapper |
| `0x4553420` | `0x4553654` | receive wrapper, retry, and result copy |
| `0x4888e80` | `0x488984a` | two-cursor collection, exclusion lookup and value clone |
| `0x489ea70` | `0x489ec09` | collect records, sort when needed, construct result tree |
| `0x4913c10` | `0x4913d14` | small-record insertion sort using 20-byte comparisons |
| `0x4ada600` | `0x4ada7ef` | coalesce adjacent equal 20-byte keys |
| `0x4b45f20` | `0x4b460fa` | read a published queue slot or return a status tag |
| `0x4b47900` | `0x4b47b05` | reserve, copy and publish a queue slot |

An FDE is a validated unwind extent, not a proof of a source-function boundary. The existing cursor, clone, allocation, comparison, hash, bulk-builder and cleanup helpers are call boundaries; their bodies are not re-owned. In particular `0x4895050`, `0x49478b0`, `0x497b9b0`, `0x497e070`, `0x3bb27c0`, `0x428d080` and `0x4913410` have prior evidence or open work.

### Input selection and collection

The prior worker packet records its second argument saved in `r13`; that existing instruction is not regenerated here. The `parent_exclusion` window constructs an input from fields at `r13+0x1450` and `r13+0x1458` and calls `0x4451aa0`; the result is at stack `+0x3c8`, whose pointer is saved in the later composite at `+0x90`. The `parent_first` and `parent_source_b` windows record a separate root/depth/count triple at `r13+0x14b0/+0x14b8/+0x14c0`, followed by fields at `r13+0x14c8/+0x14d0/+0x14d8` and the prior helper `0x3bb27c0`. The `parent_composite` window puts the first cursor at composite `+0`, the second at `+0x48`, the exclusion pointer at `+0x90`, and `r13` at `+0x98`. At `0x4549e72`, the worker calls `0x489ea70` with that composite. These stack relations are observations about this path, not proof of loader-object identity.

`0x4451aa0` multiplies the selected count by 20 with overflow and sign checks, walks keys in 20-byte steps, selects a small or large sort at the 21-record threshold, and passes its buffer into the previously studied bulk builder `0x428d080`. A zero-byte path returns a null root and zero count. The middle result word is not written on that empty path. The newly selected builder's recorded failure paths include null allocation and inconsistent tree traversal.

The record collector first tries the cursor at input `+0` via `0x4895050`. After that cursor is exhausted it reads the cursor at `+0x48` via `0x49478b0`. For the latter, it searches the pointed-to `+0x90` tree with 20-byte comparisons through the already known `memcmp` slot; equality branches back to fetch another second-cursor key. The collector uses input `+0x98` plus `0x4150` as the first argument of the lookup at `0x4889035` and `0x48895ba`. The symbol-zero `R_X86_64_RELATIVE` relocation for slot `0x5774668` has addend `0x3423840`; this is a static binding, not evidence of runtime dispatch.

At the lookup return, a zero word at `+0x10` leads to a result with root and count zero. A nonzero word requires a nonzero root before the prior clone helper `0x497b9b0` is called; a zero root takes the recorded diagnostic call and `ud2` path. The two lookup instances and their distinct error branches are retained. On the collector's no-candidate path its output triple is `0, 8, 0`; this differs from the tree builder's empty return, which writes only words 0 and 2.

### Lookup, empty default, sorting and tree building

`0x3423840` reads the table count at argument `+0xa8`, control pointer at `+0x90`, mask at `+0x98`, and hash seed context at `+0xb0`. It probes 16 control bytes at a time; its candidate address computation uses a `0x30`-byte stride. The 20-byte equality test compares a 16-byte vector and a separate 4-byte vector, combines their comparison masks, and requires `0xffff`. The hash helper is a prior-work boundary.

If no row is found, the lookup selects storage at `0x5786170`, subject to the lazy-initialization state at `0x5786188`. `data.tsv` gives the initial file bytes, before relocations and initialization. The descriptor at `0x56eb448` has relocations to `0x3432790` and `0x3431820`; both wrappers indirectly call the stored initializer and copy its three words. A separate RELATIVE relocation places `0x3438e50` into the initial default storage. If that initializer is selected and completes normally, it writes zero to result `+0` and `+0x10`; the middle word is unspecified. The exact runtime Once state and indirect call selection remain unobserved.

`0x489ea70` returns a null root and zero count when collection yields no rows. For one record it skips sorting. For 2 through 20 it calls `0x4913c10`, which moves `0x30`-byte records when the 20-byte comparison is negative; for 21 or more its slot `0x5776760` has a RELATIVE relocation to `0x4488d70`. The latter sets a temporary capacity to `max(min(n, 0x28b0a), n - floor(n/2))`. Capacities below `0x56` use stack storage; larger ones pass `0x30` times capacity to the allocator after the recorded bound check. It calls `0x4dc76d0`, whose sorting semantics are an unresolved boundary, and has a null-allocation and unwind path. Thus the packet establishes the large-branch wrapper and binding, not the full large-sort algorithm.

For a nonempty result, the caller allocates a `0x1f0`-byte initial tree node and calls `0x428c750`. The builder inserts 20-byte keys and 24-byte values, uses an 11-entry node threshold, and allocates `0x250`-byte internal nodes on a growth path. Its iterator helper `0x4ada600` compares adjacent 20-byte keys using the vector mask and, on equality, calls the prior drop helper on the preceding value before moving to the next one. On a sorted input this coalesces each adjacent equal-key run and retains its last value. Whether the large sort actually supplies the required order depends on the unresolved helper.

### Queue publication and matching receive path

The `parent_result` and `parent_publish` windows show the returned 24-byte tree triple copied to stack `+0x220..+0x238`, then a `0x148`-byte payload copied from stack `+0xf8` and prefixed by one word before the call at `0x454a4a3` to `0x4b47900`. If the branch reaches those copies and no intervening alias or call changes these bytes, the triple is at payload `+0x128..+0x140`, hence at full queued record `+0x130..+0x148`. This remains inside the `0x150`-byte record.

The producer reserves an index with `lock xadd`, uses the low five bits for a slot, and maintains blocks with metadata at `+0x2a00`, `+0x2a08`, `+0x2a10`, and `+0x2a18`. It can allocate a `0x2a20`-byte block, link it with `lock cmpxchg`, copy `0x150` bytes to the selected slot and set that slot's bit with `lock or`. Overflow and allocation-failure branches call failure helpers and reach `ud2`. A shared copy slot is an existing dependency, not a newly claimed GOT binding.

The new receiver `0x4b45f20` uses the same block metadata and `0x150` slot stride. If the current published bit is set, it copies the complete record to its result; a copied tag below 2 advances the reader index, while a tag at least 2 does not. If the bit is clear, bit 33 selects result tag 2 or 3; an absent next block also yields tag 3. The new wrapper `0x4553420` passes its core's `+0x80` as the shared queue argument, handles 2 and 3 separately, retries after the first 3, and copies `0x150` bytes to its caller for the non-2/non-3 arm. Its reference-count subtraction has a recorded failure branch.

**Inference:** if the producer's core pointer equals the receiver wrapper's core pointer, the producer's `[core+0x80]` and receiver's `[core+0x80]` identify the same queue and a successfully read ordinary item preserves the triple at result `+0x130..+0x148`. Matching layout and offsets alone do not establish that pointer equality, scheduling, publication ordering across all threads, or any downstream consumer's application of the value.

### Interpretation and branch controls

**Inference:** under valid cursor and tree invariants, with stable inputs and the established comparison helper, the candidate keys have the set form `A union (B minus C)`, where A is the first cursor, B the second and C the exclusion tree. After the observed small sort and adjacent coalescing, the result maps each selected key to the corresponding cloned value; an absent lookup supplies an empty root/count. Tests of this set equation are synthetic controls, not runs of the node.

The earlier [nonce lifecycle packet](../bridge-nonce-lifecycle-94/README.md) identifies `address_to_nonce_set` at state `+0x3760` in one layout and `+0x41e0` in a layout shifted by `0xa80`; its [field table](../bridge-nonce-lifecycle-94/tracker-fields.tsv) records the lower-layout label. This packet independently finds a lookup at `0x4150 + 0x90 = 0x41e0` from the worker state argument. **Inference:** the matching offset and bucket shape make that field identification plausible for this path. They do not prove the worker argument is the earlier packet's state object or that every stored value is a nonce set.

| Condition | Observed selected branch or outcome |
| --- | --- |
| Both cursors empty | Collector returns triple `0, 8, 0`; outer view writes root and count zero. |
| Second-cursor key compares equal to exclusion key | Return to the second cursor without adding that key. |
| Lookup value count zero | Construct empty root/count for the record. |
| Lookup count nonzero, root zero | Branch to a diagnostic helper and `ud2`. |
| One, 2–20, or at least 21 collected rows | Skip sort, call small sort, or call the relocated large-sort wrapper, respectively. |
| Tree node allocation fails | Call the recorded allocation failure slot and reach a trap. |
| Queue slot unavailable or closed | Receiver emits status tag 3 or 2 according to its selected bit/next-block branch. |
| Queue result available | Copy `0x150` bytes; increment the reader index only if the copied tag is below 2. |

The LSDA tables cover only the selected seven FDEs which actually carry LSDAs. For example, lookup and clone calls in the first collector pass lie in the call-site range with landing `0x48897b3`; the second pass lands at `0x48897a6`. The large sort helper has landing `0x4488e6c`, and the receive-wrapper calls have landing `0x4553638`. `lsda-witnesses.tsv` associates selected call instructions using the final instruction byte as a PC witness. This is static table membership, not proof that an exception occurred or a full interpretation of action selectors.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency scope, compiler/linker flags, two-build results, raw and normalized binary comparisons and masks, helper/call-target/data/relocation closure, and runtime fixtures are **not yet measured**. The synthetic tests check arithmetic, conditional models and corruption handling only; they do not execute node instructions or establish target equivalence. No captured node or visor, network, keys, chain actions, or private runtime state were used.

## Results and limitations

The producer emits 14 selected FDE extents covering 9,375 bytes; 41 windows including seven prior-context windows; 83 curated transfer/LEA sites; five relocations; 21 extracted operands; three data records; seven LSDA headers with 61 call-site rows; and 29 call-site witnesses, 13 with nonzero landing pads. These are selected-scope counts, not node-wide coverage. The focused suite has 40 passing tests and zero skips, including bad input digest before output, modified FDE bodies and bounds, branch retargeting, wrong relocation and initializer data, invalid and NOBITS mappings, altered LSDA records, threshold and 20-byte comparison controls, queue status controls, and deterministic regeneration.

The earlier loader and worker identity remain conditional; the receiver's object identity is unproved; the large-sort inner helper, some action tables, shared helpers, runtime concurrency, and downstream consumer are unresolved. Begin/action/end-block behavior and state-root inputs are not established. Node #115 and visor are distinct targets. No milestone gate is requested; `abci` remains 0/4.

Next question: prove the queue core's alias and the caller that consumes the `+0x130` tree, then connect that consumer to independently identified block execution or state-root inputs without re-owning the existing loader or stream inventory.
