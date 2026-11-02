# staking: validator L1 vote bucket insertion and cleanup in node 94

This packet establishes how a validator L1 vote bucket's two owned address-set descriptors move into a 48-byte tree value, how a full node propagates a split, how a later bounded scan handles its results, and how normal and exceptional cleanup hands the descriptors to the set destructor, allowing a reconstruction to preserve both the cursor and ownership boundaries.

- Component ID: staking, validator lifecycle and voting.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference tree was a lead only; no reference implementation is copied.
- Claim status: observation for the checked bytes, unwind records and bounded interpreter results; inference for the connection between the two descriptor fields and the previously named voter and listed sets. Unresolved behavior is below.
- Scope included and excluded: seven previously unselected FDE ranges for the inner bucket insertion, a bounded post-vote scan, three pair cleanup wrappers, an optional-pair wrapper, and the remaining-row cleanup loop. The previously studied vote handler, entry adapter, bucket-map destructor, set destructor and iterator are context or simulated boundaries only. Search, duplicate detection, real allocator, real unwinding, economic semantics, node #115 and all live execution are excluded.

## Reproduce

From the repository root on Linux x86-64, with Python 3.12.3 and the authenticated target present:

```sh
python3 tools/artifacts.py verify
python3 tools/staking_vote_bucket94.py --out research/work-items/staking-vote-bucket-lifecycle-94
python3 -m unittest tests.test_staking_vote_bucket94
(cd research/work-items/staking-vote-bucket-lifecycle-94 && sha256sum -c MANIFEST.sha256)
```

For two independent regenerations, replace the placeholders with fresh writable directories:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_vote_bucket94.py --out <tmp-dir-1>
PYTHONHASHSEED=9281 TZ=Pacific/Honolulu python3 tools/staking_vote_bucket94.py --out <tmp-dir-2>
diff -r <tmp-dir-1> <tmp-dir-2>
```

The tool checks the complete input digest first, uses `tools/elf_index.py` and `tools/fde_extents.py` for ELF sections and FDEs, rejects non-file-backed mappings, and reads call-site records, relocations and fixed instruction patterns directly from ELF bytes. It starts no external program. The bounded instruction evaluator is adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`. It interprets selected bytes over synthetic memory, not a node process. Allocation, copying, the set destructor, the outer iterator, failure sinks and unwind resume are modeled boundaries. `MANIFEST.sha256` covers this README and all generated evidence files.

## Evidence

All addresses are linked ELF virtual addresses; file offsets and exact body hashes are in `functions.tsv`. The ends are exclusive FDE extents, not a whole-program function census. `instructions.tsv` is a linear decode of the selected extents; rows in an unvisited region are not independently proved reachable. The generated branches, direct and indirect transfers, relocations and LSDA call-site ranges are retained separately. No operands are masked.

| Selected role | FDE interval | Question answered |
| --- | --- | --- |
| Inner value insertion | `0x2f51d80..0x2f52944` | How are a supplied gap, split and returned cursor handled? |
| Pair cleanup | `0x3376ce0..0x3376d1c` | In what order are the two descriptors handed off? |
| Pair cleanup copy | `0x2f07b30..0x2f07b6c` | What cleanup is called by insertion landing paths? |
| Promoted-pair cleanup | `0x2f07e00..0x2f07e3c` | What cleanup is called for a second insertion landing path? |
| Optional pair cleanup | `0x3999190..0x39991dd` | What does the presence byte gate? |
| Remaining-row cleanup | `0x3378b40..0x3378bd0` | How are remaining values visited after a cleanup failure? |
| Bounded pointer collector | `0x3bd9ca0..0x3bd9fb1` | What is collected, and what are its failure boundaries? |

`context.tsv` pins six direct transfers, including the earlier vote-store call to its adapter, the adapter's call to the selected insertion, its exceptional call to pair cleanup, the vote and bucket cleanup calls to the selected wrappers, and the call to the bounded collector. The adapter and the external set destructor appeared as stubs in the prior validator-vote packet; neither is selected or interpreted here. The earlier `staking-validator-l1-vote-94` packet identifies a bucket with voter and listed address sets, and `staking-validator-vote-prune-94` identifies a bucket-map cleanup boundary. The association of those names with the two 24-byte descriptors is an inference from those earlier observations and the matching call and value layouts, not a type name recovered from a symbol. That earlier packet also infers a zero-sized key, so a well-formed ordered map would have at most one such key. The multi-entry and split fixtures below are structural and corruption controls; they do not establish that a valid node state can reach a split.

### Insertion and split

The selected helper receives an existing leaf cursor, a pointer to one 48-byte payload, and access to the root descriptor. The payload is copied opaquely. A node has its parent pointer at `+0x210`, its parent edge and count as 16-bit words at `+0x218` and `+0x21a`, and its children at `+0x220`. Payloads use a 48-byte stride from node `+0`. The leaf and internal allocation requests are `0x220` and `0x280` bytes. The helper does not increment the enclosing map length in the tested cases; the caller must do so if its contract requires it.

A leaf with fewer than 11 values inserts at the supplied gap. If it is full, the incoming gap selects an **old** value to promote:

| Incoming gap | Promoted old slot | Left / right values after insert |
| --- | --- | --- |
| 0 through 4 | 4 | 5 / 6 |
| 5 | 5 | 6 / 5 |
| 6 | 5 | 5 / 6 |
| 7 through 11 | 6 | 6 / 5 |

A full parent can propagate a second split and a new root. `leaf-cases.tsv` covers every size and gap of a leaf; `deep-cases.tsv` checks all gaps under several parent sizes and selected two-ancestor cascades. Independent sequence and tree-shape models check the bytes, parent backlinks, child edges, allocation sequence and returned cursor. The payloads are synthetic opaque values; the cases do not establish search order or how a valid gap is found.

### Bounded scan after a vote

The context pins at `0x3946914..0x394691d` read the bucket-map length and skip this scan when it is below `0x65`. Otherwise the caller passes limit `0x64` to the selected collector at `0x3bd9ca0`. The collector allocates space for `min(length, limit)` pointers and walks the supplied tree in order, producing the node address plus `0x16c` for each row. The pointer targets are not dereferenced or copied by this function. The caller tests the vector allocation and releases it; the pinned continuation does not consume the pointers. This is a conditional allocation and walk even though the collected vector is discarded.

The earlier zero-sized-key inference would make the 101-row threshold unreachable for a well-formed map. The 99-, 100- and 101-row inputs in `scan-cases.tsv` are deliberately synthetic duplicate-key structures used to exercise the machine-code boundary, not valid chain states. Other fixtures cover limit zero and small trees. `scan-failures.tsv` records the modeled allocation-failure, inconsistent-length and allocation-size-overflow boundaries. The test does not prove that the real allocator or failure routine unwinds.

### Descriptor cleanup

The three pair wrappers each call the external set destructor with the first descriptor and then tail-transfer the second descriptor at offset `+0x18`. The optional wrapper tests byte `+0`: zero makes no destructor calls; nonzero calls the same external destructor with offsets `+0x08` and `+0x20`. The loop uses the external iterator, computes `node + index * 0x30`, and hands off the two descriptors in order until the iterator returns no row. `drop-cases.tsv` and `remaining-cases.tsv` check the exact argument bytes and order, with both dependencies simulated. They do **not** test the destructor's internal tree traversal, freeing, or iterator ownership behavior.

`chain-cases.tsv` composes actual insertion interpretation with an explicit, projected call to the pair wrapper on the returned payload. The result checks the descriptor bytes and handoff addresses across each leaf gap. It does not claim that the binary calls that wrapper immediately after an insert; actual removal and iteration remain in the previously studied caller.

### Failure and exceptional edges

The four injected cases in `failure-cases.tsv` stop at the recorded failure call and associate it with the FDE's LSDA call-site table. In particular, leaf allocation failure at `0x2f527fa` maps to `0x2f52894`; its landing calls the pair-cleanup copy on the input payload before the unwind-resume boundary. Root allocation failure at `0x2f52823` maps to `0x2f5287c`, whose bytes are `0f0b` (`ud2`). The remaining controls cover a missing root and a height overflow. Whether the real failure routines abort or unwind, and the actual saved register and stack state, are not established.

`landing-cases.tsv` separately starts each of six LSDA-selected landings with explicitly projected live registers and an artificial exception token. The instruction evaluator verifies the descriptor addresses passed to the simulated destructor and that the token reaches the simulated unwind-resume boundary. A first-destructor failure in each pair wrapper triggers the second-descriptor handoff in that projection. A further destructor failure is represented in the LSDA table by a nonzero action; the action chain and real termination behavior are not decoded or executed here.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, compiler/linker settings, independent binary comparison, relocation normalization, target runtime fixtures, or whole-ELF result is claimed. The independent models cover finite synthetic tree shapes and verify the selected instruction semantics against those shapes. The iterator and destructor hooks record calls and arguments but do not implement their target bodies. The x86 evaluator, allocator and memory-copy hooks are models, and do not establish target behavior under arbitrary memory or allocation failures.

## Results and limitations

- Seven FDE windows contain 943 linearly decoded instruction starts and 67 conditional sites. The insertion fixtures reach 539 of its 629 decoded starts, all 38 conditional sites and both outcomes at 26 of them. The bounded collector reaches 146 of its 195 decoded starts and both outcomes at 11 of its 26 conditional sites. `coverage.tsv` gives the per-function denominator, including the projected landing cases. These counts are limited to the selected windows and fixtures.
- The generator checks 78 leaf cases, 480 multilevel cases, 78 projected insertion-to-cleanup cases, seven pair cases, five remaining-row cases, six projected landing cases, 48 bounded-scan cases, four insertion and three scan failure-boundary controls, and six rejected byte mutations. The focused suite passed 25 tests without skips and with binutils absent from `PATH`.
- The byte mutations change the full-node threshold, a descriptor offset, the option-presence branch, the remaining-row stride, the collector minimum selection and its pointer offset. Separate tests reject a wrong digest, a changed body, a non-start FDE address, unmapped and NOBITS addresses, a range crossing a section boundary, a malformed LSDA header and an absent relocation.
- No component progress gate is requested. Actual allocator and unwinder behavior, cleanup after the second destructor itself fails, real set deallocation, the remaining iterator's internals, the zero-sized-key invariant, arbitrary-height trees, live state reachability and #115 remain unproved.

Next question: independently reconstruct the bucket search and vacant-entry adapter, and join its returned cursor and ownership rules to this insertion without assuming the search's duplicate-key behavior.
