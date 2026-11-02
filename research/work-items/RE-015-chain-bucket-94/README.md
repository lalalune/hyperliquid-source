# RE-015: four-variant configuration map readers and global lookup

Two node #94 readers use the same four-variant key and string-map insertion path, while a global lookup with the corresponding node layout selects only the `NodeTestnet` and `Ee` configuration bytes; this makes their map representation, conditional lookup and distinct local failure paths concrete reconstruction decisions.

- Component ID: `constants`, task `RE-015`.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference supplies questions, not implementation text or ground truth.
- Claim status: observations are selected bytes, FDEs, relocations, local transfers, descriptors and modeled branch constraints. Map/string roles, connection to a particular configuration field and the effects of external helpers are inferences. End-to-end publication and target runtime behavior are unresolved.
- Scope included and excluded: twelve selected FDE extents, their complete admitted instruction partitions, the specific descriptors and relocation slots below, selected normal-flow propositions and five LSDA call-site tables. The existing `constants` work item owns the `static_config` and `cham` format suffixes, `NvTestnet` default and the full 76-name table; those bodies and that table are not resubmitted. Previously analyzed callers, shared string readers, allocators, tree split/rebalance, initializers, dynamic drops, #115, visor and the rest of the node are boundaries.

## Reproduce

Run from the repository root after adding the new files in this packet. The observed environment was Linux x86-64 and Python 3.12.3. The collector uses the repository ELF/FDE/ULEB readers and Python standard library only; it verifies the complete target SHA-256 before parsing, does not execute the target, and does not invoke a disassembler, a subprocess, networking or system time.

```sh
python3 tools/config_chain_bucket94.py --out research/work-items/RE-015-chain-bucket-94
python3 -m unittest tests.test_config_chain_bucket94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-chain-bucket-94 && sha256sum -c MANIFEST.sha256)
```

For the independent determinism check, substitute two distinct writable **relative** directories for the placeholders. Both collector runs and the focused tests also work with a PATH containing Python but no binutils.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_chain_bucket94.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/config_chain_bucket94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The generated files and their hashes are in `MANIFEST.sha256`; each is reproduced byte for byte by the collector. Inputs to the synthetic prefix, name and byte-domain models are explicitly test cases, not captured executions.

## Evidence

Addresses are linked ELF virtual addresses, not runtime addresses. `functions.tsv`, `instructions.tsv`, `contracts.tsv`, `tables.tsv`, `names.tsv` and `lsda-headers.tsv` preserve file offsets where applicable. The admitted x86 encoding reader partitions each selected FDE from its first through its last byte, checks direct intra-FDE branch targets, and validates selected jump-table targets and LSDA boundaries against instruction starts. These checks do not establish a whole-program function census. No normalization masks are applied.

| Selected FDE | Bounded role and important edge |
| --- | --- |
| `0x13aa4e0` | Binary optional-map wrapper; null marker returns two zero words, otherwise calls `0x13b8610`. |
| `0x13b8610` | Binary map reader; key `0x13aa2f0`, value reader `0x13bdcd0`, insertion `0x14cbb80`. |
| `0x13bdcd0` | Binary value reader; dispatches selected length-prefixed string and byte slices to separate helper boundaries. |
| `0x13aa2f0` | Binary enum-key gate; one-entry map goes to `0x13f3dd0`, other markers delegate to earlier reader `0x13baf20`. |
| `0x13f3dd0` | Four-way binary key/unit handling; successful unit marker is `0xc0`. |
| `0x1441ba0` | JSON optional-map adapter; distinguishes a `null` prefix, a delegated map and an error result. |
| `0x14ba930` | JSON map reader; key envelope `0x13f3580`, external string reader `0x14be0f0`, insertion `0x14cbb80`. |
| `0x13f3580` | JSON enum envelope; admits quoted and object forms, with distinct dispatch tables. |
| `0x14b6c10` | Quoted key adapter; calls the selected classifier at `0x13f41a0`. |
| `0x13f41a0` | Classifier with four exact byte/length comparisons and a length-delimited error descriptor table. |
| `0x14cbb80` | Shared insertion and replacement; external helper handles nonempty-node split/rebalance. |
| `0x1404ef0` | Configuration-byte selection and lookup through a global map-shaped object; returns an owned copy or an absent sentinel. |

The descriptor load in `0x13f41a0` resolves to the four full 16-byte entries beginning at `0x5668248`. `names.tsv` records the complete on-disk descriptor bytes, RELATIVE addend, exact text bytes, length and file offsets: `Local`/0, `Sandbox`/1, `Testnet`/2 and `Mainnet`/3. The instruction comparisons, return codes and descriptors agree. They are a four-value domain, distinct from the earlier `AwsName` domain. The three `AwsName` entries retained here are only those needed for this lookup: `NodeTestnet`/5, `Ee`/17 and the prior `NvTestnet` default/32.

The JSON optional-map adapter `0x1441ba0` skips space, tab, newline and carriage return, recognizes the four-byte `null` prefix with result tag 0, and delegates other leading bytes to the JSON map reader. Map success becomes tag 1; a map error, malformed `null` prefix or truncated `null` prefix becomes tag 2. Malformed and truncated null prefixes construct local error codes 9 and 5, respectively. The adapter itself returns after four null bytes; complete-document or trailing-input checks belong to the caller. `json-option-prefix-cases.tsv` records 20 static prefix cases.

The JSON map caller checks for a quote at `0x14baacf` before calling the enum envelope at `0x14baadc`. Thus the envelope's separate object-shaped alternative exists in its own code, but is not selected by this map caller when that guarded cursor is unchanged. The reader checks an opening brace and a colon and records distinct local error codes for exhaustion (5 or 3 at different positions), missing comma (8), trailing comma (21), key syntax (17), colon (6) and a depth limit (24). The exact branch sites, not an inferred serde implementation, are in `contracts.tsv` and `branches.tsv`.

On the binary side, the optional wrapper normalizes a freshly read marker into a class and payload. `marker-cases.tsv` records all 256 raw byte cases. For `0xc1` through `0xdf`, the wrapper leaves the prior cached payload byte in place; `0xc0` takes the null branch. This model covers fresh-marker processing, not arbitrary invalid cached state. The key gate admits a one-entry fixed map, 16-bit map or 32-bit map; longer length forms are big-endian. A complete non-one count returns local tag 4 with the count. With an incomplete length prefix it consumes the remaining prefix and delegates to the existing scalar reader; `binary-key-prefix-cases.tsv` retains 38 static boundary cases, not executions.

The binary map calls `0x13bdcd0` with flag 1. Its selected marker tables route fixed string-like lengths and the `0xd9`/`0xda`/`0xdb` length forms to a bounded slice check, while `0xc4`/`0xc5`/`0xc6` forms reach a separate value-building boundary. Multi-byte lengths are read big-endian. A truncated length prefix consumes the remaining prefix bytes and returns tag 1; an excessive declared payload returns tag 1 without consuming that payload. The valid-length string-like path advances the cursor by the declared length before the slice checker; the checker and value builders remain external. `binary-value-prefix-cases.tsv` contains 27 modeled controls, including zero, short and maximal encoded lengths. These models stop at the helper boundary and do not assert Unicode validation or target execution.

Both map readers call `0x14cbb80`. The selected node has a 16-bit count at `+0x112`, key bytes beginning at `+0x114`, values at a 24-byte stride and child pointers at `+0x120`. An empty insertion requests `0x120` bytes; an equal key copies out the old 24-byte value and replaces it without the collection-length increment at `0x14cbd07`. A new insertion reaches that increment. Each caller checks the old-value sentinel and zero before the same relocated cleanup slot; helper semantics and the split path are external boundaries.

The global lookup reads the configuration byte at `+0x48`: 5 selects key 2; 17 selects key 3; every other byte takes the absent-result branch. The address pairs in `relocations.tsv` bind its two lazy objects to the previously analyzed initializer boundaries and bind an already documented consumer slot to `0x1404ef0`. If the selected map tag is not 1, its root is null or the key is absent, the local result starts with `0x8000000000000000`. On a hit, the routine uses the relocated allocation boundary and the imported `memcpy` symbol to make a separate value; a zero-length result uses pointer 1. The prior default of 32 therefore selects absence **if that default is the byte actually present**. `indirect-slots.tsv` retains relocation types and addends or symbol names for RIP-relative transfer sites; it does not close their implementations.

| Selected condition | Local evidence and limits |
| --- | --- |
| Binary key or value reader returns an error | The two error arms call the map cleanup boundary and reach the common epilogue without a local 16-bit store through the selected depth-field operands. This says nothing about effects inside the external cleanup. |
| JSON key or value reader returns an error after entering the object body | The normal-flow graph reaches the close call only through the local depth restore; accumulated entries pass through the drain boundary. Earlier depth-limit exits have separate paths. |
| Earlier JSON parse error plus closing error | The earlier-result test is before the closing-error branch; the later error's cleanup is a separate path. Effects inside external error/drop helpers remain unresolved. |
| Insertion finds an equal key | The replacement arm returns without traversing the new-entry length increment; the old value is handed back to its caller. |
| Global lookup misses | Unsupported name, absent map, null root and unsuccessful search lead to the same local sentinel; lazy-initializer and allocation failures are separate external calls. |

`cfg-propositions.tsv` contains 19 bounded graph queries, with witnesses for reachable paths and forbidden sites for absence queries. Conditional branches are deliberately over-approximated; external calls are assumed to return, exceptional edges are not included, and absence queries reject an encountered unmodeled indirect jump. A structural witness is not proof of a feasible input. `exception-sites.tsv` separately records 42 selected call-site ranges from five LSDA tables and their raw record bytes; action/type-table semantics and personality execution are not interpreted.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker flags, two-build comparison, fixture replay and binary equivalence: not yet implemented/measured. Helper bodies, indirect call effects, type-table actions, relocations outside the listed slots, vtable/data closure and whole-ELF comparison remain open. There are no normalized comparisons or masks. The name and marker probes are finite static models checked against pinned target instructions and corruption controls; they are not target-grounded runtime traces.

## Results and limitations

The generated summary covers 12 selected FDE ranges, 9,496 bytes, 2,393 admitted instruction encodings, 420 direct branches, 136 call/indirect-transfer sites, 376 selected store/update sites, 213 byte contracts, 530 slots in eight selected jump tables, 49 RIP-relative indirect-transfer slots, 256 fresh-marker cases, 38 key-prefix cases, 20 JSON option-prefix cases, 27 binary-value prefix cases, 19 structural propositions and 42 LSDA ranges. These are denominators for this selection only, not coverage of the component or node. Thirty-five focused tests passed with no skips, including corrupted digest, code, ranges, relocations, symbol, jump table, LSDA and CFG edges; 208 single-bit spelling mutations are abstract classifier controls. Two independent outputs matched byte for byte with different hash seeds/timezones and a Python-only PATH. Artifact verification, catalogue checking and inventory/literal reproduction passed.

The two readers' identical insertion target and the global accessor's matching layout support a common map type, but do not alone prove that either reader populates the exact global instance. A separate routing analysis proposes the field name `chain_to_replica_s3_bucket`; its caller and publication must be independently integrated before that association is treated as established. No Rust recovery, target execution, exact source identity, full path closure, component completion gate or equivalence is claimed. Current public upstream/PR freshness was not independently refreshed; the available repository and PR snapshot were checked. Next: establish the owning field's reader-to-global publication edge against the current merged ownership map, then close the external readers, split and cleanup behavior without duplicating their existing packets.
