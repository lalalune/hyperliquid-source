# RE-021: map node 94 address-keyed state overrides before precompile execution

This packet makes address-keyed overrides reconstructible from a selected node 94 request through 20-byte key and account-field parsing, cache updates, failure handling, and conditional handoff of the same cache object to the engine builder.

- Component ID: `evm`, continuing the BLAKE2b precompile question in `RE-021-blake2b-compress-94`; RE-021 is not a row in the official task table.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not implementation source.
- Claim status: **observed** for file bytes, decoded selected operands, FDE intervals, call targets, branch destinations and relocation records; **inferred** for source-level field and cache roles and the conditional path composition; **unresolved** for the router, external decoders and callbacks, registry mutation and native behavior.
- Scope included and excluded: the selected argument-to-map parser, its 20-byte key adapter, six account fields, duplicate and value-error branches, map replacement, account and code cache publication, two storage application arms, and a request-to-writer caller through an engine-builder handoff. The two five-byte boundary calls are included only to join this new selection to preceding work; their enclosing bodies are not selected. Existing registry, preparation and cache-entry bodies are external boundaries. Node #115, visor, network or chain access, target execution and complete HyperEVM recovery are excluded.

## Reproduce

Run from the repository root with the authenticated artifact and Python 3.12.3. The exporter imports the standard library and the shared `tools/elf_index.py` and `tools/fde_extents.py` readers, authenticates the entire input before parsing, excludes SHT_NOBITS sections from file-backed VA reads and starts no external program. GNU objdump 2.42 was used for human inspection only; none of its text is an exporter or test input. All addresses below are original ELF virtual addresses before load bias; the TSV records give file offsets where applicable. FDE ends are exclusive.

```sh
python3 tools/evm_state_override94.py --out research/work-items/RE-021-state-override-94
python3 -m unittest tests.test_evm_state_override94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-state-override-94 && sha256sum -c MANIFEST.sha256)
```

For independent regeneration, first ensure these are different empty directories:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/evm_state_override94.py --out work/evm-state-a
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/evm_state_override94.py --out work/evm-state-b
diff -r work/evm-state-a work/evm-state-b
```

The `.json` and `.tsv` evidence files are exporter output. The README and manifest are packaging files. The focused suite and the two regeneration runs were also performed with an empty program-search PATH. The exporter writes no timestamp, host path or hash-seed-dependent ordering. Its restricted instruction walker records encodings and selected operands; it is not a general x86 decoder or an emulator.

## Evidence

### Boundaries and previous work

`functions.tsv` records **18 selected FDE intervals, 33,680 code bytes and 6,567 decoded instruction rows**; `instructions.json` retains the raw instruction bytes and `unwind-records.json` retains the CIE/FDE records. The exporter checks the shared FDE reader against the unwind header and a fixed digest for every selected interval. An FDE interval is an unwind extent, not proof of an exact source function boundary. `control.tsv` has **1,264 control records**, including calls and returns; it is not a count of independent branches. There are **50 semantic windows**, **37 selected call edges**, **35 selected predicates**, **35 bounded table entries**, **57 relocation records**, and **217 exception call-site rows**. Exception action chains and types, dynamically called targets and unselected helpers remain open.

The previously drafted `RE-021-eth-call-target-94` identifies a request path that calls the auxiliary adapter at `0x1e67a80` and forwards its result toward preparation. `boundary-calls.tsv` records only the connecting call instructions: `0x1e67b5d` targets the newly selected `0x1b2ad60`, and `0x247dec9` targets newly selected `0x243fd20`. The containing preparation body belongs to the prior draft and is not selected here. Treat composition across the argument copies and normal returns as conditional on that draft and the intervening code behaving as described, not as proof that a live router chooses this descriptor.

The existing BLAKE2b packet binds the precompile object to the 20 bytes at `0x574f0c0`, nineteen zero bytes followed by `09`. The new `address-route.json` independently reads that data anchor. The pending `RE-021-blake2b-runtime-94` draft covers the separate precompile registry and lookup, which this packet does not reselect. This packet does **not** establish that a state override changes that registry or moves its callback.

### Entry, address keys and duplicate addresses

| Selected stage | FDE start | Byte-backed relation |
| --- | --- | --- |
| Request and forwarding | `0x1f6da60`, `0x27b86f0` | A selected request argument reaches the prior adapter and a 40-byte map is copied to the writer caller as its seventh argument. |
| Argument and nullable map | `0x1b2ad60`, `0x251f080` | The first calls the second; the `null` byte comparisons are distinct from the call to the map visitor. |
| Key and address adapter | `0x1bd8a60`, `0x1b702d0`, `0x2806f80` | A quoted key reaches the address adapter; two arms pass width 20 to the same relocation-backed decoder slot and require status 3 before copying 16 plus 4 bytes. |
| Account fields and insertion | `0x1d278c0`, `0x2441c70`, `0x27c5ce0` | The map visitor calls the account-field visitor, which dispatches by six tag values; key and value are passed to the insertion helper. |
| Apply | `0x243fd20`, `0x1f689b0`, `0x1eb2640` | The selected writer consumes a 216-byte map bucket, fetches data for its 20-byte key and calls the account publisher. |
| Slot arms | `0x1eb2060`, `0x26ba9a0`, `0x1eb2c70` | The writer chooses a replacement-map construction/publication arm or a per-slot delta arm. |
| Move-address value | `0x2526540` | A `null` option and a non-null address adapter have separate tags and failure paths. |
| Writer caller | `0x2480f00` | On a selected normal arm, the writer and engine builder receive the same local cache-object address; a non-success writer tag goes to a separate return path. |

The address adapter calls through slot `0x57705c0`, whose symbol-free RELATIVE relocation points to external decoder `0x156e650`. If that decoder returns success status 3 with exactly the prior packet's address-09 bytes, the reviewed copies produce that 20-byte map key. The decoder implementation, accepted textual forms, aliasing behavior and whether a particular request reaches this arm are not established here. The account-key map and the precompile registry are different structures; matching bytes alone does not establish a registry lookup or a changed precompile.

The insertion helper uses a 216-byte bucket and compares 16 plus 4 key bytes before its match branch. On that branch it makes two 192-byte copy-like calls: old value to its result, then incoming value to the existing bucket. The new-entry branch copies 216 bytes and returns tag 2; the caller drops a returned old value on the other result arm. Thus, subject to the resolved copy helper's ordinary semantics and normal returns, a later identical decoded address replaces the prior value. This is distinct from the duplicate-field checks below. `address_key_equal` is a synthetic projection of just the 20-byte comparison; it does not simulate hashing, probing, allocation or the node.

### Request-to-writer and engine-builder handoff

On one selected request arm, `0x1f6da60` calls the previously drafted argument adapter `0x1e67a80` at `0x1f6dcde`; the latter's connecting call to selected parser `0x1b2ad60` is retained separately in `boundary-calls.tsv`. After the adapter returns, full result 4 selects a zero first map word; otherwise low result 3 permits the 40-byte map to be staged on the request stack, while a different low result takes its error branch. The selected request call at `0x1f6dd86` passes the map address in the fifth argument to `0x27b86f0`.

The preparation adapter copies the map's 16-, 16-, and 8-byte pieces to local stack `+0xa88`, then copies those pieces to `+0x110` and passes that address as the seventh argument at `0x27b8aaf`. The callee `0x2480f00` saves six registers and allocates `0x5a8` stack bytes; including the return address, its load from `+0x5e0` addresses that seventh argument under the SysV x86-64 calling convention. `request-flow.json` checks the actual copy instructions, call displacements, argument registers and stack arithmetic. This composition assumes the intervening helpers return normally without destructively aliasing those bytes. It does not identify the live RPC method name or prove router activation.

After environment conversion returns tag `0x21`, `0x2480f00` invokes `0x1eb2d90` with local stack address `+0x4d8`. If the forwarded map's first word is nonzero, `0x24810f6` calls the selected writer with that same address in its third argument. The following byte check branches to `0x24812cd` on any writer result other than `0x21`; that arm copies the result to the caller output and goes to cleanup. A zero map word skips the writer. These are internal return objects, not final RPC error messages.

On the separate continuation where override application succeeds, the word at environment `+0x228` is nonzero, the four guard words at `+0x258`, `+0x250`, `+0x248`, and `+0x240` are zero, and the selected amount word is nonzero, the code reaches `0x24817ce`. It passes stack `+0x4d8` in the third argument to the earlier engine builder `0x247fd20`, the **same address** passed to the writer. `engine-flow.json` checks the call and register encodings. This is an address-and-call-order observation, conditional on all intervening helpers returning normally and not changing the relevant object through an alias. Other guard paths are not resolved here.

The earlier `RE-021-precompile-provider-94` draft reports a path from that builder through provider installation to lookup. Composing the two drafts additionally requires its revision and callback conditions, the target environment address, and the lookup guards to hold; none is independently proved here. In particular, an override keyed by address 09 and an execution target of address 09 are separate conditions. The move-address field's effect on the registry remains unknown.

### Account fields and failures

`fields.tsv` derives names from six RELATIVE descriptor entries, verifies the classifier's immediate/SIMD byte comparisons, extracts the tag stores, and follows the signed-relative visitor table. `duplicate-errors.tsv` separately binds each seen-guard failure to the same field-name bytes and to the common external error helper. `branches.tsv` records the actual conditional bytes and targets.

| Tag | Decoded name | Seen guard | Value helper | Selected field in the assembled 192-byte record |
| ---: | --- | --- | --- | --- |
| 0 | `balance` | `0x1d27b08` | `0x2524360` | tag `+0x00` |
| 1 | `nonce` | `0x1d27c71` | `0x258cd60` | tag `+0x28` |
| 2 | `code` | `0x1d27bba` | `0x2524f90` | tag `+0x38` |
| 3 | `state` | `0x1d27c16` | `0x2521fd0` | word `+0x58` |
| 4 | `stateDiff` | `0x1d27b64` | `0x2521fd0` | word `+0x80` |
| 5 | `movePrecompileToAddress` | `0x1d27ccd` | `0x2526540` | tag `+0xa8`, 20 payload bytes at `+0xa9` |

The labels are present in the binary and the roles are inferred from those names plus their byte uses; no Rust layout identity is asserted. The guards branch to separately labeled error construction when their selected sentinels indicate the field was already seen. Their external formatter and final wire error are not analyzed. The bytewise `null` path, unexpected/missing delimiter branches, value-helper error checks, and decoder status failures are separate paths in the recorded instructions. The value parsers other than the selected move option remain external; the packet does not claim their full accepted syntax.

The move option's valid `null` arm produces inner tag 0; the normal non-null arm calls the external address adapter and writes inner tag 1. Its error arm has a distinct outer tag. The visitor assembles this tag and its 20-byte payload into the record, and the record is copied through the map insertion path. It is **not established** that the value reaches the precompile registry.

### Account and slot application

`layout-and-cases.json` derives the parser-record offsets from stores based at stack `+0x280` and checks them against the writer's copied record at stack `+0x2c0`. The writer's nonce-tag-1 arm copies its word into the account input. Code-related variants are dispatched through the two bounded tables in `tables.tsv`; their complete source-level enum and callback implementations are not assumed. The publisher calls the earlier code-cache entry helper with context `+0x40` and the account-cache entry helper with context `+0x18`. The account entry helper separately checks the cache and, on its other selected branch, calls the external backing-account getter. Existing database and allocation helper behavior is a boundary.

After account publication returns at `0x244024a`, the writer tests the record words corresponding to `state` and `stateDiff` in this order:

| `state` word | `stateDiff` word | Selected continuation |
| --- | --- | --- |
| zero | zero | No selected slot-map update; continue the account loop. |
| zero | nonzero | Iterate 64-byte key/value buckets, byte-swap eight 64-bit words, obtain the account entry and call the external slot insert helper on account `+0x88`. |
| nonzero | zero | Construct the replacement map, then call the selected replacement publisher; it writes account byte `+0xb0` as 2 and replaces the map at `+0x88`, with cleanup of old storage. |
| nonzero | nonzero | Clean the two input map allocations and write internal result tag `0x0f` with the original 20-byte address payload. |

These are tests of the **stored words**, not a claim that every syntactically present field has a nonzero word. When all entries complete, the writer stores internal tag `0x21`. The account-publisher call precedes the conflict test, so these bytes do not justify assuming that the failure is atomic or that earlier writes are rolled back. They also do not prove that a later external layer exposes those writes.

The `movePrecompileToAddress` tag and payload would occupy writer stack offsets `+0x368` through `+0x37c`. `writer-stack-operands.tsv` lists every explicit constant-displacement RSP operand in the writer: no such operand *starts* in that interval. This narrow observation does not rule out wider accesses, pointers, copy helpers, aliases or callbacks and is not a proof that the value is ignored. Its downstream destination is unresolved.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker settings, two-build comparison, normalization masks, native behavior, helper/data closure and whole-ELF equivalence: **not yet implemented/measured**. No executable bytes have been transplanted into an implementation.

The field-name and storage-choice helpers are explicitly synthetic models of selected byte comparisons, not target execution. The **61 focused tests** include full-digest corruption, FDE and unwind disagreement, wrong or missing relocations, file-backed/NOBITS/ambiguous range controls, corrupt names and branch tables, wrong decoder width and status assumptions, altered request-copy, stack-argument and engine-cache registers and offsets, duplicate-label corruption, unsupported or truncated instruction shapes, a jump into an instruction, all **424** one-bit changes to the six classifier names, all **160** one-bit changes to the address-09 key, and all four zero/nonzero storage choices. There are no skips. These controls do not validate native semantics or model the hash-table probing algorithm.

## Results and limitations

The packet resolves a bounded input-and-cache path that can carry the same 20 bytes as the BLAKE2b registry key and shows a conditional selected request path passing the same cache object to the previously mapped engine builder; it does not prove a live RPC route, a precompile registry move, all fork boundaries, complete transition inputs or component correctness. Bytecode type variants, helpers, text decoding, unwind actions, rollback, callback side effects and the precompile lookup's response to any override remain open. The full first HyperEVM task and all four `evm` milestone gates remain incomplete; no gate is advanced.

The provided main checkout and open/merged PR snapshot were searched for the selected FDE starts. A fresh public main/PR refresh was unavailable in this static environment and is required at submission. Next question: trace any use of the move-address option into the revision-selected precompile registry without reselecting the existing registry lookup bodies.
