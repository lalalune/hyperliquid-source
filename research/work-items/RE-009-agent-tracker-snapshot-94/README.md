# RE-009: AgentTracker snapshot field order and reader defaults

Node #94 writes five agent-tracker fields in a fixed order, restores three absent map fields through initializer paths, and orders small nonce-set maps by 20-byte key comparisons; a reconstruction can preserve these choices when storing or restoring the tracker.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was read for leads only.
- Claim status: static observations for byte windows, branch destinations, field names, call edges and FDE extents; bounded inference for the record identity and reader/writer correspondence. Runtime behavior, value encodings and compatibility across releases remain unresolved.
- Scope included and excluded: one five-field outer record, selected serializer, text writer, binary reader, JSON reader, key classifiers, field-level child calls and failure paths, and the nonce-map collection, small-input ordering and pair-writer handoff. Complete child key/value encodings, complete JSON or MessagePack grammar, state loading, hashing internals, real fixtures, other releases and captured-program execution are excluded.

## Reproduce

From the repository root with CPython 3.12.3, its standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/artifacts.py verify
python3 tools/agent_tracker_snapshot94.py --out research/work-items/RE-009-agent-tracker-snapshot-94
python3 -m unittest tests.test_agent_tracker_snapshot94
python3 tools/catalogue.py --check
(cd research/work-items/RE-009-agent-tracker-snapshot-94 && sha256sum -c MANIFEST.sha256)
```

`evidence.json` is the complete generated output. The generator authenticates the binary before parsing, rejects non-file-backed or ambiguous mappings, reads actual FDE records through the shared parser, and verifies complete selected body hashes. It resolves only explicitly selected instruction starts and signed relative table entries, with no dependency on binutils output. GNU objdump 2.42 was used for manual inspection, never as generator or test input. The capture is opened as data and not executed; no network or runtime state is used. All addresses below are linked ELF virtual addresses; file offsets and full raw body bytes are in the JSON, and all FDE ends are exclusive.

## Evidence

Previous work in `bridge-nonce-lifecycle-94` identifies the in-memory tracker at state offset `+0x36d0`, and `RE-009-app-hash-builder-94` identifies a hashing closure capturing this offset. This packet does not reanalyse those functions. At contextual site `0x2816250`, that closure calls the newly inspected generic writer `0x230d1b0`. Independently, contextual site `0x275b9c4` forms an argument at `+0x36d0`, and `0x275b9fc` calls the text writer `0x230d3b0`. These are contextual links, not newly claimed analyses of their enclosing functions.

The twelve selected FDE extents are:

| Role | Start | End exclusive | Bytes |
| --- | --- | --- | ---: |
| Nonce entry writer | `0x1deb090` | `0x1debeea` | 3674 |
| Nonce entry-list writer | `0x1e2e9b0` | `0x1e2ec3b` | 651 |
| Nonce ordering routine | `0x1fe1cf0` | `0x1fe2505` | 2069 |
| Nonce-field wrapper | `0x2028520` | `0x202860b` | 235 |
| Nonce entry collector | `0x256e240` | `0x256e476` | 566 |
| Generic writer | `0x230d1b0` | `0x230d3a6` | 502 |
| Text writer | `0x230d3b0` | `0x230d6b7` | 775 |
| Last text-field helper | `0x23d1f80` | `0x23d2049` | 201 |
| Binary reader | `0x2d9e1e0` | `0x2da0caf` | 10959 |
| JSON reader | `0x31b0240` | `0x31b2e55` | 11285 |
| Binary key classifier | `0x341e2f0` | `0x341e416` | 294 |
| JSON key classifier | `0x341e420` | `0x341e546` | 294 |

The writer and classifiers are directly called at the selected sites; the readers also have contextual direct calls at `0x2abaf62` and `0x3183643`. Entry calls, selected control transfers, return paths and the actual FDEs support these bounded entrypoints. FDE extents alone do not prove full function boundaries or all possible entries.

### Field order and map decisions

The writer passes a count of five to both container helpers, chooses between them from its context byte at `+0xb`, and calls the name helper only when that byte equals one. Its five child calls and their name/child error branches appear below. The offset is relative to the record argument, not an on-disk offset. The text writer supplies the same five names and offsets, with the last name supplied by its helper. Both classifiers use a length table and byte comparisons to produce tags 0 through 4, and tag 5 for other names. The two 18-entry length tables and the two six-entry map-dispatch tables are independently read from the ELF.

| Tag | Field | Writer argument offset | Generic child call | Binary reader child | Binary duplicate branch | JSON duplicate branch | Missing in map |
| ---: | --- | ---: | --- | --- | --- | --- | --- |
| 0 | `user_to_main_agent` | `+0x00` | `0x202b5e0` | `0x2ccfd70` | `0x2da0388` | `0x31b04af` | missing-field error |
| 1 | `user_to_extra_agents` | `+0x30` | `0x202c300` | `0x2d30e60` | `0x2da0660` | `0x31b060c` | initializer path |
| 2 | `agent_to_user` | `+0x60` | `0x2029f60` | `0x2c67360` | `0x2da04f4` | `0x31b0560` | missing-field error |
| 3 | `address_to_nonce_set` | `+0x90` | `0x2028520` | `0x2b92ce0` | `0x2da05aa` | `0x31b05b6` | initializer path |
| 4 | `user_to_pending_agent_removals` | `+0xc0` | `0x202ab90` | `0x2b2a910` | `0x2da043b` | `0x31b050a` | initializer path |

For each recognized map name, the selected readers test a separate presence slot before entering its child. The five nonzero branches reach the duplicate diagnostic with the corresponding name. An unrecognized name dispatches to a separate helper; its complete behavior is not established. In the binary map completion, `0x2d9f7d7` sends missing field 0 to its named error, `0x2d9f88f` sends missing field 2 to its named error, and the missing slots 1, 3 and 4 each take initialization paths. The JSON map completion has corresponding checks at `0x31b1028`, `0x31b1031`, `0x31b1272`, `0x31b127c` and `0x31b145f`. Missing routes carry the selected `missing field` template; duplicate routes carry the selected `duplicate field` template. The initializer calls are pinned, but this packet does not independently prove the full abstract contents of the resulting containers.

The generic writer checks every field-name helper result against 2 and routes other results to `0x230d36c`. It checks every child result against `0x8000000000000004` and routes other results to `0x230d37b`. Only after all five children does it store that success sentinel. The two container-opening helpers also branch on their results. The text writer similarly checks each child return and returns early on nonzero; `0x23d1f80` handles its fifth field. These are observed control and return representations, not a complete error taxonomy.

### Nonce-map write path

For field 3, `0x230d31c` calls `0x2028520`, which builds an iterator from the field's control bytes, calls `0x256e240` to collect entries, calls `0x1fe1cf0` with the collected pointer/count and finally calls `0x1e2e9b0` with the resulting vector. The collector tests its remaining count, scans 16 control bytes per group, and stores two pointers per entry. Its selected bucket arithmetic uses a `0x30` stride and produces a pair of pointers `0x18` apart; the emitted pair vector advances in `0x10`-byte units. The collection failure and empty paths are present in the full bodies, while allocation helper semantics remain outside scope.

For 2 through 20 collected entries, the ordering routine takes the in-body insertion path at `0x1fe1d1b`. The comparison at `0x1fe1d82` passes `0x14` as the byte count and calls through slot `0x576e488`; the ELF's `R_X86_64_GLOB_DAT` relocation and dynamic symbol name identify this slot as `memcmp`. A negative comparison enters the move loop and a nonnegative result takes the other arm. The input records move as 16-byte pairs, preserving the associated value pointer. Together with the prior nonce packet's identification of the 20-byte address at the first pointer, this supports ascending bytewise address order for this small-input path, assuming the imported comparator has its standard behavior. The branch for 21 or more entries calls other ordering helpers, so a universal ordering claim is not made.

On the selected bounded-count path, the entry-list writer opens its container with the collected count, advances by `0x10` per pair, calls `0x1deb090`, and exits through an error route if a child result differs from its success sentinel. One selected pair-writer mode writes byte `0x92` at `0x1deb28d`; the mode condition and its error handling remain visible in the saved body. This does not establish the entire address or nonce-set wire representation, or the behavior of every writer mode.

### Selected binary sequence and truncation paths

On the selected sequence arm, the length is held in `r13d`. Conditional on all previously called children succeeding, the observed count decisions are:

| Sequence length | Selected outer decision |
| ---: | --- |
| 0 | first-element error path |
| 1 or 2 | the required third-element path reports an error; at 1, the second slot first takes its initializer |
| 3 | calls the first three children, then takes initializer paths for the fourth and fifth |
| 4 | calls the first four children, then takes the fifth initializer path |
| 5 | calls all five children and the remaining-count check sees zero |
| greater than 5 | after the fifth child, a nonzero remainder enters an error-construction path |

The checks at `0x2d9e7a5`, `0x2d9e828`, `0x2d9e912`, `0x2d9ea48`, `0x2d9eb7f`, `0x2d9efe3` and `0x2d9ed4e` support those decisions. A truncated two-byte length takes a separate short-input branch at `0x2d9e282`; this is one truncation control, not a complete malformed-input survey. No claim is made that a sequence with an allowed outer length succeeds if a child value is invalid.

### Inferences

The same field names, the two direct reader-classifier edges, matching tag order, corresponding writer offsets and the already published state/hash context support identifying the selected values as the same agent-tracker outer record. The classifier tag and the writer position are observations; the source-level Rust type and the interpretation of the writer modes as particular complete wire formats are not established by those tags alone. The JSON reader's leading `[` and `{` checks identify its selected array and map routes, but only its map decisions are characterized here.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No compiled comparison, normalization masks, target execution, snapshot fixture, child codec closure, complete indirect-call closure or cross-release byte identity has been established. The 13 focused unittest methods include damaged input identity, changed complete body, changed classifier constant, changed dynamic relocation and symbol, changed dispatch entry, changed call opcode/displacement, changed branch opcode/displacement, altered field names, missing/duplicate/wrong FDE descriptions, NOBITS, ambiguous section and out-of-range VA controls. Synthetic name checks validate extraction assumptions; they are not native decoder executions.

## Results and limitations

The JSON records 12 selected FDE extents totaling 31,505 bytes, 5 ordered fields, 4 selected dispatch tables, 10 duplicate branches across the two readers, 35 explicit instruction windows and 18 diagnostic references. These are selected facts, not a census of all serializers or callers. No full-scope milestone gate is requested. Only node #94 is examined; file format versions, ordering for larger nonce maps, all five complete child value encodings, omitted-key helper effects and real recovery behavior remain open.

Next question: finish the larger-input ordering helper and recover nonce-set values and their reader, including duplicate handling, then compare with a sanitized offline fixture once target execution is authorized.
