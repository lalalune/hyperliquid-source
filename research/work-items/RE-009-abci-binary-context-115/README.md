# RE-009: binary ABCI context-read path and height aliases

For node #115, an independent compact-snapshot reader can route `initial_height` and `hardfork_height` to one shared context field, preserve its duplicate check, and carry that field and `height` through the selected nested reader copies; the authenticated #94 selector instead classifies `hardfork_height` as its unknown index.

- Component ID: `abci`; this RE-017 loader question advances RE-009 storage and snapshot compatibility.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was a navigation clue only. No unlicensed source was copied.
- Claim status: ELF contents, selected instruction bytes, relative destinations, relocations and bounded selector outcomes are observations. Names, call-path joins, layout projections and behavior beyond the selected byte windows are inferences or unresolved as identified below.
- Scope included and excluded: selected compact binary `exchange.locus.ctx` map and initial sequence paths, context keys, duplicate/missing guards, selected scalar arms and conditional returned-field projections. Earlier loader, dispatcher and writer functions are contextual boundaries; their existing GOT slots and loader call sites are not claimed as new. Full input grammar, all fields' decoder implementations, live state mutation, block execution, root construction and component gates are excluded.

## Reproduce

Run from the repository root on Linux x86-64, with Python 3.12.3, the authenticated `artifacts/node/115/hl-node`, and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. The generator checks the full target digest before parsing or creating output, excludes `SHT_NOBITS` from file-backed mappings and invokes no external programs. GNU objdump 2.42 was used only for human inspection; no binutils output is an input to the generator or generated evidence. No node or visor execution, networking, keys or chain actions were used.

```sh
python3 tools/abci_binary_context115.py --out research/work-items/RE-009-abci-binary-context-115
python3 -m unittest tests.test_abci_binary_context115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_binary_context115.py --out work/re009-context-a
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_binary_context115.py --out work/re009-context-b
diff -r work/re009-context-a work/re009-context-b
diff -r -x README.md -x MANIFEST.sha256 work/re009-context-a research/work-items/RE-009-abci-binary-context-115
(cd research/work-items/RE-009-abci-binary-context-115 && sha256sum -c MANIFEST.sha256)
```

Use fresh `work/re009-context-a` and `work/re009-context-b` directories. Generation and the focused tests also run with a PATH containing Python and no binutils. The following optional comparison authenticates the separately retained historical ELF before reading its FDEs, instructions and Location. It prints the comparison and leaves the normal generated files unchanged:

```sh
python3 tools/abci_binary_context115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out work/re009-context-history
```

`functions.tsv` reconciles selected FDEs with the unwind header and hashes their complete described byte ranges; `windows.tsv`, `edges.tsv`, `references.tsv`, `literals.tsv`, `relocations.tsv` and `tables.tsv` contain original bytes and decoded operands. `keys.tsv`, `field-arms.tsv`, `missing-arms.tsv`, `sequence-checks.tsv` and `numeric-keys.tsv` bind bounded key and branch cases to those bytes. `operands.tsv` and `flow.json` record selected copy-offset arithmetic; `location.json` records a contextual Location. `scalar-cases.tsv` is a synthetic model, not captured execution, and `summary.json` counts only the selected records. `MANIFEST.sha256` covers this README and all generated evidence.

## Evidence

### Coordinates and ownership

All hexadecimal code, data, slot and table coordinates are linked ELF virtual addresses before rebasing. Generated records include file offsets when applicable. Each selected function extent is an actual FDE range reconciled with `.eh_frame_hdr`, with an exclusive end and body hash; it is not proof of a complete source-function boundary, complete CFG or all callers. Prior PR #2047 reports the Location-linked loader and startup handoff; prior PR #2149 maps the reader dispatcher and outer binary branch. Their existing loader calls and GOT sites are boundaries here. The #115 Location record in `location.json` independently contains `l1/src/abci/state.rs:123:37`; a Location alone does not prove an entire function boundary or that the reader preserves its incoming Location argument.

| Selected function role | #115 FDE start | Exclusive end | Purpose here |
| --- | --- | --- | --- |
| Locus reader | `0x332c430` | `0x333208d` | `ctx` child and its selected return. |
| Context reader | `0x30d1c60` | `0x30d3ee7` | Context map/sequence, selected fields and return. |
| Locus string-key selector | `0x2fbbd20` | `0x2fbbe89` | Selected `ctx` spelling. |
| Context string-key selector | `0x41fbef0` | `0x41fc480` | Context field names and aliases. |
| Unsigned-value decoder | `0x348e980` | `0x348ec9e` | Selected integer markers, short inputs and negative boundary. |
| Exchange string-key selector | `0x3bd7d50` | `0x3bda734` | Selected `locus` spelling. |
| Exchange / locus / context numeric-key selectors | `0x347f020` / `0x33de700` / `0x348eca0` | `0x347f2e1` / `0x33de9c1` / `0x348ef61` | Selected inline numeric field-index clamps. |

The higher route is conditional on the earlier read/outer-map results documented in PRs #2047 and #2149. The previously reported call at `0x32cb0dc` in the contextual wrapper enters the exchange visitor `0x2fd7260` (also a boundary in PR #2194); its non-2 branch at `0x32cb10d` reaches the selected copy path. The exchange visitor's `locus` child call at `0x2fd78dc` enters `0x332c430`. The locus reader's `ctx` child call at `0x332c805` enters `0x30d1c60`. `edges.tsv` decodes these displacements. Calls and windows in the earlier parent and wrapper are marked context; that distinction does not claim those earlier FDEs or the earlier wrapper call as new.

### Map fields and duplicate guards

For already-decoded field-name bytes, the exchange selector's checked five-byte comparison maps `locus` to index 0, and the locus selector's checked three-byte arm maps `ctx` to index 0. The context selector maps the following names to the signed-relative dispatch-table entries at `0x68ac4c`. The table records the selected guard's branch destination and one associated value-call boundary; the whole callee implementation is not implied. A slot is an indirect target address, and the corresponding relocation is recorded separately.

| Index | Context name probes | Duplicate branch target | Selected value call: direct target or slot |
| ---: | --- | --- | --- |
| 0 | `initial_height`, `hardfork_height` | `0x30d3a42` | slot `0x64e2580` |
| 1 | `hardfork` | `0x30d3abb` | `0x32b03e0` |
| 2 | `height` | `0x30d3aa4` | slot `0x64e2580` |
| 3 | `tx_index` | `0x30d3ac4` | `0x451c540` |
| 4 | `round`, `consensus_round` | `0x30d3ad6` | `0x4524ae0` |
| 5 | `time` | `0x30d3a05` | `0x3d4f3c0` |
| 6 | `prev_time` | `0x30d3a8d` | `0x3d4f3c0` |
| 7 | `next_oid` | `0x30d3aed` | slot `0x64e2580` |
| 8 | `next_lid` | `0x30d3acd` | slot `0x64e2580` |
| 9 | `next_twap_id` | `0x30d3a76` | slot `0x64e2580` |
| 10 | `system_nonce` | `0x30d3a39` | `0x421db60` |
| 11 | `use_system_nonce` | `0x30d3a1f` | `0x37ce740` |
| 12 | `mac` | `0x30d3a5c` | slot `0x64dfeb0` |

`field-arms.tsv` records the exact guard and branch bytes, call sites and target or slot for these 13 rows. For the six scalar-like arms, `windows.tsv` and `edges.tsv` also record a selected nonnegative-fixint jump from each guard's continuation to the corresponding call preparation. Other marker paths pass through normalization, and the call listing is not a complete CFG or a claim that every field uses only one helper. The generator interprets a bounded set of key-comparison and relative-jump opcodes and checks every single-byte substitution of the listed context names and of `locus`; it rejects unsupported forms and out-of-FDE branches. These probes are controls on these names, not an enumeration of every accepted name. The selected `ctx` arm is separately checked, including substitutions of its final byte.

Both index-0 spellings share the presence word at stack `+0x128`. After a successful selected decode sets it to 1, either spelling on a later map entry takes `0x30d21a3` to the `hardfork_height` duplicate-name reference. The corresponding `height` presence word is at stack `+0x100`; its duplicate branch reaches the `height` reference. These branches join the `duplicate field` template and formatter. This is a static interpretation of the selected order and guards, not a complete fixture acceptance test.

The three numeric-key helpers have an inline nonnegative small-integer arm that returns tag 9 and index `min(value, limit)`. For the fresh one-byte nonnegative marker path the limits are 59 for exchange, 16 for locus and 13 for context. The selected table has exactly one entry beyond the corresponding ordinary indices in each case. For context, index 13 goes to `0x30d20b1`, which calls an unknown-value helper and checks its returned tag; neither ignoring the value nor overall acceptance is asserted. Wider and negative numeric-key forms are outside this claim. `numeric-keys.tsv` checks each clamp instruction, call, slot and destination against the selected table, and `windows.tsv` records the fresh-marker caller paths.

### Map completion, depth and failure boundaries

On the selected completed-map path, the following absent-field guards reach the named `missing field` formatting boundary in this order, subject to earlier guards and helper returns. `height` uses the opposite conditional-branch direction: its present branch bypasses the missing handler. Every listed call is to `0x3046740`; a non-9 formatter result takes the selected error continuation `0x30d3792`, whereas a tag-9 formatter result can supply a value and allow subsequent checks. Therefore these observations do not say that every missing field unconditionally fails.

| Selected missing name | Guard VA | Taken branch destination | Name-reference VA |
| --- | --- | --- | --- |
| `hardfork_height` | `0x30d2f54` | `0x30d37b1` | `0x30d30a3` |
| `height` | `0x30d2f8c` | `0x30d3134` when present | `0x30d3473` |
| `time` | `0x30d3156` | `0x30d34e9` | `0x30d3509` |
| `prev_time` | `0x30d315e` | `0x30d3591` | `0x30d35ac` |
| `next_oid` | `0x30d3167` | `0x30d3637` | `0x30d3657` |
| `next_lid` | `0x30d3175` | `0x30d36e0` | `0x30d3700` |

The absent `height` fall-through at `0x30d2f9a` goes to its name reference and formatter; `missing-arms.tsv` preserves both branch directions, literal references and non-9 exits. Other selected completion instructions zero absent optional words using their presence flags, mask the selected `use_system_nonce` byte, and handle the `tx_index` sentinel; exact source-level option types remain unresolved. For the selected locus and context entries, a 16-bit word at input `+0x22` is tested before decrement: zero and the decrement-to-zero case branch to distinct recorded destinations. A locus or context child result tagged 2 takes a distinct error path. These guards do not establish a whole-document maximum depth, allocator behavior, complete cleanup or all failure cases.

### Selected sequence route

On a freshly fetched context marker, the `0x90..0x9f` arm supplies the low nibble as a sequence count. Zero reaches the `0x2f7fe90` formatting boundary with operand 0. Assuming each earlier selected child returns tag 9, count 1 or 2 reaches the same boundary with operand 2, while count 3, 4 or 5 reaches it with operand 5. `sequence-checks.tsv` contains the compared immediates, branch opcodes and targets, preceding helper calls and formatter operands. These operands are observations, not an assertion about the full sequence arity or formatter semantics. Non-9 child returns have separate recorded code paths. Counts above 5 and alternate length encodings are not closed here.

On a later selected sequence success continuation, the first and third decoded words are staged at `rsp+0x60` and `rsp+0x78`, with stage base `rsp+0x50`. The selected SIMD reload/store path places them at output `+0x10` and `+0x28`. This agrees in offset with the selected map route; it does not prove that arbitrary map and sequence inputs describe equivalent objects.

### Height scalar and returned bytes

For the selected map `height` arm, the RIP-relative slot at `0x30d2be9` has a unique `R_X86_64_RELATIVE` relocation to the selected unsigned decoder `0x348e980`. On tag 9, the caller saves the result and marks the field present; the completed map stores the saved word at output `+0x28`. The selected first-field arm uses the same decoder boundary and stores its saved word at `+0x10`.

| Selected marker case | Observation or boundary |
| --- | --- |
| Nonnegative fixint `0x00..0x7f` | Selected normalized arm writes the value with tag 9. |
| `0xcc` / `0xcd` / `0xce` / `0xcf` | Selected unsigned payload widths 1 / 2 / 4 / 8, in big-endian order; full payload goes to tag 9. |
| `0xd0` / `0xd1` / `0xd2` / `0xd3` | Selected signed payload widths 1 / 2 / 4 / 8; nonnegative values go to tag 9 and negative values reach a formatting boundary. |
| Short payload | The selected short-input arm advances the remaining payload to its end and writes tag 1. |
| Other marker or formatter result | Helper/formatter boundary; complete acceptance or rejection is unresolved. |

`scalar-cases.tsv` holds 67 synthetic inputs for this bounded model, including width and sign boundaries; it is not a trace of the target or a proof of unexamined marker behavior. The checked target windows and table destinations supporting the model are separate. The result of the negative formatter is not inferred.

The selected map stores and copy instructions support the following conditional byte projection:

| Stage | First-field qword | Height qword | Evidence |
| --- | ---: | ---: | --- |
| Context result | `+0x10` | `+0x28` | `0x30d31a6`, `0x30d31ba`. |
| Locus result | `+0x10` | `+0x28` | Child temporary and selected copies through the locus return. |
| Exchange result | `+0x10` | `+0x28` | Selected child staging and aggregate copies. |
| Outer allocated result | `+0x10` | `+0x28` | Selected wrapper and outer allocation/copy. |

The arithmetic and all pinned immediate bytes are in `operands.tsv` and `flow.json`. The copy import's selected relocation and dynamic-symbol entry identify `memcpy`; they do not establish runtime binding. This inference requires the selected success branches, ordinary copy binding, valid nonoverlapping ranges, normal helper returns, System V AMD64 callee-saved register preservation and no conflicting writes through aliases. It does not establish the identity of a later block-state or hash input. Existing #115 loader work separately reports state writes after its comparison; joining that report to this allocated object still requires proving the intervening returned-pointer identity and absence of changes.

### Cross-release check

The optional command verifies the historical node #94 digest `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, its context selector FDE `0x21e4170..0x21e4663` and its length table at `0x3d4114`; it separately verifies the #115 digest and selector `0x41fbef0..0x41fc480` with table `0x7c7160`. For probes `initial_height`, `hardfork_height`, `height`, `round`, `consensus_round`, the respective selected indices are `[0, 13, 2, 4, 4]` in #94 and `[0, 0, 2, 4, 4]` in #115. The old index 13 is the old unknown-key arm, not proof of snapshot rejection. The same optional check validates the original #94 state-link caller `0x32725d0`, call `0x3272785`, callee `0x3273810` and `state.rs:107:37` Location `0x56dfbf8` using #94 bytes and relocations; it does not relabel these coordinates as #115.

A previously studied #115 writer's contextual window references the `hardfork_height` literal and reads its first qword field at input `+0x10`. This supports a release-specific key-name comparison for this selected field, not a claim of complete binary snapshot compatibility or a runtime read/write round trip.

## Implementation and comparison

Independent Rust path: **not yet implemented**. Cargo graph, lockfile, compiler and linker flags, and two-build comparison: not yet applicable. Raw/normalized implementation comparisons, masks, complete helper and call-target closure, data/relocation/vtable closure and whole-ELF comparison: not yet measured. The target's selected original bytes and FDE hashes are evidence only; they are not transplanted as source implementation.

## Results and limitations

`summary.json` records 9 selected FDEs, 81 byte windows, 38 selected transfers, 209 relative table cells, 7 relocation records, 13 RIP-relative references, 5 literals, 17 key probes, 13 context field guards, 6 selected missing checks, 6 sequence-count checks, 3 numeric-key clamps, 62 projection operands and 67 synthetic scalar cases. The key interpreter checked 36,465 context and 1,275 exchange single-byte substitutions. These are selected record counts, not function-coverage denominators. The focused suite passed 27 tests with zero skips, including changed digest, FDE body, branch direction or displacement, marker and selector bytes, table bounds, relocation/symbol, NOBITS and invalid ranges, name and Location, short scalar payloads, and copy/sequence offsets. Deterministic regeneration, artifact verification and catalogue checking are reported in the draft; no full repository suite, target execution, hosted CI or container run is claimed.

No gate is requested: `abci` remains 0/4. The full loader-to-live-state object identity, remaining context and locus fields, arbitrary compact markers and malformed documents, the complete sequence branch, helper side effects, state-root inputs, and begin/action/end-block paths remain open. Next question: trace a previously unowned consumer of the returned allocation into a specific state mutation or root input, checking pointer identity and intervening writes rather than joining by matching offsets alone.
