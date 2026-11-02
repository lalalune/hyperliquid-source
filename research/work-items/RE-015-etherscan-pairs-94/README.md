# RE-015: conditional binary configuration pair-map path in node 94

The binary reader reached by the previously identified `chain_to_etherscan_ws_urls` field builds a map whose array value paths require two positions and permit a null-like second position, so a reconstruction must account for those paths rather than assume the reference tree's variable-length string list is sufficient.

- Component ID: `constants`, task `RE-015` (`global_constants/*`); this packet follows one downstream configuration field from an already studied global initializer.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes).
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference supplies hypotheses, not authority or implementation code.
- Claim status: byte, FDE, relocation, and local branch observations for this digest; field name, value types, map operations and callback purposes are inferences as qualified below. Runtime reachability and equivalence are unresolved.
- Scope included and excluded: ten newly selected FDE ranges on one binary field-reader, insertion, and cleanup path. Earlier field classifiers and visitor instructions appear only as handoff context. This does not repeat the 76-name table, select the earlier visitor, assert any runtime path, cover JSON value decoding, or claim completion of the component.

## Reproduce

From the repository root on Linux x86-64, Python 3.12.3 was used. The producer authenticates the entire node #94 artifact first, reads ELF/FDE/CIE data through `tools/elf_index.py` and `tools/fde_extents.py`, excludes `SHT_NOBITS` when mapping virtual addresses to file bytes, and writes only the 18 listed machine-readable files. Its restricted x86 length decoder is adapted from the repository's MIT-licensed `tools/nv_stream_inventory.py`; fixed byte witnesses provide the additional semantic anchors. It invokes no external program. GNU objdump 2.42 was used for human inspection only; its output is neither input to the producer nor saved as generated evidence.

```sh
python3 tools/config_pairs94.py --out research/work-items/RE-015-etherscan-pairs-94
python3 -m unittest tests.test_config_pairs94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-etherscan-pairs-94 && sha256sum -c MANIFEST.sha256)
```

For independent deterministic output checks, substitute two different writable directory names for the placeholders. Both regeneration and the unit tests also ran with a PATH containing Python but no binutils.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_pairs94.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/config_pairs94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer only writes evidence; it does not execute the node, access a runtime configuration, or contact a network. `MANIFEST.sha256` binds this README and all 18 generated files, excluding the manifest itself. The test and producer need the captured artifact, and do not skip if it is missing.

## Evidence

### Coordinates and attribution boundary

All addresses are linked ELF virtual addresses, not process addresses. `functions.tsv`, `instructions.tsv`, `witnesses.tsv`, `dispatch.tsv`, and `context.tsv` also record file offsets. FDE extents are half-open unwind ranges, not proof of a complete function inventory. Selected instruction bytes are partitioned from each FDE entry under a restricted set of encodings, and local direct branch and table targets must land at those boundaries.

The previously recorded configuration work `RE-015-config-name-field-94` links the global directory field, an initializer, the selector, and a field classifier/visitor. It identifies a conditional binary selector branch but does **not** establish that the standard filename reaches it after the intervening path transformation. We therefore analyze the following conditional handoff, not an asserted live initializer-to-file execution:

```text
prior field classification: chain_to_etherscan_ws_urls -> tag 0x1e
prior binary visitor: tag 0x1e -> arm 0x13ad5da -> call 0x13ad609
new binary map reader 0x13bffa0
  -> prior string-like reader 0x13bdcd0 (external boundary)
  -> 0x13aa5f0 optional-second wrapper -> prior 0x13bdcd0 (boundary)
  -> 0x14cbfa0 insert/replace -> 0x13a3440 split/insert
  -> 0x14daa70 map cleanup -> 0x14cd630 drain
```

`context.tsv` independently checks that the prior diagnostic's RIP-relative reference at `0x14a8022` resolves to `0x21bb8d` and that the immediate length at `0x14a8031` is 26 bytes. The bytes form the complete field name; the following pool bytes are not assumed to be a NUL terminator. The prior classifier's length-dispatch slot selects `0x13c792a`, and its recorded success store at `0x13c7a39` writes `0x1e`. This packet relies on the earlier packet for the full name-to-success predicate. The prior visitor's checked bias, relative table slot, and direct call resolve that tag to this packet's reader; the prior classifier and visitor FDEs are not selected here.

For provenance, `context.tsv` also retains the already reported complete `/cham` and `/static_config` template windows and the `NvTestnet` bytes; `relocations.tsv` checks its pointer slot and length. These are prior anchors, not a new ownership claim or a claim that the templates directly call the new reader. Earlier work infers a configuration filename from the global directory field; neither its runtime value nor the reachability of this binary branch is established here.

### Selected ranges and normal-flow map

| Role | FDE start | End, exclusive | New local observation |
| --- | --- | --- | --- |
| binary field map | `0x13bffa0` | `0x13c171a` | marker dispatch, per-entry pair checks, return or cleanup |
| optional second value | `0x13aa5f0` | `0x13aa6df` | cached/fresh `0xc0` special case and delegated reader |
| discard pair | `0x13b2f30` | `0x13b2f65` | conditional release of two owned components |
| insert or replace | `0x14cbfa0` | `0x14cc311` | key comparison, replacement, root allocation and count |
| split and insert | `0x13a3440` | `0x13a456e` | node capacity, split positions and parent update sites |
| split cleanup | `0x1396c80` | `0x1396cb5` | release-like callback on unwind path |
| drop map | `0x14daa70` | `0x14dab80` | drains records and conditionally releases their parts |
| drain map | `0x14cd630` | `0x14cd9f1` | per-entry traversal and node-size choices |
| unexpected slice | `0x14d0eb0` | `0x14d0f34` | formatting/error helper boundary |
| map-value type error | `0x14d4c60` | `0x14d4cda` | type-error formatter and returned sentinel |

`calls.tsv` records 138 selected direct/indirect call sites and identifies selected callees; everything else is a boundary. `transfers.tsv` keeps 524 recognized transfers. `cfg.tsv` reports 33 local reachability queries in a normal-flow overapproximation: both outcomes of every conditional and all six recorded table targets are included; calls are assumed to return, and unwinding and external call bodies are omitted. Consequently, a reachable result is not a proof of a feasible input, and an unreachable result is limited to this local graph. For example, the normal path from replacement branch `0x14cc08b` reaches return `0x14cc104` but not the collection increment at `0x14cc27f`; the empty-root branch can reach the increment.

### Marker and pair branches

The six adjacent signed-rel32 tables contain 225, 18, and 32 slots for each of the outer reader and value reader. Their LEAs, every slot, and target instruction starts are checked. `marker-model.tsv` enumerates 256 synthetic fresh bytes and gives both cached-table and fresh-path joins. These are models of fixed byte predicates, not target executions.

For the outer map, fixed markers `0x80`..`0x8f` supply a low-nibble count, while `0xde` and `0xdf` select two- and four-byte big-endian counts. The extended-header checks at `0x13c0138` and `0x13c00e0` branch on insufficient bytes to `0x13c0219`, which advances by the remaining amount, clears it, writes status 1, and returns. After a valid outer depth check, count zero reaches the success path without calling the key reader; a nonzero count enters the key/value loop. The remaining-entry counter is initialized from count minus one and is decremented at `0x13c03aa`; `0x13c03af` selects completion after the last entry. The `0x13c033c` depth counter is local to the outer reader; its exhausted branch writes status 8. The following table summarizes the distinct value-reader joins.

| Fresh byte | Normalized tag | Payload | Value-reader join | Observation |
| --- | --- | --- | --- | --- |
| `0x80`..`0x8f` | `0x80` | low nibble | `0x13c092d` | fixed-map-shaped value path |
| `0x90`..`0x9f` | `0x90` | low nibble | `0x13c0a5e` | fixed-array-shaped value path |
| `0xa0`..`0xbf` | `0xa0` | low five bits | `0x13c0490` | distinct fresh string-like join |
| `0xc0`..`0xdb` | original byte | preserved | table-specific | raw-marker dispatch; other semantics remain open |
| `0xdc` / `0xdd` | original byte | preserved | `0x13c07eb` / `0x13c04a1` | 16-bit / 32-bit array count |
| `0xde` / `0xdf` | original byte | preserved | `0x13c081c` / `0x13c0573` | 16-bit / 32-bit map count |
| `0xe0`..`0xff` | `0xe0` | original byte | `0x13c0431` | high-byte class |

The cached join for `0xa0` is `0x13c048c`, four bytes before the fresh join, so the two entry mechanisms must not be conflated. At `0x13aa604`/`0x13aa609`, cached tag `0xc0` takes the wrapper's special branch; a fresh `0xc0` also joins it. `0x13aa67f` loads `0x8000000000000000`, and the wrapper returns tag 9. The caller separately compares the second slot with `0x8000000000000001` at `0x13c0b18`..`0x13c0b28`. Treating the first sentinel as a null-like optional value and the second as a missing-value sentinel is an inference from these tests and cleanup branches.

For the fixed-array-shaped value route and the extended array routes, the local depth counter is checked before either reader. Depth 0 selects a failure callback followed by `ud2` if it returns; depth 1 decrements to zero and selects the error tag at `0x13c10c0`; depth at least 2 continues. The counter here is the value loaded at `0x13c0a62`, not an asserted initial file depth. Conditional on those depth checks and external reader results:

| Array count | Observed next decision |
| --- | --- |
| 0 | branch to the missing-first error boundary before the first reader call |
| 1 | after a successful nonmissing first result, branch to missing-second |
| 2 | after successful nonmissing results, continue with both 24-byte components, including the `0xc0` special second value |
| 3..`0xffffffff` | after both results succeed, set status 4 with expected count 2 and call `0x13b2f30` to discard the pair |

The first or second reader's error and missing-sentinel paths take precedence over the extra-count check. `arity-model.tsv` enumerates 576 combinations of fixed counts, three representative local depths, and abstract reader outcomes, including unproven sentinel-production cases. It does not show that the external reader produces every modeled outcome.

For `0xdc` and `0xde`, the value reader requires two remaining bytes, loads a word and rotates its bytes; for `0xdd` and `0xdf`, it requires four bytes and uses `bswap`. The decoded big-endian count joins the same array or map path as its fixed-size counterpart. If the header is short, `0x13c113b` advances by the remaining amount, sets remaining to zero and status 1, and proceeds to map cleanup. `header-model.tsv` gives 54 synthetic fixed, extended, boundary, trailing-byte, and truncated-header cases. Counts in that file are abstract inputs, not actual configuration samples.

For a fixed or extended map-shaped **value** marker, `0x13c095a` calls the newly selected type-error helper. Its RIP-relative reference points to the complete 30-byte template in `context.tsv`, and, if the formatter returns, it stores the signed-min sentinel. The caller's taken branch reaches map cleanup and cannot reach insertion in the local normal-flow graph. `map-value-model.tsv` enumerates 48 fixed-count/depth cases, and `header-model.tsv` also probes extended counts; neither establishes behavior for a formatter that unwinds.

### Key ordering, replacement, split and cleanup

At `0x14cc02e`, the compared pointer slot has a `GLOB_DAT` relocation naming `memcmp`. The surrounding byte witnesses select the shorter length, use the comparison result when nonzero, and otherwise use the length difference. Under the ordinary `memcmp` contract and valid representable key lengths, this implies lexicographic unsigned-byte ordering with shorter equal prefixes first; `key-order-model.tsv` contains 11 synthetic controls, including empty, prefix, and high-byte cases.

For equal keys the routine conditionally calls the release-like slot for the incoming key, copies the prior 48-byte value to its result, writes the new 48 bytes, and returns without the collection increment. The caller conditionally calls the same release-like slot for the old first and second components; signed-min and zero checks guard the second. A newly inserted key follows the count increment instead. These are observations of calls and copied layouts; the exact allocator identity is not inferred solely from a RELATIVE relocation.

For a valid, non-sentinel incoming key and an empty root, `0x14cc1ce` requests `0x328` bytes, initializes metadata including the 16-bit count at offset `0x322`, and reaches the increment at `0x14cc27f`. A full node has 11 keys; the 24-byte key slots start at node offset `0x218`, and the corresponding values occupy 48-byte slots. The split's normal path has these position-dependent decisions, reproduced for all 12 valid indices in `split-model.tsv`:

| Insertion index | Promoted old index | Destination | Old/new counts after insertion |
| --- | --- | --- | --- |
| 0..4 | 4 | old, same index | 5 / 6 |
| 5 | 5 | old, index 5 | 6 / 5 |
| 6 | 5 | new, index 0 | 5 / 6 |
| 7..11 | 6 | new, index minus 7 | 6 / 5 |

The helper also has `0x328`- and `0x388`-byte allocation sites, null-result branches, parent child/count writes, and cleanup calls. This table assumes a valid index and returning allocations; it is not a proof of every parent propagation or allocation-failure outcome. On reader failure, `0x14daa70` iterates using `0x14cd630`, conditionally calls the release-like slot on the key and both value components, and distinguishes `0x328` and `0x388` node sizes. The 50 selected LSDA call-site records are retained with encoded bytes and landing sites in `exception-sites.tsv`; their action/type meanings are not decoded.

`unwind-paths.tsv` connects five selected LSDA-covered calls to their recorded landing sites and locally reachable cleanup calls. For example, an unwind from the second reader call at `0x13c0ae8` has landing `0x13c1655`; a conditional first-value release, conditional key release, map drop, and call to external continuation `0x5660110` are locally reachable at `0x13c166a`, `0x13c16f4`, `0x13c1707`, and `0x13c170f`. The conditional releases can be skipped. For the split helper's leaf-allocation failure handler at `0x13a43a5`, the recorded landing `0x13a447c` can reach pair cleanup at `0x13a44be` and the same external continuation at `0x13a44df`. These routes start from decoded LSDA records, then use the local normal-flow overapproximation with calls assumed to return; they do not establish which exception is thrown or decode action/type tables.

### Generated records

`functions.tsv`, `instructions.tsv`, `transfers.tsv`, `calls.tsv`, `dispatch.tsv`, `marker-model.tsv`, `arity-model.tsv`, `map-value-model.tsv`, `header-model.tsv`, `key-order-model.tsv`, `split-model.tsv`, `cfg.tsv`, `witnesses.tsv`, `context.tsv`, `relocations.tsv`, `exception-sites.tsv`, `unwind-paths.tsv`, and `summary.json` are deterministic producer output. `witnesses.tsv` gives the fixed bytes behind the branch and layout statements; `summary.json` records the selection denominators and limits.

## Implementation and comparison

Independent Rust implementation, `Cargo.lock`, compiler/linker flags, two-build comparison, normalized byte comparisons, masks, and whole-ELF comparison: **not yet implemented/measured**. The inferred reference defines this field using a string-keyed map of variable-length string lists. The observed fixed-array route instead checks two positions and a null-like second position. This comparison motivates validating a pair with an optional field, but does not prove the source-level type, JSON behavior, other binary marker representations, or a reachable difference for the normal configuration file.

## Results and limitations

The selected scope comprises 10 FDE ranges totaling 13,121 bytes, 2,817 admitted instruction encodings, 300 fixed witnesses, 550 signed-rel32 table slots, 12 selected relocations, 50 LSDA records, and five selected unwind routes. These are counts of the explicitly selected ranges and tables, not a whole-node function-coverage denominator. The producer generates 256 marker cases, 576 array predicate cases, 48 map-value predicate cases, 54 header cases, 11 byte-order examples, and 12 full-node split cases; all are static models and controls, not observed target runs.

Local verification passed 36 focused unit tests with no skips, including corrupted digest, out-of-range and NOBITS address mapping, duplicate FDE, broken instruction/branch/table/relocation/LSDA bytes, malformed field handoff, truncated headers, depth/arity boundaries, and replacement versus increment. Two independent regenerations with different hash seeds and time zones matched byte for byte, including under a Python-only PATH. Artifact verification and catalogue check passed. No component gate is requested: source-level type identity, external readers and callbacks, complete alternate marker semantics, parent split propagation, action/type unwinding, runtime initialization reachability, node #115, visor, and executable equivalence remain open.

Next question: trace the prior selector's path transformation and the JSON value parser to determine whether the ordinary initializer can reach this binary branch and whether the two input forms share the same value contract.
