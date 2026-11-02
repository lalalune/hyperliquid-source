# RE-009: reconstruct the `locus.ust` snapshot entry path

For up to 20 entries in the selected serializer mode, node #94's `locus.ust` writer emits a key-sorted sequence of pairs with nine default-elided value fields, and a matching candidate reader rejects duplicate keys, giving a reconstruction concrete ordering, layout, and failure rules.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` was used only as a lead, and no source was copied.
- Claim status: observations are authenticated bytes, FDE records, literals, relocations, and selected call/branch edges; the state-field roles, original types, and association between the writer and reader family are inferences; end-to-end runtime and storage behavior remain unresolved.
- Scope included and excluded: the selected writer's collection, sort dispatch, pair and value encoding, two compact collection-reader routes, a JSON-shaped reader route, and selected failures. The large-sort helpers, arbitrary timestamp text, complete integer codecs, key parser grammar, full reader/writer grammar, enclosing state type, persistence, hash ownership, other releases and execution are excluded.

## Reproduce

From the repository root, Python 3.12.3 and the standard library are sufficient; the generator imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`. The authenticated input is `artifacts/node/94/hl-node`. `records.json` binds the digest, file offsets, FDE/CIE records, relative-call displacements, data bytes, table entries and relocations; `bodies.json` retains the raw bytes of each selected FDE extent. A different artifact or changed selected instruction is rejected before evidence is written. SHT_NOBITS sections are excluded from file-backed VA resolution.

```sh
python3 tools/artifacts.py verify
python3 tools/ust_snapshot94.py --out work/ust-snapshot-a
python3 tools/ust_snapshot94.py --out work/ust-snapshot-b
diff -r work/ust-snapshot-a work/ust-snapshot-b
python3 -m unittest tests.test_ust_snapshot94
(cd research/work-items/RE-009-locus-ust-snapshot-94 && sha256sum -c MANIFEST.sha256)
```

To compare each generated file with the packet, use the following after the first generation:

```sh
for f in bodies.json records.json fields.tsv presence.tsv examples.tsv container-examples.tsv name-cases.tsv reader-decisions.tsv pair-lengths.tsv sort-paths.tsv; do
  cmp "work/ust-snapshot-a/$f" "research/work-items/RE-009-locus-ust-snapshot-94/$f"
done
```

For the binutils-free and environmental determinism check, resolve Python before clearing the command search path:

```sh
PYTHON_BIN=$(command -v python3)
PATH=work/no-bin PYTHONHASHSEED=11 TZ=UTC "$PYTHON_BIN" tools/ust_snapshot94.py --out work/ust-snapshot-c
PATH=work/no-bin PYTHONHASHSEED=83 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/ust_snapshot94.py --out work/ust-snapshot-d
diff -r work/ust-snapshot-c work/ust-snapshot-d
PATH=work/no-bin "$PYTHON_BIN" -m unittest tests.test_ust_snapshot94
```

The generator and tests invoke no external program. GNU objdump 2.42 was used manually to interpret selected bytes, never to generate the evidence. The binary is only read; no node, visor, network, keys, database or chain data are executed or accessed.

## Evidence

All addresses below are linked ELF virtual addresses; file offsets and raw bytes are in `records.json`. Ends of FDE extents in that file are exclusive. An FDE describes an unwind interval, not proof of all control-flow ownership or cold fragments. This is bounded analysis: the extractor authenticates 22 selected FDE extents, 56 byte windows, 43 direct call or tail-jump edges and 52 conditional branch destinations. The counts are for these selected records, not a function census.

### Containing writer and collection

At `0x275abf8`, the containing writer emits the five bytes `locus` and then a 16-field map header in named mode. At `0x275ad79`, it emits `ust`; at `0x275ada4` it passes the source base plus `0x740` to `0x20296f0`. The contextual windows do not claim complete recovery of the containing function.

The adapter `0x20296f0` calls collector `0x256dd10`, sort `0x1fe87b0`, then sequence writer `0x1e4a430`. The collector uses `0x58`-byte table entries and produces pairs of pointers separated by `0x18` bytes to the key and value. Each collected pointer pair occupies `0x10` bytes. For 2 through 20 entries, the local sort compares 20 bytes through the `memcmp` relocation and orders the raw keys in ascending byte order. Counts 0 and 1 return before comparison. At 21 or more entries it first allocates; the allocation-failure branch is recorded. Counts through 2000 call `0x1ff3e80`, whereas counts above 2000 enter the `0x251b6d0` path. Their complete sorting and failure behavior is not recovered. `sort-paths.tsv` models only these initial branch boundaries and assumes allocation succeeds where applicable.

On the selected direct success path, with the count fitting 32 bits and serializer byte `+0xc` other than 2, `0x1e4a430` emits a sequence whose length is the collected count; `0x1dd8490` emits a two-element sequence, then key and value. Key adapter `0x1e0d0a0` supplies 20 input bytes, capacity 42 and mode 0 to the shared formatter. The relocation and the prefix/alphabet bytes are bound here; the separate [prefixed-hex evidence](../RE-005-prefixed-hex-rust-94/README.md) establishes the formatter's `0x` plus 40 lowercase hexadecimal characters for these arguments. The shared string writer then receives that text. These statements are conditional on successful helper returns and the selected serializer mode, not a claim about every mode.

### Value writer

The writer `0x275ce60` tests these fields in this order. Offsets are relative to its value pointer and are decoded from the load instructions; the names come from the target's literal bytes. The signed/unsigned role is inferred from the called integer writers, not from original Rust type metadata.

| Name | Offset | Emitted when | Selected value writer |
| --- | --- | --- | --- |
| `ln` | `0x00` | 64-bit word is nonzero | unsigned integer |
| `R` | `0x08` | 64-bit word is nonzero | unsigned integer |
| `C` | `0x10` | 64-bit word is nonzero | signed integer |
| `P` | `0x18` | 64-bit word is nonzero | signed integer |
| `t` | `0x30` | its three dwords differ from `(D, 0, 0)` | formatted string |
| `no` | `0x20` | 64-bit word is nonzero | unsigned integer |
| `f` | `0x3d` | byte is nonzero | boolean marker |
| `r` | `0x28` | 64-bit word is nonzero | unsigned integer |
| `a` | `0x3c` | byte is nonzero | single-character variant |

`D` is the nonzero result of the shared date helper for the recorded input `0xaf93b`. An initial zero result branches at `0x275ce95` to `0x275d35f` before the header. Its epoch-date interpretation was established separately in the [day-count evidence](../RE-001-daycount-date-94/README.md); this packet does not re-prove that helper. The `t` adapter formats the first component, writes byte `0x54` (`T`), formats the remaining component and passes the resulting string to the string writer. Three formatting failures reach `0x1dfcb38`; a string-output failure has its own branch. The exact accepted or emitted timestamp grammar is not established.

The `f` byte contributes its raw value to the header count even though its emission test is nonzero. Therefore the models use canonical values 0 and 1 only. The `a` table's indices 0 through 4 point to `e`, `i`, `d`, `u`, `p`; the outer writer omits `a` for index 0, so the observed nondefault output labels are `i`, `d`, `u`, `p`. The candidate compact reader uses byte 5 as its absent sentinel at `0x195839b`; the extractor reads this immediate to bound the selected arms. Indices beyond that table and arbitrary internal enum states are outside scope.

For serializer flag `+0xb` equal to 1, the selected writer emits a map header and names before present values; for flag 0, it emits an array header and selected values without names. Values other than 0 or 1 are excluded. The selected header, name and child failures leave the normal path before later fields; `records.json` records the particular branch destinations. This does not establish effects of an individual I/O or allocation failure.

### Candidate readers and failures

A containing compact reader's tag-4 arm `0x173a6fc` calls collection reader `0x19a14e0`. Its map route calls `0x26351d0`; its sequence route calls `0x2661ac0`, which calls pair reader `0x18e0050`. Both reach value reader `0x1956bf0`. The map route passes literal `User` to `0x1699080`, whose normal path prepares a 20-byte destination for generic decoder `0x190f5b0`; the sequence pair reader also prepares a 20-byte destination for that decoder. The generic decoder's complete grammar is excluded.

For a sequence-form pair, these gates apply **after all earlier child operations succeed**:

| Pair count | Selected route |
| --- | --- |
| 0 | branch `0x18e05d7` to the first-element diagnostic |
| 1 | read the key, then branch `0x18e0771` to the second-element diagnostic |
| 2 | read key and value, then take the count-two join |
| greater than 2 | read key and value, then branch `0x18e0ad7` to the extra-element result |

Child errors take their own paths and can precede a length error. The pair loop stops on a pair-reader failure. `pair-lengths.tsv` contains conditional static boundary models, not target executions.

Both compact entry routes and a separately located JSON-shaped entry loop `0x259d4e0` call insertion helper `0x27c8cf0`. Its selected key-equality path compares 16 plus 4 bytes; for a match it copies the previous 64-byte value into the result and writes the replacement into the selected slot. On the absent-key insertion path it places sentinel 2 at result offset `0x3d`. With canonical stored `f` bytes 0 or 1, an existing key returns a non-2 result and each of the three entry loops constructs the literal `duplicate key`; the sentinel-2 path continues the loop. Raw code and the reconstructed overlapping literal stores are recorded. These observations do not establish a persistent update, rollback, or crash behavior.

The compact field classifier `0x26bf820` and JSON-shaped classifier `0x26bf8c0` map the same nine names above to tags 0 through 8, and unrecognized names to tag 9. Each single-byte table has 50 entries; the two additional recognized names are `ln` and `no`. The two value readers' nine recognized map-field arms each have a seen-state branch to the corresponding duplicate-name diagnostic; unknown-name arms call separate helpers. Their normal output offsets match the writer's selected layout. The tables and selected arm targets are in `records.json` and `reader-decisions.tsv`; `name-cases.tsv` covers all 256 single-byte inputs and selected length/case controls. This does not establish identical error precedence or full grammar between the formats.

The association of these readers with the `locus.ust` writer is an **inference** from the enclosing tag-4 route, matching 20-byte key handling, all nine field names and the output layout. The direct field-name-to-tag predicate for the containing reader is not analyzed here, so the identity is not presented as a proven complete round trip. Similarly, the JSON-shaped route is a matching candidate, not a verified on-disk snapshot format.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no Cargo build, two-build result, normalization mask, compiled byte comparison, target execution, live fixture or runtime equivalence claim. Relocations are bound for the selected calls; the other helper bodies, dynamic/vtable targets, cold fragments, and whole-ELF closure are not established.

`presence.tsv` is a static model of all 512 combinations of the nine presence predicates under the declared canonical boolean and variant domain. `examples.tsv` and `container-examples.tsv` contain nine small-value row models and three short-container models, using pinned marker decisions and the separately studied address formatter. For example, the model gives `80` for the default named value and `81a26c6e01` when only `ln` is 1. These are derived predictions, not bytes captured from a running node. The container model is limited to at most 15 distinct 20-byte keys, successful selected serializer operations, small integer encodings, and default `t`. The separate sort model covers the local comparison branch up to 20 entries; it does not simulate the larger helpers.

## Results and limitations

The focused suite has 30 passing test methods, including wrong target digest, a modified body with a recomputed outer digest, instruction and literal corruption, NOBITS and unmapped addresses, table corruption, pair-length and sort thresholds, duplicate-key diagnostics, canonical value-domain rejection, and exhaustive single-byte field classifications. The 512 presence masks are model cases, not 512 native comparisons. Reproducibility and manifest checks are limited to the supplied files and pinned artifact. No full-scope milestone gate is requested.

Open questions include the direct `ust` name-to-reader-tag binding, both large-sort helper algorithms, all timestamp and address parse formats, large integer boundaries, serializer flags outside the selected values, allocator and I/O failures, and any on-disk, hash, or runtime relationship. Next, trace the containing reader's field classifier and the large-sort helper dependencies against non-overlapping evidence, then compare a complete fixture only under separately authorized offline execution.
