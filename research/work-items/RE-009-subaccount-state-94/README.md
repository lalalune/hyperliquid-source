# RE-009: sub-account state codec path in node 94

This packet establishes node #94's sub-account tracker codec, including nested formats and failure rules, and connects its MessagePack writer to a previously mapped computed app-hash closure.

- Component ID: `RE-009` (storage/state serialization; selected sub-account tracker state).
- Target release and full SHA-256: Linux x86-64 `hl-node` #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead, not an authority or implementation source.
- Claim status: static observations, with interpretations and unresolved details identified below. No milestone or coverage gate is requested.
- Scope included and excluded: the selected JSON and MessagePack tracker, collection, pair, and row codec copies, their specified calls, branches, constants, and preallocation. This does not establish a complete state snapshot, state-root hashing, persistence timing, all serializer copies, runtime format selection, ordering, or source-level equivalence.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12.3 and the captured artifact present:

```sh
PACKET_DIR=research/work-items/RE-009-subaccount-state-94
python3 tools/subaccount_state94.py --out "$PACKET_DIR"
python3 -m unittest tests.test_subaccount_state94
(cd "$PACKET_DIR" && sha256sum -c MANIFEST.sha256)
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For independent output comparison, use a fresh ignored directory in the repository:

```sh
REPRO_DIR=work/subaccount-state94-reproduce
PYTHONHASHSEED=7 TZ=UTC python3 tools/subaccount_state94.py --out "$REPRO_DIR/a"
PYTHONHASHSEED=131 TZ=Pacific/Honolulu python3 tools/subaccount_state94.py --out "$REPRO_DIR/b"
diff -r "$REPRO_DIR/a" "$REPRO_DIR/b"
```

The input SHA-256 is checked before section or unwind parsing. The tool uses the standard library and the existing `tools/elf_index.py` and `tools/fde_extents.py`; it does not invoke a disassembler, any subprocess, or the captured binary. All generated evidence is byte-for-byte reproducible without binutils on `PATH`. The manifest records the hashes of this README and all 19 generated files. An optional manual disassembly, not used to generate evidence, is `objdump -d -M intel --start-address=0x21e6580 --stop-address=0x21e6617 artifacts/node/94/hl-node`; the manual inspection used GNU objdump 2.42. No network, keys, captured-node execution, or chain data is involved.

## Evidence

All addresses are linked ELF virtual addresses; `functions.tsv` also gives file offsets, full FDE-derived half-open extents, FDE/CIE addresses, and body hashes. `tools/elf_index.py` excludes `SHT_NOBITS` for byte-backed section mappings. The 43 selected ranges agree between `.eh_frame_hdr` and `.eh_frame`; FDE extents are unwind metadata and do not by themselves prove complete source function boundaries. The call and branch inventory is selected for this question, not a census of every instruction or a denominator for node coverage. `anchors.tsv` preserves fixed instruction bytes, `edges.tsv` decodes selected relative calls and branches, and `tables.tsv` records signed relative jump-table entries directly from the ELF. Existing evidence in `research/work-items/sub-account-94/` and `research/work-items/vaults-subaccount-create-94/` supplies context for the tracker identity; the selected FDE starts in this packet do not overlap those packets.

**Tracker and row layout.** The MessagePack tracker writer at `0x21f97b0` references the two length-delimited field names, calls the first collection writer at `0x202c4e0`, then advances its tracker pointer by `0x30` before calling `0x20297e0`. The separate JSON writer at `0x21f94d0` references the same names and invokes corresponding writers. The JSON reader at `0x1c85e60` compares the full 20- and 21-byte names in SIMD chunks; the MessagePack reader at `0x173feb0` calls a separate classifier at `0x21e6ed0`. `outer-name-sources.tsv` independently resolves and compares their literal bytes.

| Tracker field | Observed tracker offset | Observed value path | Inferred role |
|---|---:|---|---|
| `user_to_sub_accounts` | `+0x0` | map-like collection of key and row-list pairs | master to sub-account rows |
| `sub_account_to_master` | `+0x30` | map-like collection of two-value pairs | sub-account to master |

The user-row vector readers at `0x24e4050` and `0x24e00e0` use a 64-byte stride. Selected JSON and MessagePack row writers refer to the same short field bytes in the order below. The latter passes the literal `Address` for the two values; the JSON writer supplies each value as 20 input bytes to its formatting helper. The exact address text representation is outside this packet.

| Writer key | Reader aliases | Selected row value location | Observed value evidence |
|---|---|---:|---|
| `n` | `n`, `name` | pointer at `+0x8`, length at `+0x10` | string serialization call |
| `s` | `s`, `sub_account_user` | `+0x18` | 20 input bytes; `Address` literal |
| `m` | `m`, `master` | `+0x2c` | 20 input bytes; `Address` literal |

These names and the association with tracker state are interpretations of the literal bytes, call graph, and existing state evidence; they are not a recovered Rust type declaration. `row-fields.tsv` records the literal coordinates and offsets.

**Connection to the computed app hash.** The earlier [app-hash builder packet](../RE-009-app-hash-builder-94/README.md) associates a captured state field with one of its serialized Keccak closures. At the boundary inside that already-studied closure, the newly checked call at `0x2818e80` targets this packet's tracker writer `0x21f97b0`. The preceding configuration store and argument setup in `hash-context.tsv` give the writer mode byte `+0xb` the value one, selecting the named tracker form on that path. The closure's containing FDE is prior work and is deliberately excluded from this packet's 43 selected FDEs. This connection uses the prior closure-to-app-hash reconstruction; it does not establish how the computed value is persisted or committed.

**Input shapes and failures.** The table records the selected gates after successful decoding of earlier children. This qualification matters: an invalid earlier child can fail before a later count or duplicate check is reached.

| Layer | Selected observations and branch evidence |
|---|---|
| Tracker field names | JSON duplicate branches `0x1c8609d` and `0x1c861dd`; missing branches `0x1c86898` and `0x1c868a1`. MessagePack map-form duplicate branches `0x1741993` and `0x1741865`; missing branches `0x1740b64` and `0x1740bd1`. |
| Tracker positional input | MessagePack tests zero, one, and finally count two at `0x174039d`, `0x17403f9`, and `0x1740588`; the two collection readers are called in field order. JSON separately dispatches opening `[` and `{`. |
| Inner collections | Each JSON reader dispatches both `[` and `{`; each selected MessagePack reader has array and map paths. The selected JSON writers emit an outer array and nested pair opening; the MessagePack entry writers call the array-header and pair writers. |
| Inner duplicate keys | Both fields and both input shapes in each format use the same respective insertion helper and construct `duplicate key` on the duplicate result: eight error constructions are recorded in `duplicate-key.tsv`. |
| Pair arity | Both selected MessagePack pair readers test zero, one, and count two at the sites in `edges.tsv`. Their corresponding writers pass count two to the array-header helper. |
| Row field names | The JSON classifier at `0x21e6620` and the MessagePack classifier at `0x21e6580` have separately recorded code and tables. Both classify each short and long alias to the same tag. The respective row readers dispatch that tag to the same presence guard, so a short name followed by its long alias reaches the duplicate-field branch. |
| Row required fields | The JSON and MessagePack map-form readers have distinct missing and duplicate field blocks for all three keys; `field-errors.tsv` resolves the field bytes and diagnostic prefixes. The selected MessagePack positional reader tests counts zero, one, two, and three, with a different-count error after the third successful child. |

The writer's serializer flag controls the MessagePack map versus array header. In the fast row writer at `0x21f9000`, flag zero produces the positional header `0x93`, while flag one produces the named header `0x83` and the successive field-key byte pairs `a1 6e`, `a1 73`, and `a1 6d`. These are partial wire fragments, not complete encoded rows: the field values and error paths still intervene. Behavior for other flag bytes is not asserted. Unknown tracker and row names take separate helper calls; whether every unknown value is accepted or skipped is not established here. No full JSON parser, MessagePack implementation, or byte-for-byte end-to-end fixture is claimed.

**Initial allocation is not the input maximum.** At `0x24e00ff`, the MessagePack row-vector reader selects `min(count, 0x4000)` rows, shifts by six for its initial byte allocation, and has an allocation-failure branch at `0x24e012b`. The later comparison at `0x24e0220` takes a growth call when length equals capacity. Thus the observed `0x4000` is an initial reservation bound, not a proven 16,384-row validity limit. `reservation-cases.tsv` models the arithmetic around the boundary, including the largest 32-bit count; it does not assert allocation success or later decoding success.

**Small-collection output order.** Before invoking the entry writers, both field wrappers pass their collected 16-byte records to separate routines at `0x1fe9710` and `0x1fe3bb0`. Their count gates send counts at least 21 to a separate path, while the path for two through 20 compares a following key to the current key over 20 bytes and shifts records when the comparison is negative. All six selected comparison calls use slot `0x576e488`; its ELF `R_X86_64_GLOB_DAT` relocation names the dynamic symbol `memcmp`, as recorded in `sort-comparisons.tsv`. Under the ordinary `memcmp` contract, the selected insertion path orders the 20-byte key contents in ascending byte order. The dynamic import could be interposed, and the path for 21 or more entries is unresolved; this is not a global ordering claim.

The classifier, presence, arity, reservation, and small-sort files are explicit static models of the pinned gates, not captured execution results. `classifier-cases.tsv` covers all 256 one-byte values and chosen long-name mutations; `outer-classifier-cases.tsv` covers both outer names and one-bit changes at each byte. `presence-cases.tsv` covers 64 combinations of short, long, both, and absent row names. `arity-cases.tsv` models counts for the tracker, two pair types, and the row; its results assume valid earlier children. `small-sort-cases.tsv` compares all 24 permutations of four synthetic 20-byte keys in the bounded insertion model.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no reconstructed Cargo build, compiler or linker comparison, normalized binary comparison, relocation closure, target fixture execution, or whole-node equivalence result. The selected serializer helper targets are only call edges; this packet does not claim their complete implementations. The reservation model is not a measured memory allocation.

## Results and limitations

The reproducible evidence has 43 selected FDE ranges, 104 selected direct calls, 60 selected branches, six selected indirect comparison calls, one contextual prior-closure call, 106 selected jump-table entries, 20 field-error blocks, and eight duplicate-key constructions. Model outputs contain 299 row-classifier cases, 47 outer-classifier cases, 64 presence cases, 25 arity cases, seven reservation cases, two row-header cases, and 24 small-sort cases. These are counts within this packet, not totals for the node. The focused unittest suite has 22 tests and no skips; its controls cover a bad artifact digest, malformed instructions, changed relative targets and literals, out-of-range and NOBITS mappings, a corrupt FDE and jump table, the comparison import, the prior-closure call boundary, aliases, duplicates, and count boundaries. The two restricted-PATH reproductions compared equal.

Unresolved: complete serializer and parser coverage, serializer flag provenance outside the selected prior closure, the behavior of unknown fields and malformed child values beyond the selected exits, the sort path for at least 21 entries, full comparator and relocation closure, persistence and commitment of the computed app hash, all other node versions, and end-to-end captured fixtures. No progress gate is advanced. Next question: trace how the computed app hash containing this closure's digest reaches the persisted state or consensus commitment.
