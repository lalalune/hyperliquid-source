# RE-015: trace node 94 validator configuration loading

The previously unbound `node_config.json` template is reached from the global configuration cell and leads to readers in which `key` and `sentry_ips` are the explicitly recognized JSON object fields and a successfully parsed sentry list of three or more entries is rejected in the JSON object, JSON sequence, and selected binary sequence paths.

- Component ID: RE-015, global configuration; this is a bounded configuration consumer, not a whole-component recovery.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Node #115 and visor are separate artifacts and are not analyzed here.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred, unlicensed reference submodule `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a comparison lead, not source authority or implementation material.
- Claim status: the byte windows, FDE records, encoded targets, relocations, comparisons and stores are observations; role names, error meanings, format-token meanings and the conditional models are interpretations. Runtime paths, concrete config values and complete helper semantics are unresolved.
- Scope included and excluded: one previously unbound filename entry and its selected consumers, 11 FDE extents, specified branches and errors. The earlier configuration initializer and filename-constructor FDE are contextual boundaries; the 76-name table, other configuration consumers, unrelated marker arms, Rust build and component gates are excluded.

## Reproduce

From the repository root with the authenticated artifact at the location in `provenance/artifacts.json` and Python 3.12.3 on Linux x86-64:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 -B tools/validator_config94.py --out work/validator-config-a
PYTHONHASHSEED=113 TZ=Pacific/Honolulu python3 -B tools/validator_config94.py --out work/validator-config-b
diff -r work/validator-config-a work/validator-config-b
for f in work/validator-config-a/*; do cmp "$f" "research/work-items/RE-015-validator-config-94/${f##*/}"; done
(cd research/work-items/RE-015-validator-config-94 && sha256sum -c MANIFEST.sha256)
python3 -B -m unittest tests.test_validator_config94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

The collector checks the whole artifact size and SHA-256 before extraction. It imports the repository ELF section and FDE/ULEB readers, excludes `SHT_NOBITS` from file-backed VA mapping, reads relocation records directly, and uses a restricted fail-closed x86-64 instruction-length and direct-transfer reader. It reads bytes only; it neither executes the captured artifact nor launches external programs. `MANIFEST.sha256` supplies hashes of this record and every retained generated file. `summary.json` identifies the input, counts and coordinate system. The individual tables also contain file offsets and raw bytes, so addresses do not depend on a disassembler's printing format.

GNU objdump 2.42 was used only to inspect selected bytes during analysis, never as an input to the collector or tests. The two generated directories were compared under different hash seeds and time zones, and the collector and focused tests also ran with a PATH containing Python but no binutils. The repository-wide reproduction script was run in an isolated scratch environment with links to the pinned inputs; it reported that inventories, raw counts and refined literal classifications reproduce the imported evidence.

## Evidence

All code addresses below are linked ELF virtual addresses (VAs), not file offsets; each FDE end is exclusive. `functions.tsv` includes both coordinates, exact FDE/CIE/LSDA references, body hashes and instruction counts. These extents are selected FDE ranges, not a census of all component functions. `instructions.tsv` partitions their bytes into 3,339 instruction-length records; `transfers.tsv` records 720 direct or indirect control-transfer sites, including unresolved calls and jumps. The labels below are analytical roles, not recovered symbols.

| Role | Selected start VA | Observed relation or output |
| --- | --- | --- |
| Configuration loader | `0x28ea420` | Path transform, existence check, format selection, read, parse and result copy |
| JSON document wrapper | `0x1b2cfd0` | Calls visitor and checks trailing input |
| JSON visitor | `0x1cfdbf0` | Object and sequence branches, fields, defaults, result stores |
| JSON sequence first item | `0x1b66500` | Called by the visitor's sequence arm |
| JSON object sentry guard | `0x21c28b0` | Calls list reader and checks its returned count |
| JSON list reader | `0x1be6b30` | Checks array syntax and calls the list loop |
| JSON list loop | `0x24cec60` | Iterates and retains four-byte elements, with error cleanup |
| JSON list item | `0x1b9b9d0` | Calls the selected address-value reader |
| JSON address-value reader | `0x1be97a0` | Length and consumption checks around the existing address parser |
| Binary visitor | `0x185ba10` | Selected fresh-marker, fixed-array and result routes |
| Binary sentry guard | `0x21c2940` | Calls a collection reader and checks its successful count |

### Entry, complete pool entry and loader

The previous startup inventory recorded `node_config.json` as present but unbound. In the already inventoried caller, the load at `0x222db47` selects relocation slot `0x576e928`, whose `R_X86_64_RELATIVE` addend selects the global cell at `0x577b288`; that cell's relocation points to the already studied initializer `0x164ff00`. After the cell's state guard, the caller forms an argument from cell offset `0x18`, uses a LEA at `0x222db6f` to the *start* of the complete 37-byte pool entry at `0x1f1371`, and calls the selected loader at `0x222dbf3`. The pool bytes are `c0 22`, then the 34-byte literal suffix `\x2fhyperliquid_data/node_config.json`, then `00`; the interior substring alone is not the entry. The interpretation of `c0` as a default argument token follows the compiler-specific interpretation documented in `RE-015-format-prefix-correction-94`. The earlier label for cell offset `0x18` is `cham_dir`; its concrete argument and the rendered path remain unknown. The prior caller is used only as three explicitly labelled byte excerpts and is not counted among the 11 selected FDEs.

The loader calls the path-transform slot `0x576f628` and the existence-predicate slot `0x576e9e8`. A zero predicate branches at `0x28ea462` to an error path selecting the complete `missing file: ` format template and storing the minimum signed 64-bit sentinel. The transformed component is then obtained through slot `0x576e850`; its returned tag and byte slice drive the format decision. The following table is conditional on that external component-reader contract and does not establish what it returns for a real path.

| Component result | Route | Evidence |
| --- | --- | --- |
| Tag is not `9`; exact `..`; no dot; or the only usable dot is leading | Text reader | `0x28ea502`, `0x28ea518`, `0x28ea537`, `0x28ea54e` |
| Last-dot suffix has exactly three ASCII case-folded bytes `rmp` | Binary reader | `0x28ea55b` through `0x28ea5b9`; e.g. model components `x.rmp`, `x.RMP` |
| Other suffix length or bytes | Text reader | Same checks; e.g. model components `.rmp`, `x.rmpx` |

The binary route calls slot `0x576f640`, then `0x185ba10`; its error templates contain `read: ` and `rmp_serde::from_slice: `. The text route calls slot `0x576f648`, then `0x1b2cfd0`; its error templates contain `read_to_string: ` and `serde_json::from_str: `. Exact bounded template bytes and LEA targets are in `data.tsv` and `instructions.tsv`; source names for the helpers are inferred from those contexts, not established symbols. Read and parse failures select their own error paths. A non-sentinel parse reaches `0x28ea9bb`, which copies the 56-byte result to the caller-provided result buffer. The transform, I/O and allocator internals are outside the selected closure.

### JSON fields, state and failure branches

The document wrapper calls `0x1cfdbf0` and on success accepts only trailing byte values `9`, `10`, `13`, and `32`; any other trailing byte enters error code `0x16` and cleans up the preceding result as needed. The visitor recognizes object `{` and sequence `[` entries and checks/decrements a recursion byte on the selected nesting routes. The object visitor's two length-bounded field comparisons and destinations are:

| Decoded object field | Comparison evidence | Duplicate | Omission at object close |
| --- | --- | --- | --- |
| `key` | length 3 at `0x1cfddc5`, bytes at `0x3d2871` | `0x1cfddfa` to `0x1cfe678` | `0x1cfe2b7` to missing-field path `0x1cfe4ae` |
| `sentry_ips` | length 10 at `0x1cfddbb`, bytes at `0x3d2874` | `0x1cfdf29` to `0x1cfe6b9` | empty triple `(0, 1, 0)` selected at `0x1cfe2f4` |

The comparison bytes are adjacent but each is length bounded. Both duplicate paths use the `duplicate field` template at `0x1e0fd5` with different field-name slices; the missing-key path uses the `missing field` template at `0x1df8f3`. Unrecognized field names route to the external unknown-value reader at `0x1b2dd60`, whose complete success and error semantics are not claimed. In particular, `node_ip` does not match either selected comparison; the static classifier alone does not prove that a complete JSON document containing it succeeds.

The first value's reader is given a 32-byte destination at `0x1cfdfba` and called at `0x1cfdfc6`. The successful visitor stores a three-word vector-like result followed by 32 other bytes through offset `0x37` at `0x1cfe78f` through `0x1cfe7c5`; the interpretation of the latter bytes as a Rust key type or a particular key encoding remains open. The sequence's missing-first error passes descriptor `0x568a3b8`, whose length is 38 and whose relocation points to the diagnostic `struct ValidatorConfig with 2 elements` at `0x3b8af9`. This binds the type-name evidence to an actual selected error call, rather than merely to nearby text.

The object route calls `0x21c28b0`; the sequence route calls `0x1be6b30` directly and performs its own count check. On a successful parsed list, these checks compare against `3` at `0x21c28eb` and `0x1cfe3ec`, and respectively take error branches at `0x21c28ef` and `0x1cfe3f0`. The latter is therefore a separate sequence-path guard, not a presumed call to the object wrapper. The list loop calls `0x1b9b9d0` and uses four-byte element storage. The address-value reader rejects a decoded string longer than 15 bytes, invokes the already studied parser `0x1573af0`, and rejects a clear success bit or unconsumed suffix. Existing parser internals are a boundary. List parsing occurs before the count comparison, so a malformed element can fail earlier than an oversized-list error.

### Selected binary sequence branch

The loader initializes the cached marker state to `1` before calling `0x185ba10`. The selected signed 32-bit table entry at `0x307bd8`, relative to base `0x307bd4`, resolves to fresh-marker reader `0x185bbcf`. For that branch, with sufficient input and nesting budget and assuming successful nested readers, the fixed-array marker range is `0x90` inclusive to `0xa0` exclusive, with the low four bits as the sequence count:

| Marker | Selected static route |
| --- | --- |
| `0x90` | Missing first value route at `0x185c491` |
| `0x91` | First value, then default empty sentry vector |
| `0x92` | First value, then sentry reader `0x21c2940` |
| `0x93` through `0x9f` | After the first two values, enter extra-sequence result tag `4` |
| `0x8f`, `0xa0` | Outside this fixed-array branch; other marker behavior remains unclassified |

The binary guard calls collection reader `0x19ffc40`; a result tag other than `9` is propagated. On tag `9`, it branches at `0x21c2970` when the returned count is at least `3`, using the same 37-byte message at `0x70693e` as both JSON paths: `SentryIps can only have at most 2 IPs`. The count checks and two byte-level controls are independently retained:

| Path | Compare bytes and VA | Error branch and target |
| --- | --- | --- |
| JSON object | `48 83 f8 03` at `0x21c28eb` | `73 16` at `0x21c28ef` to `0x21c2907` |
| JSON sequence | `48 83 fa 03` at `0x1cfe3ec` | `0f 83 50 01 00 00` at `0x1cfe3f0` to `0x1cfe546` |
| Binary sequence | `48 83 fa 03` at `0x21c296c` | `73 35` at `0x21c2970` to `0x21c29a7` |

`branches.tsv` retains 51 selected conditional sites with encoded bytes, taken and fallthrough VAs and the analyst's condition labels. `contracts.tsv` retains 52 bounded byte witnesses. `cfg.tsv` contains 24 intra-FDE graph queries, including negative queries with named forbidden sites. This graph assumes calls return, considers both conditional edges feasible and stops at indirect jumps; reachability and absence of a path in that restricted graph do not establish actual runtime feasibility or complete interprocedural closure. The field, extension, count and marker case tables contain explicitly synthetic inputs for the conditional models, not captured node executions.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker configuration, two-build comparison, raw or normalized implementation-byte comparison, relocation masks, complete helper/data/vtable closure and captured-runtime fixtures: not yet measured. This packet does not transplant the captured bytes into an implementation.

The remaining comparison gaps are tracked separately:

- Helpers: the path transform, filesystem readers, key reader, IP parser and their complete error behavior remain external boundaries.
- Call targets: direct calls inside the selected ranges are listed, but register-indirect calls and jumps and their runtime targets are not closed.
- Relocations: 18 selected records are retained and checked; the rest of the executable's relocations and any comparison masks are not measured.
- Vtables and data: one relocated diagnostic descriptor and the bounded literals are checked, but their complete data and vtable graph is not traced.
- Whole ELF: no complete function denominator, linked rebuild, whole-file comparison or binary-equivalence result exists.

The inferred reference `references/can1357-hl/node/startup.rs` describes a `NodeConfig` lead with `key`, `node_ip`, and `sentry_ips`. The selected binary field comparisons establish only `key` and `sentry_ips` as special object fields in this visitor; the diagnostic describes a two-element `ValidatorConfig`. These facts are useful constraints, but they do not prove that the inferred reference type and this binary visitor are identical or establish how other types treat `node_ip`. Reference source is not copied into a Rust implementation.

## Results and limitations

For this digest, the deterministic output covers 11 selected FDEs containing 15,167 bytes and 3,339 decoded instruction records; it records 51 selected branch witnesses, 52 exact witness windows, 24 restricted graph queries, 18 selected relocation records, and 75 LSDA call-site rows across 6 parsed headers. LSDA action and type-table meanings remain uninterpreted. These are denominators for this selection only, not total functions or total component coverage. Two exact field comparisons and 104 single-bit spelling mutations are recorded; mutation, extension, count and marker cases evaluate the extracted static decision model rather than the captured executable.

The focused suite passed 50 tests with no skips, including changed artifact digest, corrupted target byte, changed instructions, immediate bounds, relocation, pool data and table slot, malformed/truncated inputs, non-file-backed or ambiguous mappings, malformed unwind data and forbidden CFG sites. Two independent output trees matched with `diff -r`; the retained generated files matched both. Artifact verification, catalogue check and isolated inventory/literal reproduction passed. No node or visor execution, runtime state, network access, chain action or private-key access occurred.

This is a partial static packet and requests no progress gate: global configuration remains 0/4. In particular, the dynamic value of the path argument, complete transform and I/O behavior, all JSON error and recursion cases, all binary map/marker arms, external key/IP readers, error-object lifetimes and later consumers of the returned buffer remain open. Next question: which unowned downstream consumer receives the result assembled by the previously inventoried caller, and what exact observable state or error handling follows while preserving the existing ownership boundaries?
