# RE-015: trace configuration loading and name selection in node #115

Node #115 distinguishes an unreadable or rejected static configuration, which selects name tag 33, from a valid configuration missing `aws_name`, which reads a second file and can reach an unwrap failure; reconstruction must preserve both routes and the release-specific name tags.

- Component ID: `constants`; task `RE-015`, with the shared file and formatting routines identified as dependency boundaries.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed inferred reference `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only to select questions. No inferred source was copied.
- Claim status: observations are #115 ELF bytes, FDE extents, fixed instruction encodings, dynamic relocations, data entries and call-site tables; source-level roles and format-template interpretation are inferences. Runtime paths, environment, all external helper effects and complete component behavior remain unresolved.
- Scope included and excluded: a selected initializer through home value, directory selection, config and fallback file paths, file-read/error handling, struct/name conversion and the final output stores; complete structural partitions of the listed bodies, selected error paths and 79-way name/enum dispatch. The global lazy caller, generic formatter, remaining metadata and directory-creation semantics, every JSON value and escape path, OS implementation and complete dependency closure remain outside the semantic claim. No progress gate is requested.

## Reproduce

From the repository root, Python 3.12.3 on Linux x86-64. The producer uses only the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it authenticates the complete #115 input before reading ELF records or writing output. It rejects ambiguous or SHT_NOBITS mappings and invokes no external program. Selected instruction forms are decoded from bytes; unknown encodings and branch targets inside an instruction are rejected. Neither the generator nor its tests execute the capture or use network, keys or runtime state.

```sh
python3 tools/node115_config_trace.py --out research/work-items/RE-015-config-path-115
python3 -m unittest tests.test_node115_config_trace -v
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-config-path-115 && sha256sum -c MANIFEST.sha256)
```

For the determinism check, substitute two distinct empty writable relative directories for the placeholders:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/node115_config_trace.py --out <out-a>
PYTHONHASHSEED=943 TZ=Pacific/Kiritimati python3 tools/node115_config_trace.py --out <out-b>
diff -r <out-a> <out-b>
```

Both generations and the focused tests were also run with a PATH containing only Python. All eight generated JSON files agreed byte-for-byte. GNU objdump 2.42 was used only for bounded human inspection; neither its text nor its output counts are inputs to the producer or tests. All generated addresses, lengths, instruction partitions, dynamic-symbol records, tables and exception records come from the authenticated ELF. The locally authored predicate and structural decoders adapt the repository's MIT research tools at commits `01454ff2358ad2edb367ee52108bcc79dd046bab` and `2310f67dee7c52f45886472e17c3682072446fea`; ELF, CIE, FDE and LEB decoding are reused from the current shared tools.

The historical comparison below is optional and reads a retained Git record, not the retired capture. Replace the placeholder with an owned relative directory:

```sh
git show 01454ff2358ad2edb367ee52108bcc79dd046bab:research/work-items/RE-015-aws-name-codec-94/evidence.json > <out-a>/node94-record.json
python3 -c 'import json,sys; a={x["text"]:x["result"] for x in json.load(open(sys.argv[1]))["parser"]["rows"]}; b={x["name"]:x["tag"] for x in json.load(open(sys.argv[2]))}; print("added",[(x,b[x]) for x in b if x not in a],"removed",[x for x in a if x not in b]); print("boundaries",[(x,a.get(x),b.get(x)) for x in ("EaMm","HeavyTestnet","NvTestnet","JoinMainnet","FBinSpot")])' <out-a>/node94-record.json research/work-items/RE-015-config-path-115/name-paths.json
```

The historical JSON SHA-256 is `a1312dc1bc62fea8c2517680aa51914cad6874c39364c280bf66ad536a84e8df`. It is not an input to #115 generation and the #94 76-entry table is not re-exported here.

## Evidence

All addresses are linked ELF virtual addresses; ranges are half-open. `summary.json` also gives file offsets, FDE and LSDA addresses, full-body hashes, data bytes, and selected instruction/relocation landmarks. FDEs describe unwind ranges; they are not by themselves a whole-program function census. `instructions.json` partitions every selected body into the restricted instruction forms, and `transfers.json` records every direct branch/call, selected indirect transfer, return and trap identified by that decoder. Register-indirect destinations and nonselected computed dispatches are not presumed resolved. `exceptions.json` contains all encoded call-site ranges for the selected LSDAs; action chains and reachability are not inferred from the action indices.

| Observed role, with inferred descriptive name | #115 FDE range |
| --- | --- |
| initializer and output writes | `0x17785f0..0x177876f` |
| home value | `0x17782e0..0x17783dd` |
| directory selector and creation-failure handler | `0x17780c0..0x1778265`, `0x1778270..0x17782d7` |
| config file reader and struct parser wrapper | `0x17783e0..0x177858d`, `0x1775dd0..0x1775ede` |
| config struct parser | `0x17771b0..0x1777faf` |
| enum envelope and quoted-name reader | `0x1773070..0x1773fc4`, `0x1777080..0x17771a3` |
| quoted matcher, renderer, plain matcher | `0x1774100..0x1774be1`, `0x1774e60..0x17754f1`, `0x1775500..0x1775dc6` |
| separate name file path and reader | `0x1772fa0..0x1773069`, `0x1773fd0..0x17740fe` |
| name-file trimming boundary | `0x1778840..0x1778ad7` |
| shared metadata and directory-creation helpers | `0x5c9c810..0x5c9ca28`, `0x5c8f4c0..0x5c902df` |
| shared open, read-loop and file-result helpers | `0x5c97060..0x5c97226`, `0x5c75580..0x5c75843`, `0x5ca4940..0x5ca4d49` |
| formatting argument adapters | `0x1772f80..0x1772f94`, `0x1777fb0..0x1777fc4`, `0x1778590..0x17785a3` |

### Pool entries and argument bindings

These are complete selected descriptor entries, not references to the middle of the text. `summary.json` records the linked LEA target and exact entry bytes; the table does not assert a complete whole-node xref census.

| Literal | LEA site | Entry VA | Entry bytes |
| --- | --- | --- | --- |
| `/cham` | `0x17780f3` | `0x44ab69` | `c0 05 2f 63 68 61 6d 00` |
| `/hl` | `0x1778164` | `0x43de29` | `c0 03 2f 68 6c 00` |
| `/code` | `0x177866c` | `0x43de2f` | `c0 05 2f 63 6f 64 65 00` |
| `/static_config` | `0x177840e` | `0x4401ef` | `c0 0e 2f 73 74 61 74 69 63 5f 63 6f 6e 66 69 67 00` |
| `/aws_name` | `0x1772fe1` | `0x44205d` | `c0 09 2f 61 77 73 5f 6e 61 6d 65 00` |

The sites pass these descriptors and argument records to the same relocated formatter slot. The interpretation of `c0` as an argument marker followed by a length-delimited suffix is supported by the earlier #115 `RE-001-node115-cache-suffix` argument-binding evidence, not by treating the bytes as literal NUL-terminated paths. This packet independently binds the selected #115 references and adapters; the shared formatter body is outside its scope. In particular, no actual home directory or rendered path is claimed.

### Initializer, selection, and writes

1. The initializer calls `0x17782e0` via `0x1778608`, then `0x17780c0` via `0x1778621`. If the home helper returns its signed-minimum marker, or its next conversion reports tag 1, its local result is an empty three-word representation. The environment lookup and conversion helpers are boundaries.
2. The selector prepares the `/cham` descriptor and calls the metadata boundary. A result tag 2, or a mode whose masked value does not equal `0x4000`, takes the `/hl` path. If the `/hl` check also fails the directory test, the selector calls the creation boundary at `0x17781dd`; the selector supplies a mode word `0x1ff` and a one-byte flag `1`. The creation helper has three `mkdir`-bound calls, and its first call passes the saved mode word; on a return of `-1` it reads the error integer. A nonzero helper result goes to `0x1778270`, which prepares the `could not create` diagnostic and a nonreturning error call. The metadata helper includes a `stat64`-bound call. These dynamic references do not establish actual OS outcomes, permissions after the process umask, or race behavior.
3. The initializer checks the selected path again. The error or non-directory branches reach `0x17786f0`, prepare the `cham_dir does not exist` descriptor and call the failure boundary. On the continuing route, it prepares `/code`, then calls the config reader through RELATIVE slot `0x64e2418 -> 0x17783e0`.
4. After that call returns normally, stores at `0x177869e..0x17786ce` place the first three-word value at output `+0x00`, the selected directory value at `+0x18`, the code value at `+0x30`, and the returned name byte at `+0x48`. These are observed writes through the last byte; they do not by themselves prove the complete Rust type size, alignment or ABI.

The LSDA entry covering `0x1778692..0x177869e` identifies landing pad `0x177871c`; the decoded cleanup conditionally releases the code temporary and then joins cleanup of the selected-directory and home temporaries before the unwind-resume boundary. The parser call in the config reader is covered by `0x17784a4..0x17784b3 -> 0x1778557`; the directory selector has separate cleanup landings `0x177822e` and `0x1778247`. These describe local table entries and instructions, not a guarantee about an external helper's behavior.

### Read, parse, and failure distinctions

| Condition observed along the selected route | Local result or next boundary |
| --- | --- |
| Config file helper returns the signed-minimum first word | `0x1778452` falls through, releases the error payload and returns byte `33`. |
| Struct parser returns tag 0 | The value byte loaded from the parser result is selected by `cmove` at `0x1778531`. |
| Struct parser returns a nonzero tag | The instruction at `0x177852c` selects `33`; cleanup still runs. |
| Parsed map closes with no `aws_name` value | Its marker remains `79`; `0x1777a3b` calls `0x1773fd0`, which reconstructs a selected-directory `/aws_name` path and uses the same file helper. |
| Separate name file helper returns its error marker | `0x177401c` reaches the `Result::unwrap()` diagnostic call at `0x177408a`, followed by the trap at `0x17740b7` if that call returns. |
| Separate name text, after the trimming boundary, is rejected by the plain matcher | The `79` test at `0x177403c` reaches the distinct unwrap call at `0x17740b1`; it does not return a matcher value to the outer default selector on that route. |
| A second `aws_name` map key is seen after a value was set | `0x17778bd` reaches the `duplicate field` descriptor at `0x1777e6a..0x1777ea1` and the parser's error route. |
| Parser succeeds but has non-whitespace trailing bytes | The wrapper reaches error code `22` at `0x1775e9a` and sets result tag 1. Its bit mask admits only bytes `09`, `0a`, `0d`, `20` in this trailing check. |

The struct parser checks a decoded key length of eight and the immediate bytes `aws_name` at `0x1777357..0x177736d`. Its initial byte marker is `79`. The result paths also support a sequence entry; `0x1777a21` calls the same separate-name helper on the selected empty-sequence route. This is not a complete JSON grammar or escape, recursion-limit, duplicate-field precedence, or error-message reconstruction.

The shared file helper stores signed-minimum on selected failed-open and failed-read/validation paths at `0x5ca4ac8..0x5ca4ad2` and `0x5ca4c5f..0x5ca4c69`, matching the two caller tests. Its directly connected open and read helpers bind dynamic slots to `open64`, `read`, `fstat64`, `close` and `__errno_location`. The `read` loop at `0x5c756c9` retries when the error integer is 4 and ends its selected loop on a zero result; the open helper has an analogous retry. These are static Linux x86-64 observations, not observed system calls. The byte-validation target `0x16815e0` and other helpers remain boundaries.

`open-case.json` separately follows the fixed option bytes for a path of at most 383 bytes with no interior NUL and normal helper returns. It derives the `open64` flags `0x80000`, whose low two access-mode bits are zero, and mode argument `0x1b6`. Long paths and other entry points are not covered by that case; no filesystem state is read.

### Name and discriminant boundaries

The #115 plain matcher at `0x1775500` admits lengths 2 through 13, checks exact full-slice byte predicates, and returns AL `79` on rejection. Lengths 5 and 6 have no successful leaves. The quoted matcher at `0x1774100` has a distinct result representation: success stores tag 0 and a name byte; its error path constructs an error result using the relocated list at `0x6410ce8` and count 79. The value 79 is an internal comparison marker in the envelope as well as the plain matcher's rejection byte; it must not be confused with the quoted matcher's error-result tag.

`codec.json` contains complete byte-derived predicates and instruction partitions for both matchers and the 79 renderer leaves. An independent structural decoder agrees on every instruction boundary in both matchers. `envelope-paths.json` resolves both 79-entry signed-relative tables at `0x481928` and `0x481a64`: the direct string arm stores the same tag; the object arm preserves it on the zero-helper-result route, subject to its closing-token check. The error-list pointer/length pairs, both matcher predicates and the renderer all agree for 79/79 #115 names. The renderer's slot table has no local range check; only valid tags are claimed. Sink effects and behavior for invalid renderer input remain unresolved.

| Boundary | Historical #94 tag | Independently decoded #115 tag |
| --- | ---: | ---: |
| `EaMm` | 12 | 12 |
| `EaTx` | absent | 13 |
| `HeavyTestnet` | 13 | 14 |
| `NvTestnet` | 32 | 33 |
| `NvMainnet3` | absent | 37 |
| `JoinMainnet` | 36 | 38 |
| `DummyNv` | absent | 39 |
| `FBinSpot` | 37 | 40 |

The optional historical comparison finds three additions and no removed spelling relative to the retained 76-row #94 record. The historical target was node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; its plain matcher was `0x164cdb0..0x164d62e`, its `/cham` LEA `0x164f840 -> 0x1fc0ec`, its `/static_config` LEA `0x164fbae -> 0x1ef5f5`, its documented default was 32, and its rejection value was 76. Those coordinates and observations remain #94 evidence, not #115 addresses. This run compared the historical record with independently decoded #115 bytes; it did not rehash or execute a #94 binary. The #115 descriptor addresses and discriminants above are not inferred from the release label or reference source.

## Implementation and comparison

Independent Rust: **not yet implemented**. Build, lockfile, raw or normalized binary comparison, helper/data closure and runtime differential behavior: **not yet implemented/measured**. No normalization masks or byte transplantation are used.

The focused collector is required for this active #115 question: the repository's shared ELF/FDE readers do not decode these comparison predicates, selected x86 control transfers or their option/relocation joins, and generated evidence cannot depend on native disassembler text. It keeps the common readers unchanged. Its bounded symbolic expressions establish the exact match predicates without executing target instructions; full-coverage instruction partitions and independent renderer/list/envelope checks constrain that extraction.

Controls reject a damaged whole-file digest or size, invalid/unbacked/ambiguous ranges, a shortened FDE, an unwind-index mismatch, a body-byte mutation, a branch into an instruction, bad or truncated encodings, out-of-range input loads, inconsistent symbolic constraints, changed parser and renderer table targets, changed enum dispatch, changed RELATIVE and GLOB_DAT bindings, altered open options, a template terminator and an LSDA header. Exact-name mutation cases are checked against the extracted static relation, not against a running node.

## Results and limitations

The generated record contains 23 selected FDE extents totaling 23,939 bytes, 5,831 structurally decoded instructions, 1,609 transfer/return/trap records, 135 reviewed landmarks, five complete template entries, and 77 call-site ranges across 12 LSDAs. The independent matcher partitions cover 2,246/2,246 and 2,785/2,785 bytes; the renderer covers 1,681/1,681 bytes. The 79 name agreements and 79 envelope dispatch agreements are checks over these selected code/data paths, not a node-wide denominator or a compiled-Rust match.

Final local validation: 25 focused unittest methods passed with no failures, errors or skips; both no-binutils generations under different hash seeds and time zones matched each other and the retained generated files. Artifact hash/signature verification, catalogue consistency and inventory reproduction passed. The repository-wide test suite, hosted CI and container build were not run. The original workspace already contained unrelated modified evidence files; none was changed by this packet.

The complete directory-creation policy, formatter and many parser helpers remain boundaries. This packet cannot establish all error precedence, complete input grammar, runtime values, whole-component behavior, a full binary-equivalence result or a progress-gate completion. Next question: independently trace the remaining quoted-string/escape helper and the config parser's unknown-value branches while preserving the selected file/default distinction.
