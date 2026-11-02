# RE-009: node 115 state read, outer decoding and failure handoff

Node #115's selected JSON state-read path maps `exchange.locus.ctx.height` into byte offset `+0x28` of the allocated state on successful returns, while missing and duplicate fields and decimal overflow take distinct paths.

- Component ID: `abci`; this bounded loader and snapshot question advances RE-009 and follows the RE-017 state-link lead.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was a navigation clue only, and no unlicensed source was copied.
- Claim status: the recorded bytes, FDEs, relative destinations, relocation-backed Locations, and LSDA entries are observations. Names such as state, binary, vector, error and cleanup are interpretations constrained below; models are synthetic, not captured behavior.
- Scope included and excluded: one previously unowned upper wrapper, new selected continuations of a previously identified read boundary, two outer decoders, one nested JSON height route, selected output/error paths and two selected collection-cleanup loops. Prior loader, startup, exporter, comparator, GOT slots and already recorded call sites remain context or external boundaries; no complete inner schema, process entry, block-to-root closure, runtime trace, or component gate is claimed.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and the authenticated `artifacts/node/115/hl-node`. The tool imports the existing `tools/elf_index.py` and `tools/fde_extents.py`, checks the entire target digest before parsing or creating output, excludes `SHT_NOBITS` from file-backed mappings, and invokes no external program or captured binary. GNU objdump 2.42 was used only to inspect selected instructions by a human; its output is neither an extractor input nor a generated evidence file. No node, visor, key, chain action or network was used.

```sh
python3 tools/abci_state_read115.py --out research/work-items/RE-009-abci-state-read-115
python3 -m unittest tests.test_abci_state_read115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
: "${TMPDIR:?Set TMPDIR to a writable temporary directory}"
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_state_read115.py --out "$TMPDIR/re009-read-a"
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_state_read115.py --out "$TMPDIR/re009-read-b"
diff -r "$TMPDIR/re009-read-a" "$TMPDIR/re009-read-b"
diff -r -x README.md -x MANIFEST.sha256 "$TMPDIR/re009-read-a" research/work-items/RE-009-abci-state-read-115
(cd research/work-items/RE-009-abci-state-read-115 && sha256sum -c MANIFEST.sha256)
```

Use fresh temporary output directories. An optional cross-release byte check, requiring the separately authenticated historical ELF, prints both releases' coordinates and raw witness bytes without changing the normal generated files:

```sh
python3 tools/abci_state_read115.py --old-elf references/can1357-hl/bin/hl-node-mainnet-new --out "$TMPDIR/re009-read-history"
```

`functions.json` contains raw bytes, hashes and reconciled `.eh_frame`/`.eh_frame_hdr` records for selected FDEs. `windows.tsv`, `edges.tsv` and `references.tsv` contain selected original bytes and decoded operands. `dispatch.tsv` reads relative table entries directly; `constants.json` contains bounded literals and Location records. `unwind.tsv` and `unwind-witnesses.tsv` decode the selected call-site tables, retaining raw action indices. `height-flow.json` decodes 43 selected instruction operands and carries an eight-byte word through the selected copy ranges. `cleanup-pair.json` records one bounded comparison of two original-code windows and its explicit masks. `synthetic.json` is a set of branch models, not a target execution. `summary.json` counts these selected records. The manifest covers this README and all generated files.

## Evidence

All coordinates are linked ELF virtual addresses before rebasing; generated records also give file offsets. Each listed FDE is reconciled with the unwind header, checked against overlap and hashed over its described range. An FDE range does not prove source-function boundaries, all callers, full control flow or ownership of any common dependency. The read dispatcher's selected windows and edges are marked `context`; they are new continuations used to connect this question, not a claim on its earlier caller sites or GOT slots.

### Entry, Locations and return value

| Stage | Selected observation |
| --- | --- |
| Upper wrapper `0x564a680` | `0x564a685` forms the address of Location `0x64767d8`, whose relative relocation and record resolve to `l1/src/abci/state.rs:102:40`; `0x564a68c` calls the existing reader boundary. This wrapper is distinct from the prior exporter callers. |
| Reader entry `0x422e410` | After the prologue and before the first helper call, `0x422e41e` executes `mov rdx,rsi`, then `0x422e421` executes `mov rsi,rdi`. There is no earlier read or save of the incoming `rdx` in this entry sequence. Thus the Location just placed in `rdx` is overwritten, and the first helper receives the original first two argument words in `rsi`/`rdx`, subject to the stated calling convention. The record is a call-site anchor, not evidence that this Location is propagated. |
| Wrapper return | The wrapper tests bit 0 of `al`. On zero it moves the returned `rdx` to `rax` and returns. On nonzero it saves `rdx` and calls a diagnostic with the 43-byte `Result::unwrap` literal and the different Location `node/src/hl_node.rs:346:66` at `0x64ab040`; `ud2` follows if the diagnostic returns. |
| Wrapper unwind | The LSDA range covering the diagnostic call selects landing `0x564a6ca`. The landing loads the saved pointer, calls the first entry of its pointed-to table, and resumes unwinding if that call returns. This does not prove that an unwind occurs or identify the dynamic callback. |

Prior PR #2047 separately maps a loader Location at `state.rs:123:37` and a caller of the same reader; PR #2123 maps distinct export callers and treats the reader as a boundary. Neither earlier call site or associated slot is repinned here. The new wrapper's Location, the dispatcher overwrite, and the two parser continuations are independently extracted from #115 bytes. The incoming Location may be meaningful at its caller; this observation is limited to the selected direct entry into this reader.

### Input and outer decoder decisions

The reader tests an earlier path-helper result, then inspects the returned final component only on its selected tag-9 route. A two-dot component, no dot, or a dot in position zero takes the text route. Otherwise it supplies the last suffix and the three bytes `rmp` to an existing comparison helper; a nonzero comparator result chooses the binary read route. The comparator implementation is outside this packet; the earlier exporter packet examines its ASCII case-folding behavior. A zero path-helper result instead reaches a formatted error boundary. These observations do not prove filesystem identity, normalization or the semantics of the called path helpers.

| Condition | Selected effect |
| --- | --- |
| Text or binary read result first word is `0x8000000000000000` | The `neg` overflow branch selects, respectively, the `read_to_string: ` adapter `0x422eb70` or the `read: ` adapter `0x422ecc0`. Other first words enter their decoder route. |
| Text decode | `0x3ef18b0` initializes its parsing context, calls `0x404c260`, and checks bit 0 of the returned `al`. A set bit bypasses the subsequent trailing-byte scan and is passed to the JSON error adapter `0x422ebf0`. |
| JSON outer map | `0x404c260` accepts a selected opening `{` route, checks a decoded key's length and the eight bytes `exchange`, and calls `0x40908e0` for the value. A previously saved nonzero value pointer at the matching key enters the `duplicate field` formatting path; no saved value at map completion enters the `missing field` path. Unknown keys go to a separate helper whose complete behavior is not established. |
| JSON outer sequence | A selected `[` route calls a sequence helper and, on its selected element branch, calls the same `0x40908e0` child. The child's non-2 result reaches a `0x27a8` allocation and copy; child failure and null allocation have separate exits. Full sequence arity and the child schema are not asserted. |
| JSON depth byte | At this outer reader entry, the text wrapper initializes adjacent parser bytes to `00 80`. With the first byte zero, depth byte `+0x49` is tested before decrement: 0 reaches a guard, 1 decrements to 0 and enters the code-`0x18` path, and 2 or more proceeds with the decremented value. A nonzero first byte bypasses this particular decrement. The record does not establish a whole-document maximum depth. |
| Binary outer map | On the freshly fetched marker path, `0x80..0x8f` reaches the low-nibble map-count arm. The map key path has both bytewise and eight-byte comparisons against `exchange`; a first match calls child `0x32caf70`, a second match takes the duplicate-template path, and zero entries take the missing-template path. The child and unknown-key helper remain boundaries. |
| Binary outer sequence | Fresh markers `0x90..0x9f` select the low-nibble sequence-count arm. Count 0 calls `0x2f7fe90` with an `invalid length ` template; its formatter is a boundary. For a nonzero count and a successful selected child result, count 1 takes the tag-9 result route; a larger count builds tag 4 and calls `0x30291b0` to clean up the selected child. Child errors take separate paths. |
| Binary dispatch and truncation | Four bounded signed-relative table spans contain 225, 18, 225 and 18 entries; a separate seven-entry error-cleanup table is recorded. These spans are static data, not a census of reachable markers or instruction boundaries. Selected two- and four-byte length arms compare remaining input first, use big-endian byte order on the full-input branch, and route short input to distinct error stores. |

On the selected child entry `0x40908e0`, a subsequent `{` route calls `0x3efb050`; a `[` route invokes a sequence helper and can call `0x4112920`. The selected nested map route is followed below; the complete schemas and the separate sequence route remain boundaries. Both outer decoders make selected calls using a `0x27a8`-byte temporary and preserve a child-produced pointer on their normal routes. This establishes common observed transfer sizes and selected cleanup layout, not Rust type identity or snapshot compatibility. The binary decoder returns tag 9 to the read dispatcher on its selected normal route; the dispatcher tests that byte and either returns the associated word or calls `0x422eac0`. The JSON decoder's selected error and non-error path instead use the register result described above. The read boundary's binary return sequence does not itself contain a trailing-input check after the selected decoder call; no claim is made about all inner parser consumption or acceptance of any complete fixture.

### Nested JSON height materialization

The following route is conditional on the selected map branches and normal returns. It is a field path in the serialized `exchange` object; it does not by itself establish a live block application or state-root input. The three literal keys and selected signed-relative dispatch entries are read directly from the authenticated ELF. The key classifiers operate on already decoded key bytes; their input decoding helpers remain boundaries.

| Stage | Observation from the selected path | Missing, duplicate and failure decisions |
| --- | --- | --- |
| `exchange` map | `0x3efb050` calls selector `0x3bda740`. Its five-byte length-table arm compares `locus`, returns field index 0, and the caller's index-0 table entry selects `0x3efb3dc`. | The local word at `rsp+0x43d0` starts as 2. A matching key while its low dword is not 2 takes the `duplicate field` formatter. At selected map completion, a low dword still equal to 2 takes the `missing field` formatter. Child tag 2 takes a separate error route. |
| `locus` value | After the colon, `0x3efd86e` calls `0x4112920`; its selected map route calls `0x3bd3ad0`, which matches the three bytes `ctx` and returns index 0. The index-0 table entry selects `0x4112b8f`. | The local `rsp+0x18` word starts as 2; not-2 on a repeated key takes the duplicate formatter, and 2 at selected completion takes the missing formatter. Child tag 2 is an error route. |
| `ctx` value | `0x411364c` calls `0x409c990`. Its selected map route calls `0x41fc4a0`; the length-6 selector compares all six `height` bytes and returns index 2, whose table entry selects `0x409d03a`. | The separate `rsp+0x68` presence word starts as 0. A repeated key with value 1 takes the duplicate formatter; after an earlier required-field check passes, the missing check tests bit 0 and supplies the same six-byte literal to the missing formatter when clear. |
| `height` scalar | After a selected colon check, `0x409d63e` calls `0x3ef2dc0`, which calls `0x3ef2440` for its selected digit routes. The caller tests result bit 0. | A set bit takes `0x409da71`; a clear bit marks height present and keeps the returned `rdx` word. Empty input, a missing colon, an initial zero followed by another digit, and the selected accumulator fallback each have distinct byte-backed paths. These statements do not assert acceptance of complete JSON fixtures. |

On the selected successful scalar path, `0x409d643` saves the returned word in `rbp`, and the completed context result stores it at output offset `+0x28` at `0x409ccd9`. The locus parser first transfers this word from its child result at `rsp+0x360` to `rsp+0x2d8` and then to `rsp+0x1638`. On its selected successful return, two `0xba0` copies and two `0xb90` copies put it at `+0x28` of the locus output. The enclosing map copies the locus payload into its own temporary, then uses the `0xba0` copy at `0x3f0bf5d` and the `0x10e8` copy at `0x3f0c502` to put the word at `+0x28` of its output. On the selected non-error route, `0x40908e0` copies that output through `0x4090d50` and `0x4090d9a`; the outer map copies `0x27a8` bytes into the newly allocated object at `0x404c52a`. The word therefore lands at allocated-object offset `+0x28`; `height-flow.json` records the original operand bytes, intermediate offsets and copy-range arithmetic.

The copy slot `0x64df508` is a contextual dependency, not a newly owned loader GOT site: the tool resolves its unique `R_X86_64_GLOB_DAT` relocation and undefined `memcpy` dynamic symbol directly from the ELF. This offset conclusion assumes ordinary binding of that slot, valid nonoverlapping source/destination ranges, all selected calls returning normally and no intervening writes through aliases; the runtime binding and full caller identity are not proved.

In the selected decimal digit loop, the immediate at `0x3ef24b2` plus one and the digit comparison at `0x3ef251f` give quotient `1844674407370955161` and remainder `5` for the maximum 64-bit unsigned value. An accumulator below the quotient can take the multiply-by-10-and-add arm; at the quotient, only digits at most 5 take that arm. Larger cases reach a separate indirect fallback at `0x3ef252d`, rather than an established immediate rejection. A subsequent carry branch reaches a guard. Eight synthetic boundary models exercise these decisions without claiming the fallback's result, complete decimal grammar, signedness of the resulting source field, or captured execution.

### JSON trailing bytes and error cleanup

On a non-error result from `0x404c260`, `0x3ef18b0` compares the saved cursor and length. A cursor at or above the length bypasses its scan. For a valid in-bounds cursor below the length, it admits only bytes `09`, `0a`, `0d` and `20`: these are the set positions at or below `0x20` of the loaded mask `0x100002600`. Each admitted byte advances the stored cursor. A different byte is not advanced past; the reader constructs error code `0x16` via `0x3ef1a90`, calls `0x3f22170` on the selected decoded pointer, calls a release-like slot with size `0x27a8`, and returns the new error word. These are conditional static observations, not a claim that a live snapshot was parsed.

The error-position helper bounds its requested prefix by `min(cursor + 1, length)` after a maximum-word guard, then calls `0x5c56920`. That helper has separate bounds checks and calls through two indirect byte-search boundaries; their actual runtime binding is not resolved. The earlier release's line/column algorithm is therefore not silently transferred to #115.

The four formatting adapters use distinct literal prefixes: `read_to_string: `, `read: `, `serde_json::from_str: ` and `rmp_from_slice: `. The JSON parse adapter tests the first word of its incoming record: 0 conditionally passes its `+8` pointer and `+0x10` size to a release-like slot, 1 passes its `+8` subobject to `0x4232440`, and other words bypass those inner actions; each selected normal branch then passes the outer record and size `0x28` to the release-like slot. In the binary parse adapter, table entries 0 and 1 select the inner cleanup helper, 2 through 4 return without that selected cleanup, and 5 and 6 conditionally pass the `+0x10` pointer and nonzero `+8` size to the release-like slot; larger byte tags bypass the table. The invoked formatter, allocator and dynamic bindings remain boundaries.

### Two selected collection-cleanup loops

The JSON cleanup `0x3f22170` and binary cleanup `0x3007980` have separate FDEs. On their selected normal paths, each first invokes its own preceding helper and then performs these two loops. Offsets are relative to the pointer passed to that cleanup function.

| Header offsets: size, pointer, count | Element stride | Selected inner call | Backing release when size is nonzero |
| --- | ---: | --- | --- |
| `+0x1fa0`, `+0x1fa8`, `+0x1fb0` | `0x200` | `0x3d90a50` | Size word shifted left 9. |
| `+0x1fb8`, `+0x1fc0`, `+0x1fc8` | `0x120` | `0x3d83020` | Size word multiplied by `0x120` using shift and LEA. |

Each count controls the corresponding element loop; the size word separately controls whether the backing release-like call is made. These statements assume a readable, internally valid header, ordinary call returns and no conflicting aliases. They do not establish allocator semantics or behavior of arbitrary corrupt headers. The remaining cleanup functions and later fields are not exhaustively reconstructed.

For these two loops only, the original `0x3f22186..0x3f2222d` and `0x3007996..0x3007a3d` windows are both 167 bytes. They differ in 16 raw bytes, exactly four relative displacement fields. `cleanup-pair.json` lists the four 4-byte masks at offsets `0x2b`, `0x4f`, `0x7b`, and `0xa3`; the extractor verifies each opcode and resolves each pair to the same selected helper or slot before masking. The masked windows compare equal and hash to `7b6923088ad76e1db08593a18635765e59a08af0779086ca5f56e47e02978caa`. This is an original-to-original selected-window comparison, not source equivalence, complete destructor equivalence, or closure of dynamic calls and data.

The two box-cleanup wrappers call the corresponding cleanup and pass size `0x27a8` to the release-like slot on normal return and on the selected cleanup-unwind route. For the JSON tail, the error-position call's LSDA landing calls the JSON box-cleanup wrapper, whereas an unwind from the cleanup call goes to a distinct landing that releases the outer allocation. The binary map-child landing conditionally calls the binary box-cleanup wrapper. The selected element-cleanup call sites in both formats have landings that continue their respective remaining-element loops and conditionally release backing storage. `unwind-witnesses.tsv` binds these relationships to exact call-site ranges; zero landing entries and raw action values are preserved without interpreting personality or type tables.

### Historical cross-check

The earlier RE-017 state-link and RE-009 wrapper reports are bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; their historical records can be read from repository commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4`. The optional authenticated comparison reads the #94 bytes at `0x2fe307d`, `0x2fe3047` and `0x2fe3055`, and the #115 bytes at `0x3ef1922`, `0x3ef1904` and `0x3ef19b7`. Both selected suffix masks are `0x100002600`, but the old result test compares an output dword with 2 and the new test checks bit 0 of `al`. The old selected operation copies `0x1fc8` bytes, while the new selected operation passes `0x27a8` as a release size. Those are different instructions and contexts, not an equality test for the two complete layouts. No #94 addresses, tag values or results are relabelled as #115 facts.

### Inferences and unresolved links

The `state.rs` and `hl_node.rs` records, field literal and caller relationships support the descriptive loader and state names. The conditional pointer flow depends on normal returns, the established calling convention and no unexamined alias writes. The Location in the original third argument is overwritten on entry, so it cannot be treated as a value forwarded to the first helper by this route. Unexamined indirect bindings, file/path helper internals, inner state fields, complete cleanup and any scheduler-dependent reachability remain open.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler/linker flags, two-build result and target-to-reconstruction comparisons are not yet measured. The only normalization is the bounded original-to-original cleanup comparison stated above. Helper semantics, dynamically bound calls, relocation/vtable/data closure, complete file-format compatibility and whole-ELF equivalence are not established. No target bytes are transplanted into an implementation.

## Results and limitations

The focused suite passed 28 tests with zero skips, including a wrong digest with no output, changed real FDE range, all selected instruction windows and direct transfers, every selected RIP-reference opcode and displacement, damaged table entries, malformed or duplicate Location relocation, changed literals and dynamic-symbol records, NOBITS/ambiguous/out-of-range mappings, each masked displacement, malformed LSDA tables and selected landing controls. Synthetic checks cover all 256 single suffix bytes, changed nested key bytes, every height-flow opcode and operand, selected sequence counts, decimal accumulation thresholds and depth boundaries. Two independent output generations with different hash seeds and time zones matched byte for byte; the focused suite and generation also ran with Python as the only executable on PATH.

`summary.json` records 25 selected FDEs, 96 windows of which 4 are context, 119 selected transfers, 38 RIP-relative references, 498 relative table entries, 660 LSDA call-site records, 23 selected unwind witnesses, 256 suffix-byte models, 12 depth models, 8 key models, 12 sequence models and 8 decimal accumulation models and 43 height-flow operands. These are selected record counts, not a coverage denominator. Artifact digest/signature verification and the catalogue check passed. No full repository suite, target execution, hosted CI or container run is claimed.

No component gate is requested. The process-entry path, the full `exchange` value schema, all alternate dispatches and error semantics, the link from this loaded object to a particular block execution, begin/action/end-block closure and complete state-root inputs remain open. Next question: trace this loaded height word from a non-overlapping consumer into a binary-backed block transition or root input, and independently map the binary format path.
