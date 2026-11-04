# RE-009: node 115 state read-to-export path

This packet establishes a selected node #115 state read-to-export path, including case-insensitive output-format selection, selected state field inputs, distinct failure exits, and the eventual short-write loop, so an independent reconstruction can preserve their ordering and result handling.

- Component ID: `abci`; this bounded storage and serialization question also advances RE-009 and the RE-017 state-loader investigation.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; the unlicensed reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was used for navigation and a separately authenticated historical binary, not copied source.
- Claim status: instruction bytes, linked addresses, FDEs, Location records, relocation entries, literals, branch targets and observed register/memory operations are observations. Format names, successful data flow through calls, ASCII case folding and the relationships between releases are inferences with the conditions below.
- Scope included and excluded: two selected continuation variants from an upper wrapper, an alternate poll-A wrapper, the state read, output routing, selected serializer inputs, output helper and write loop. Existing loader callers and their GOT sites are contextual boundaries, not re-owned. Process-entry reachability, all dispatch arms, every state field, complete serializer/helper closure, block execution, state-root computation and component gates are excluded.

## Reproduce

From the repository root with the authenticated `artifacts/node/115/hl-node` and the shared `tools/elf_index.py` and `tools/fde_extents.py` parsers available, use fresh output directories:

```sh
python3 tools/abci_state_export115.py --out research/work-items/RE-009-abci-state-export-115
python3 -m unittest tests.test_abci_state_export115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_state_export115.py --out work/re009-export-a
PYTHONHASHSEED=271 TZ=Pacific/Honolulu python3 tools/abci_state_export115.py --out work/re009-export-b
diff -r work/re009-export-a work/re009-export-b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-009-abci-state-export-115 work/re009-export-a
(cd research/work-items/RE-009-abci-state-export-115 && sha256sum -c MANIFEST.sha256)
```

For the optional historical cross-check, provide the original node #94 ELF at the relative reference path and use a fresh output directory. It is not required for ordinary generation or tests:

```sh
python3 tools/abci_state_export115.py --old-elf references/can1357-hl/bin/hl-node-mainnet-new --out work/re009-export-history
```

The generator authenticates #115 before parsing or writing, decodes ELF/FDE records with the repository parsers, excludes NOBITS from byte mappings, and calls no external programs. The optional cross-check separately authenticates #94. Generation and focused tests were run on Linux x86-64 with CPython 3.12.3, including a Python-only PATH without binutils. GNU objdump 2.42 was used only for bounded human inspection; its text is not parsed or included in generated evidence. The node and visor were not executed.

`extents.tsv` records selected `.eh_frame` ranges, CIE/FDE coordinates, file offsets and raw body hashes; `windows.tsv` retains unmasked instruction bytes and hashes. `edges.tsv` decodes only selected aligned transfers; `dispatch.tsv` reads signed relative table entries. `relocations.tsv`, `imports.tsv`, `locations.tsv`, `location-refs.tsv`, `operands.tsv`, `names.tsv`, `fields.tsv` and `constants.json` are decoded from the target bytes. `cases.tsv`, `dispatch-cases.tsv`, `map-cases.tsv` and `write-cases.tsv` are explicitly **synthetic models** of the pinned decisions, not observed executions. `summary.json` gives selected-record counts, and the manifest covers this README and every generated file.

## Evidence

All addresses below are linked ELF virtual addresses before rebasing; tables also provide file offsets. Each selected FDE is reconciled with `.eh_frame_hdr`, checked against overlaps and hashed. An unwind range is not proof of a complete source function or a complete caller census. The machine-code observations are limited to the selected windows and aligned transfers.

### Entry, selection and result handoff

| Stage | Observation |
| --- | --- |
| Upper wrapper | `0x2cd8370` sets a byte at its stack `+0x222` to zero and calls `0x2ae1690` at `0x2cd83a2` with the object beginning at stack `+8`. No process-entry caller is established. |
| Parent variants | After an earlier helper, `0x2ae1690` compares its stack word at `+0xe0` with 1. The selected equal branch reaches the call to poll A at `0x2ae1a47`; the other parent route can reach poll B at `0x2ae1eeb` after additional branches. For A, the window beginning at `0x2ae19b7` passes the original input, a stack destination and length `0x2c40` to a slot imported as `memcpy`. The later zero state is conditional on ordinary symbol binding and no intervening alias modification. |
| Alternate poll-A wrapper | `0x2b404b0` checks the first argument's word at `+8`, saves the second argument at `+0x10`, loads a nested pointer from its third argument and calls poll A at `0x2b40577`. On the selected normal return it clears the saved slot and guard, returns the saved value in `rax` and moves the poll's `eax` into `edx`. Nonzero guard values on entry or after polling lead to diagnostic paths; an empty saved slot also reaches a diagnostic, followed by `ud2` if it returns. This is a second static call edge, not proof that the caller supplies the selected command or that the wrapper is process entry. |
| Poll A | At `0x2ae41f4` the byte at object `+0x21a` indexes the relative table at `0x6040e4`; entry 0 is `0x2ae420b`. The later word at `+0xc0` is reduced by 2, with index 12 selected on borrow, and indexes the table at `0x60411c`. Word 4 selects index 2 and `0x2ae4ebc`. |
| Poll B | `0x2cde430` first calls `0x5ce5fb0`; the selected route requires its low return byte to be nonzero. It then uses object byte `+0x21a` and tables `0x60bf88` and `0x60bfc0`; state 0 and command word 4 select `0x2cde4b0` and `0x2cdefb5`. |
| Read then export | A calls the boundary `0x422e410` at `0x2ae4f0b` with Location `state.rs:102:40`; B makes the corresponding call at `0x2cdf007`. Each tests bit 0 of `al`. On the zero-bit path each places returned `rdx` in a stack slot and passes the slot address, the second input pair and Location `state.rs:113:9` to `0x422ed40`. These are new caller sites; the already mapped loader's separate call site and GOT entries are not repeated. |
| Completion | On writer return zero, A calls `0x2a9ff60` with the saved read-result pointer and B calls `0x2c86fc0`. The following windows include multiple indirect helper calls and conditional cleanup branches; their shared slots and helper bodies are boundaries. Assuming those calls return normally, the selected finish paths clear flag bytes and set object `+0x21a` to 1, then A returns `al=0` while B returns `al=1`. The parent tests A's low byte for zero and B's for 2, with different continuation paths. This does not establish the full source-level poll or result types. |

`dispatch.tsv` contains the 14 selected resume entries and 13 selected command entries for each variant. The tables are byte-hash-pinned. For command word 4, `4 - 2 = 2` selects the documented entry. Words 0 and 1 select index 12; word 14 also selects index 12. The inspected command-table sequence has no bounds check for a larger computed index. The synthetic table records this arithmetic without asserting that invalid words are dynamically reachable or accepted.

### Output routing and the serializer boundary

The output routine `0x422ed40` first compares the whole supplied byte span with the nine-byte immediate `2f6465762f6e756c6c`. Exact equality returns zero before component parsing, serialization or the later output helper. This is a byte comparison: differing length, byte or case does not take the shortcut.

On other inputs, the routine calls the component parser. Only its returned tag 9 reaches a backward scan of the returned component. A component equal to two dots, no dot, or a dot at position zero takes the text branch. For a dot after at least one preceding byte, the routine compares the suffix after the final dot with bytes `726d70` at `0x4659e5`. The callee `0x159fca0` folds ASCII `A` through `Z` to lowercase on both sides; other byte values are unchanged. Therefore all eight ASCII case variants of the three-byte suffix select the binary branch. This conclusion is conditional on the parser returning tag 9 and the stated component span; no complete path-parser or filesystem-normalization claim is made.

| Selected condition | Consequence in the pinned code |
| --- | --- |
| Exact nine-byte shortcut | Return zero without calling either serializer or the subsequent output helpers. The caller has already made its read call. |
| Tag 9 and a qualifying case-folded suffix | Initialize a vector-like three-word object and serializer configuration bytes `00 04 00 01`, followed by zero, then call `0x3c13960`. A first result word other than `0x8000000000000004` takes the binary error wrapper. |
| Other parser tag, component or suffix | Request `0x80` bytes and call text serializer `0x3c136f0`. Null allocation reaches a failure helper. A nonzero serializer result or the checked sentinel reaches error conversion before the common output stage. |
| Successful selected serialization | Call output-preparation helper `0x15020f0`. Its nonzero return bypasses the next call; zero calls `0x15024a0` with the buffer and original destination pair. The buffer is released conditionally before the raw helper result is returned. |

At the binary serializer, the configuration gives byte `+0xb = 1` initially. Under successful helper returns and preservation of that byte at subsequent tests, the code requests a one-entry outer map header, passes literal `exchange` to a string writer, then requests a 59-entry inner map header. The selected map-header helper `0x3d4f6d0` and marker packer `0x3d52310` produce header byte `81` for count 1 and bytes `de003b` for count 59 on their normal capacity paths. These headers are separated by the `exchange` string-writer call; its full behavior is outside this packet. The map writer has a distinct error-result store and capacity-growth paths. The emitted marker shapes support a MessagePack-family interpretation; the complete wire format is not established.

The text route `0x3c136f0` stores opening byte `7b`, passes the same `exchange` literal to a helper, stores separator bytes `3a20`, calls `0x3c2f460` with the dereferenced input pointer, and reaches a closing-byte `7d` store on the selected successful path. Selected depth, buffer-capacity and nonzero-return checks are retained as windows, but escaping, growth helpers and all nested text fields remain helper boundaries.

`names.tsv` reports 27 fixed-pattern literal-writer reference candidates in the binary serializer FDE, not all 59 advertised entries or a complete state schema. The pattern scan alone is not an instruction-boundary census. The following ten name/operand associations have separately retained instruction-aligned windows and appear in `fields.tsv`. Offsets are relative to the dereferenced serializer input, and an address calculation does not establish a field's type or complete serialized contents. Name emission depends on the writer flag and prior helper results.

| Name | Offset | Observed operand |
| --- | --- | --- |
| `cls` | `+0x7c0` | Address passed to a helper. |
| `spot_infos` | `+0x90` | Address passed to a helper. |
| `token_infos` | `+0xa8` | Address passed to a helper. |
| `canonical_tokens2` | `+0xc0` | Address passed to a helper. |
| `allow_duplicate_token_names` | `+0x3e8` | Byte loaded and saved before the name-writer call. |
| `fee_schedule` | `+0x7d8` | Address passed to a helper. |
| `unrewarded_users` | `+0x930` | Address passed to a helper. |
| `user_states` | `+0x888` | Address passed to a helper. |
| `user_to_main_agent` | `+0x1fd0` | Address passed to a helper. |
| `address_to_nonce_set` | `+0x20a8` | Address passed to a helper. |

### Output and failure ordering

`0x15024a0` first obtains a generated path-like pair through `0x1502f90`, then passes that pair and the serialized buffer to `0x5ca5110`. A nonzero return branches to an error-construction helper. On zero, it performs another destination-dependent check/preparation and then calls `0x1502da0`; its final filesystem semantics are not established here. The separately pinned `0x15020f0` has its own test, optional preparation call, zero return and error-construction path. Those calls and relocations are observations, not proof that the data is durable or that the final operation is atomic.

`0x5ca5110` treats its third argument as the buffer pointer and fourth as the remaining byte count. After its selected open-like helper succeeds, it loads the dynamic `write` import and iterates as follows:

| Raw result or condition | Observed consequence |
| --- | --- |
| Remaining count is zero | Bypass `write`, set the selected success value to zero, and call the dynamic `close` import. |
| Return is positive and no greater than remaining | Advance the pointer by the returned value, subtract it from remaining and repeat; zero remaining takes the success exit. |
| Return is zero with bytes remaining | Select a nonzero static error value and close. |
| Return is all ones | Call `__errno_location`; error value 4 takes the retry path without changing pointer or remaining, and other values take the error/close path. |
| Other raw return exceeds remaining | Reach the failure helper and `ud2` if it returns. |
| Selected open-like result has tag 1 | Return its saved error value before entering the write loop. |

`imports.tsv` resolves the ELF's dynamic-symbol records for `memcpy`, `write`, `__errno_location` and `close`; dynamic interposition and actual syscall behavior are not observed. The write-step and map-header boundary vectors are static models, including impossible or corrupted synthetic values, and are not target execution.

Both caller variants route read-bit failure and nonzero writer return to separate diagnostic paths; each reaches `ud2` if its called diagnostic returns. The pinned bytes contain a `Result::unwrap` diagnostic literal, but the complete source-level error type is not established. Helpers can modify buffers or external state before an error; this packet makes no rollback claim.

### Historical release cross-check

The earlier `RE-017-abci-state-link-94` record, retained in repository history, is bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The optional byte-level check above authenticates that ELF, reconciles its `0x22ae8a0..0x22b107c` FDE, and verifies its selected raw window and these locations and direct edges:

| Release | Read location and call | Write location and call | Selected read-result test |
| --- | --- | --- | --- |
| #94 | `state.rs:86:40`, reference `0x22aefdb`, call `0x22aefea` to `0x3c155a0` | `state.rs:97:9`, reference `0x22af04e`, call `0x22af060` to `0x3c165b0` | An output-buffer first word is compared with 2. |
| #115 A | `state.rs:102:40`, reference `0x2ae4f04`, call `0x2ae4f0b` to `0x422e410` | `state.rs:113:9`, reference `0x2ae4f2d`, call `0x2ae4f3f` to `0x422ed40` | Bit 0 of `al` is tested and `rdx` is saved. |
| #115 B | `state.rs:102:40`, reference `0x2cdf000`, call `0x2cdf007` to `0x422e410` | `state.rs:113:9`, reference `0x2cdf029`, call `0x2cdf03b` to `0x422ed40` | Bit 0 of `al` is tested and `rdx` is saved. |

The same historical check verifies that the earlier #94 `state.rs:107:37` wrapper calls `0x3c155a0`, the read helper also used at its `:86:40` site. The #115 calls independently name the new read boundary in the new ELF. Similar ordering and path Locations make a cross-release relationship plausible, but the distinct result representation, addresses and data layouts prevent a claim of binary or semantic equivalence. No #94 result is relabelled as #115 evidence.

### Inferences and unresolved questions

Under the selected state, command, parser and normal-return conditions, the value returned by the read boundary is supplied to the serializer, and its produced buffer is supplied to the output/write chain. Calls, aliases and dynamic bindings may change behavior; no runtime trace proves reachability or pointer preservation across unexamined code. The output path exposes an exportable state representation, not a demonstrated live consensus-state mutation. The source-level types of the saved pointer, context, result words and most helper inputs remain unknown.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler/linker flags and two-build comparison: not yet available. Raw and normalized candidate-to-target comparison, masks, complete call-target and helper closure, relocation/vtable/data closure and whole-ELF comparison: not yet measured. The recorded windows are original unmodified target bytes for static evidence, not transplanted implementation code.

## Results and limitations

`summary.json` reports 14 selected FDEs, 62 byte windows, 90 selected transfers, 54 table entries, 2 Location records, 4 Location references, 16 scalar operands, 4 dynamic imports, 27 literal-reference pattern candidates, 10 field operands, 19 synthetic route cases, 9 dispatch cases, 10 map-header cases and 9 write-step cases. These are bounded record counts, not function coverage or an equivalence denominator. The focused suite passes 27 tests with zero skips, including a bad target digest, every selected window, every selected transfer opcode and displacement, every recorded table entry, all 27 name literals, selected import/Location corruption, overlapping FDEs, NOBITS and out-of-range mappings, ASCII fold boundaries, and serializer/write failure controls. Two independent regenerations are checked across hash seeds and time zones.

The full component's begin/action/end-block paths, state-root inputs and their relationship to this exporter remain open. No full component gate, node build, runtime differential, hosted CI or container result is claimed. Next question: identify the unowned producer and consumer of this export's saved state pointer and establish whether it is the same object that enters a verified block transition and state-root capture.
