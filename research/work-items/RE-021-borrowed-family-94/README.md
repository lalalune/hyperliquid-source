# RE-021: revision-selected borrowed registry and post-call state in node 94

This packet identifies an alternate handler family's revision-selected borrowed registry, ordered post-call account updates and output-state reset, so a reconstruction can preserve their data flow and failure ordering.

- Component ID: `evm`; RE-021 extends the existing BLAKE2b precompile question and is not a new official TASKS row.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied.
- Claim status: bytes, FDE and exception records, relocations, and selected branch destinations are **observations**. Handler, registry, account and callback names, and composition across normal calls, are **inferences**. Runtime selection, the unselected lookup's result, complete helper behavior, and behavioral equivalence remain **unresolved**.
- Scope included and excluded: the alternate revision selector, its 15 preexecution constructors and six provider adapters, the revision-9 execution and postexecution constructors, the executor and selected callback/account-update bodies. Existing registry constructors, frame construction, runtime lookup, wrapper and compressor are dependency boundaries. Node #115, visor, live inputs, captured execution, networking and a full component reconstruction are excluded.

## Reproduce

From the repository root with the authenticated node #94 artifact. The recorded environment used CPython 3.12.3 and GNU objdump 2.42. The exporter uses Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it checks the complete input hash before parsing, excludes SHT_NOBITS from file reads, and launches no external program. Objdump was used only to inspect human-readable instruction boundaries, not to generate any evidence number or listing. No target code is executed or emulated.

```sh
python3 tools/re21_borrowed_family94.py --out research/work-items/RE-021-borrowed-family-94
python3 -m unittest tests.test_re21_borrowed_family94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-borrowed-family-94 && sha256sum -c MANIFEST.sha256)
```

For the independent regeneration check, substitute two different empty relative directories for the placeholders:

```sh
PYTHON_BIN=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/re21_borrowed_family94.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/re21_borrowed_family94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$PYTHON_BIN" -m unittest tests.test_re21_borrowed_family94
```

The exporter writes the JSON and TSV evidence files; this README and the manifest are packaging files. The manifest covers every other file in this folder. Outputs have no time, host path, external-disassembler output, or hash-seed-dependent ordering.

## Evidence

All code/data addresses are linked ELF virtual addresses before load bias. `functions.tsv` records file offsets, exclusive FDE ends, FDE/CIE/LSDA coordinates and body hashes; `function-bytes.json` retains the selected bytes. FDE extents are unwind ranges, not independently proven source-function boundaries. `windows.tsv` retains reviewed byte windows, and `transfers.tsv` derives the selected direct destinations from signed displacements. These are bounded selections, not a complete instruction census or CFG. `unwind.json` and `exception-sites.json` retain the raw frame and LSDA call-site data; action chains and exception types are not decoded.

### A separate revision family

The earlier [compression packet](../RE-021-blake2b-compress-94/README.md) identifies the address-09 object and callback. Open PR #1373 maps the standard registry's constructor lineage and a runtime lookup, while #1540 describes a different revision-9 read family. Their selected bodies are not re-exported here. Open PR #1612 follows an inspected handler family; the builder and executor below are different FDEs. This packet identifies an alternate family, but its composition with those pending results requires their independent review.

`0x37fb9e0` reads an input byte, checks its unsigned value against 19, and indexes the 20 signed relative entries at `0x59a830`; the default covers larger bytes. Each case calls four constructor groups and stores a canonical byte on its normal path. The first pair from the second group is copied into the handler's provider position. `revisions.tsv` expands the machine-code table to all 256 byte values; it is an input-domain projection, not proof that all values are valid revisions.

| Requested byte | Canonical byte | Prior constructor mode selected by new adapter | Address 09 under prior lineage |
| --- | --- | --- | --- |
| 0–5 | 0, 2, 4 or 5 | 0 | absent |
| 6–8 | 6 or 8 | 1 | absent |
| 9–10 | 9 | 2 | present |
| 11–16 | 11, 12, 15 or 16 | 3 | present |
| 17 | 17 | 4 | present |
| 18–19 | same byte | 5 | present |
| 20–255 | 255 on the default normal arm | 5 | present |

The final column is conditional on the earlier constructor-derived lineage; it is not a captured table or a claim about deployed activation. The new adapters all produce a zero word followed by a constructor result. Their cache pointers are in NOBITS storage, so their contents are not read from the ELF. For inputs 9 and 10, `0x37fc098` calls preexecution constructor `0x32b84c0`, whose first descriptor `0x56e19f0` has a relative relocation at `+0x28` to new adapter `0x328c570`. That adapter calls the prior mode-2 constructor `0x4e99650`. The earlier work reports that mode 2 includes the address-09 callback. `flow.json` retains the 20-byte key and callback relocation only as prior dependency checks.

For the same case, `0x37fc0b2` calls execution constructor `0x32cace0`. The output pair at `+0x20/+0x28` has descriptor `0x56e6400`; its `+0x28` relocation selects adapter `0x3287080`. The case copies the constructor's 176-byte block to the handler at `+0xe8`, and the common tail copies the handler to engine `+0x110`. Thus the provider pair is at engine `+0x158/+0x160` and the selected frame pair at `+0x218/+0x220`. The independent data, relocation and fixed-copy witnesses are in `flow.json`, `callback-pairs.json` and `windows.tsv`. This offset composition assumes the relevant allocations and copies complete normally and the pairs are not replaced later.

### Publication, call boundary and failure ordering

`0x37f98f0` first calls a callback and requires returned byte 5. It invokes the provider pair, passes its result to the previously researched set-derivation boundary `0x34389a0`, and extends the separate context set at `+0x80` through `0x36e3590`. It then tests the old context word at `+0xe8`: zero skips destruction, while nonzero calls newly selected `0x34d74a0`. The new five-word representation is copied to context `+0xe8` after that call. The destructor scans occupied 48-byte records, branches on their value tags, performs selected retain/release or dynamic-drop operations, and eventually releases the backing allocation; external destructor and allocator behavior remains a boundary.

After two further byte-5 gates and a checked subtraction, environment byte `+0x294` equal to 1 selects the existing frame constructor through relocation slot `0x5774588`. A null result takes a separate failure edge. Otherwise the executor invokes the engine pair at `+0x218/+0x220`, whose revision-9 descriptor above resolves to `0x3287080`. The adapter calls the existing FDE at `0x32aceb0` and releases its frame on the selected normal return. That FDE is already present in `foundation-keyed-multiply-xor-mixer-94` and is not reselected or reinterpreted here.

Under the prior mode-2 registry lineage and frame-layout results, the selected executor can install a borrowed registry containing address 09 and pass a frame to the existing runtime boundary. The two selected entry points must be connected by a caller passing the constructed engine to the executor; that caller is not selected here. The new packet does **not** independently establish the borrowed lookup's full-key hit, the BLAKE2b wrapper's invocation, or a live route through the runtime. The already mapped #1373/#1540 lookup paths concern other FDEs and are not silently substituted for this boundary.

| Selected condition | Observed consequence |
| --- | --- |
| First callback byte is not 5 | Return an error-shaped object before provider invocation. |
| Second or third callback byte is not 5 | Take its respective error arm after registry publication. |
| Selected subtraction borrows | Branch to a separate failure call after publication. |
| Environment byte differs from 1 | Take the distinct alternate-frame branch. |
| Frame constructor returns null | Branch to the separate null-frame failure path. |
| Frame callback's first result word equals 4 | Copy selected payload words, write sentinel `0x8000000000000002`, and return; post-call callbacks below are bypassed. |
| Frame result differs from 4 and its low 32 bits equal 3 | Enter the separate interpreter-action path. |
| Other selected frame-result values | Enter the post-call callback sequence described below. |

The third row does not claim a transaction rollback. The explicit null-allocation table contains 77 reviewed checks: four in each of the 15 preexecution constructors, 11 in the selected execution constructor, and six in the selected postexecution constructor. The table does not enumerate every allocation in the builder or executor.

The LSDA interval covering the old-map destruction call `0x37f9ab7` lands at `0x37fb836`. That landing writes the new five-word representation into context `+0xe8` before calling the unwind-resume boundary. A prior set-derivation/extension unwind lands at `0x37fb867` and conditionally drops the temporary provider if its first word is nonzero. The frame adapter has distinct landing pads for the runtime call and for the subsequent dynamic frame-payload drop. These are static exception-table edges, not observed exceptions or a complete cleanup proof.

### Post-call status, account updates and output

The selected execution constructor's first descriptor `0x56e63a0` resolves its `+0x28` method to `0x3286e10`. The selected postexecution constructor `0x32bded0` supplies six additional descriptors; the executor calls the first four on the selected non-interpreter continuation.

| Order | New method | Selected effect |
| --- | --- | --- |
| Result adjustment | `0x3286e10` | Selects one of two result subobjects, copies the context environment word at `+0x238` into the selected result, clears two words, then restores them according to the status byte. Returns byte 5. |
| Capped adjustment | `0x3286bf0` | Checks a signed 64-bit addition, stores it, then checks an unsigned subtraction and caps the stored word at half the difference. |
| First account update | `0x3287b50` → `0x32d1d80` | Selects a 20-byte key from environment `+0x280`, loads an account through an external boundary, checks a two-word sum, and updates four words at account `+0x40`. |
| Second account update | `0x32876d0` → `0x32d2e70` | Selects a 20-byte key from environment `+0xd0`, loads an account, sets flag mask `0x04`, checks two subtractions, and updates four words at account `+0x40`. |
| Final output | `0x3286e80` → `0x32d36c0` → `0x32ac4c0` | Copies a 96-byte result input, resets context byte `+0xb8` to 5, and follows either an old-error path or a checked state-reset and output-assembly path. |

For the status adjustment, bytes 0–4 restore both cleared words, bytes 16–21 restore the first word only, and all other byte values leave both zero. `status-classes.tsv` expands the pinned comparisons over 256 possible byte values; it does not claim all of them occur. The output word is written before this classification.

For the capped adjustment, let `prior` and `adjustment` be signed 64-bit interpretations of the two machine words. A signed-add overflow branches before the new word is stored. Otherwise their sum is stored. If unsigned `remaining > total`, the subsequent subtraction borrows and the failure branch occurs **after** that store. On the normal arm the final word is the unsigned minimum of the stored word and `(total - remaining) >> 1`. Source-level gas/refund names are inferred rather than established.

Both account-update methods first select the same kind of four-limb value. Treat the four consecutive little-endian limbs at environment `+0x240` as `cap`, those at `+0x90` as `left`, and those at `+0x180` as `right`. If the 32-bit word at environment `+0x178` is 1, the selected value is the unsigned minimum of `cap` and `(left + right) mod 2^256`; otherwise it is `cap`. Carry out of the high limb of `left + right` is discarded before the comparison. `credit-selection.json` retains both sets of operand instructions, the guard branches and final comparison bytes, with the complete selected windows in `windows.tsv`. The names `cap`, `left` and `right` describe the observed calculation, not established source fields.

After that selection and the 64-bit multiplier are chosen, the machine computes the product's low 256 bits and adds them to the existing four account words. An overflow of **that addition** selects four all-one words. Overflow discarded during the preceding multiplication alone is not a saturation condition. The first method checks its 64-bit multiplier addition after account loading and before the four account-word stores. The second sets the flag before either subtraction, so either borrow can leave the flag write already visible. Both copy a non-5 account-load result to their output instead of performing the selected credit. These statements assume valid pointers and ordinary returns from external account and allocation helpers; they do not establish persistence or transaction-wide atomicity.

For the final method, an old context byte other than 5 selects an error-shaped output with sentinel `0x8000000000000002` after the context byte has been reset; a dynamic cleanup remains external. On the byte-5 path, two selected unsigned subtraction-borrow branches precede the output-state reset helper `0x32ac4c0`. The executor's final callback receives a 96-byte copy of the result object that the earlier status adjustment examined. The final method again selects its subobject using the first word and copies the status word from subobject `+0x40` to its stack before the helper call. The selected status translator `0x324d170` indexes the signed-relative table at `0x580fd4` using the low byte of that copied word, returns a class in `al` and a byte in `dl`, and the caller indexes the second table at `0x582234` with that class. Intervening callback side effects and aliasing are separate assumptions. The exact status-to-class and output-arm rows are in `output-status.tsv`; their table bytes, class counts and first unselected entry are in `output-status.json`.

On its selected normal path, `0x32ac4c0` first conditionally releases an old allocation described by context `+0x58/+0x60`, copies a 32-byte reset template to context `+0x58..+0x77`, and writes a newly mixed word at `+0x78`. The template's file bytes are zero, but its first word has a `R_X86_64_RELATIVE` relocation with addend `0x202e90`: after relocation that word is load bias plus the addend, while the other three words are zero. It then requests 24 bytes. A null return branches to a separate allocation-failure helper **after** those writes; `state-reset.json` records the file bytes, relocation, allocation immediate and null branch. On a nonnull return it conditionally releases the prior context `+0x20` record list, installs a one-element replacement described by context `+0x18/+0x20/+0x28`, and clears `+0xa8`. It copies the old five words from context `+0x30..+0x57` into output `+0x00..+0x27`, copies the same relocated template to context `+0x30..+0x4f`, and writes a new mixed word at `+0x50`. Finally it moves the old three words at context `+0x00..+0x17` into output `+0x28..+0x3f` and replaces those context words with `0, 8, 0`. The mixed words depend on thread-local and stack-address inputs; their runtime values are not recovered. Lazy initialization, allocation and release helpers are external boundaries, and these static writes do not establish transaction-wide rollback.

The exporter takes the contiguous prefix whose destinations stay within the translator FDE: input bytes 0–112, of which 68 point to an `ud2` instruction and 45 reach a return shape. The next table word targets outside that FDE, so it is a boundary for this bounded scan, not a proof about the table's full extent or permissible runtime statuses. The return shapes lead to these caller arms:

| Returned class | Prefix entries | Output arm | Selected effect |
| ---: | ---: | --- | --- |
| 0 | 4 | `0x32d38cc` | Assemble an output containing the selected post-subtraction words. |
| 1 | 3 | `0x32d3973` | Select a different output representation. |
| 2 | 31 | `0x32d3968` | Use first output word `0x8000000000000001`, then join output assembly and cleanup. |
| 3 or 4 | 7 | `0x32d3b15` | Prepare a diagnostic, call through slot `0x576e098`, then reach `ud2` if that call returns. |

These are selected static edges, not executions or an assertion that the trap cases are valid runtime inputs. Output cleanup invokes dynamic methods and can call external allocation helpers. The full algebra of the prepared output and all cleanup actions remain unresolved.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, original compiler/linker settings, two-build comparison, relocation masks, helper/data closure, native behavior and whole-ELF identity are **not yet implemented or measured**. No executable bytes are transplanted.

The focused tests check the input digest, byte windows at both ends, exact branch opcodes and displacements, revision table and case-entry corruption, descriptor/relocation changes, allocation checks, FDE/index correspondence, exception headers, and invalid, crossing, ambiguous or NOBITS-backed reads. The status and arithmetic checks are synthetic projections of the pinned byte predicates: they do not execute captured instructions. The selection model is compared with a separate Python big-integer oracle over 1,024 bounded operand combinations, including discarded high carry, and the credit model over 256 combinations; boundary controls distinguish multiplication truncation from addition saturation and check the earlier flag/store on subsequent borrow.

The focused suite passed 30 methods with zero skips. Two fresh generations under different hash seeds and time zones, with an empty program-search PATH, matched each other and the retained generated evidence byte for byte. Artifact verification and catalogue consistency passed. The full repository suite, hosted CI, containers and target execution were not run.

## Results and limitations

`summary.json` reports 37 selected FDE intervals totaling 29,550 bytes, 56 reviewed windows, 53 selected transfers, 15 case targets, six provider adapters, 11 execution pairs, six postexecution pairs, 77 selected allocation checks, 22 LSDA tables and 319 LSDA call-site rows. The 77 checks cover the explicitly selected constructors, separate from the output-state helper's 24-byte allocation. The 256 revision and 256 status-byte rows are expanded byte-domain projections; the 113 final-output status rows cover only the stated bounded table prefix. These are not captured calls or node coverage. No component gate is advanced; `evm` remains 0/4, and the broader COMPONENTS first task remains unfinished.

The supplied checkout and open/merged PR inventory were checked for selected-FDE overlap. The environment does not access the network, so a submission-time public main and PR refresh remains necessary. No claim is made about runtime hash seeds, unselected lookup semantics, dynamic callback replacement, all exception actions, complete state-transition inputs, or exact dependency/fork boundaries.

Next question: review the existing `0x32aceb0` borrowed lookup and dispatcher under its existing ownership, then independently validate the composed address-09 route and the two account-update contracts with a separately authorized target-grounded harness.
