# RE-017: node 115 ABCI context to pending-record drain

This packet shows how a constructor derived from the state-loader path places an expanded-state pointer in a captured owner and how a later cleanup reads that owner's state word to populate the `height` field of a pending ABCI record, including the empty, serialization-failure, output, and unwind paths.

- Component ID: `abci`; this is a bounded RE-017 question connected to RE-009 state/snapshot work.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was a navigation clue only and no code was copied.
- Claim status: the listed bytes, offsets, transfers, relocations and exception-table entries are observations; object identities and semantics below are conditional inferences, not execution traces.
- Scope included and excluded: the selected constructor-to-callback handoff, pending record drain, its selected height-read path, serializer and buffered output, including selected failure/unwind exits. The prior loader and existing startup/constructor instructions are contextual boundaries. Process entry, dispatcher execution, all aliases, all paths and full component completion are excluded.

## Reproduce

Run from the repository root with `artifacts/node/115/hl-node`, `tools/elf_index.py` and `tools/fde_extents.py` present. The tool authenticates the full binary before creating output, reads ELF bytes in Python, never invokes an external program, and does not execute the binary. These commands use initially empty relative directories `.re017-check-a` and `.re017-check-b`:

```sh
python3 tools/abci_context_result115.py --out research/work-items/RE-017-abci-context-result-115
python3 -m unittest tests.test_abci_context_result115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=7 TZ=Etc/UTC python3 tools/abci_context_result115.py --out .re017-check-a
PYTHONHASHSEED=984 TZ=Pacific/Honolulu python3 tools/abci_context_result115.py --out .re017-check-b
diff -r .re017-check-a .re017-check-b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-abci-context-result-115 .re017-check-a
(cd research/work-items/RE-017-abci-context-result-115 && sha256sum -c MANIFEST.sha256)
```

The local checks used Python 3.12.3 on Linux x86-64; generation and focused tests were also run with a PATH containing Python and no binutils. GNU objdump 2.42 was used only for exploratory human reading, never by the tool or tests. Reproduction has no target execution, network, or chain side effects. The generated files are `functions.json`, `windows.tsv`, `operands.tsv`, `branches.tsv`, `calls.tsv`, `landings.tsv`, `relocations.tsv`, `literals.tsv`, `layout.json`, `arithmetic.json`, `location.json` and `summary.json`. The manifest covers these files and this README.

## Evidence

All instruction, data and FDE coordinates are linked ELF virtual addresses before any rebasing. Tables additionally give file offsets; for example the drain FDE starts at VA `0x5a8b130`, file offset `0x5a8a130`. `functions.json` reconciles the selected FDE ranges with `.eh_frame_hdr` and saves full range bytes and their SHA-256. An FDE range is an unwind range, not proof of a complete source function or a complete caller census. The other tables record only the listed pinned instructions, operands, relocations, literals and LSDA call-site ranges; they are not whole-binary coverage measurements. The operand, branch and call tables label each site `selected` or `context`; all relocation rows are `anchor-only` and do not claim ownership of existing GOT slots. The parser accepts only the explicit selected instruction forms and LSDA encodings, and excludes fileless `SHT_NOBITS` sections.

### Selected route

| Selected FDE start | Role and observed connection |
| --- | --- |
| `0x567bd50` | Builds the captured owner body, copying a context that contains the expanded-object pointer. |
| `0x567bc40`, `0x567bb70` | Two selected transforms copy the owner body; the first has a sentinel-dependent cleanup branch. |
| `0x2a92960` | Callback adapter; its normal and selected unwind paths both call `0x2aaea40`. |
| `0x2aaea40` | Calls the drain before an atomic decrement of the owner word and later checking the pending slot. |
| `0x5a8b130` | Takes the pending slot, forms a record, performs a temporary serialization and calls the record sink. |
| `0x4f0e990`, `0x4fbd410` | Selected height-read wrapper and leaf; the leaf reads a word through the preserved expanded-object pointer. |
| `0x595a6b0` | Conditional record sink; a disabled sentinel can return before encoding, otherwise the selected route decides whether to roll and encode. |
| `0x50e2f80`, `0x4d6d740`, `0x14c37f0` | The line encoder, record serializer and buffered output helper on the selected route. |

The route begins at an existing boundary, not a new ownership claim on the loader. The #115 Location data at `0x64767a8` resolves to `l1/src/abci/state.rs:123:37`; the existing reference at `0x3c1352f` is checked as contextual evidence. Prior loader-handoff work in PR #2047 connects that Location path to the constructor input under its stated branch and helper conditions. The constructor passes its first argument into an existing clone/expansion boundary and receives an expanded-object pointer in `rax`. At `0x5a6c0af` it saves that pointer and at `0x5a6c10a` stores it in the context. This packet does **not** establish that the loader's original pointer and the expanded-object pointer are identical, or that every field survived the intervening clone unchanged.

The following selected byte arithmetic is reproduced by `operands.tsv` and `layout.json`, conditional on normal calls, the named copy binding, and no conflicting writes through aliases:

| Handoff | Byte-backed relation |
| --- | --- |
| Context to owner body | Pointer offset `0x450` in the copied context, plus context offset `0x6b0`, gives owner-body slot `0xb00`. |
| Allocation to body | The allocation has a `0x10`-byte prefix before the copied `0xb28`-byte body. |
| Owner to callback object | The owner pointer moves through the selected staged copies to future offset `0x838`; copying from future offset `0x198` puts it at callback offset `0x6a0`. |
| Descriptor | The `0x718`-byte, 8-aligned callback descriptor at `0x64471a0` has a relocated callback entry at `0x64471b8` to `0x2a92960`. Runtime dispatch of that entry is an explicit assumption. |
| Owner to state word | The drain loads callback `+0x6a0`, passes allocation `+0x10` to the read wrapper, and the leaf reads `[body+0xb00]` then `[pointer+0x28]`. The non-instrumented wrapper tail path and a selected leaf return preserve that word in `rax`. |
| State word to record | The drain keeps that returned word, puts it at record `+0x80` and also passes it as the sink's second argument. The serializer's third field label is `height`; its second field is `resps` at record `+0x58`, where this drain sets byte 2. |

The literal `crash_height` accompanies the selected read call. Together with the serializer field label it supports a height interpretation; the raw `+0x28` word's complete source-level type and invariants remain unproved. The first field label is `abci_block`. These labels do not identify every nested field or establish a state root.

### Selected decisions and failure exits

| Condition | Observed transfer or effect |
| --- | --- |
| Owner assembly length has its high bit set | The assembler enters its failure helper; if the helper returns, the selected path reaches `ud2`. Zero length takes a separate path; nonzero allocation failures join failure helpers. The selected constructor call supplies length 16, so the high-bit and zero-length cases are not reached from that call with an unchanged argument. |
| Pending word at callback `+0x5f8` is `0x8000000000000000` | The drain stores that sentinel first, then the overflow branch on negation returns without forming a record. Any other 64-bit value takes the record path, with the slot already set to the sentinel. |
| Height read on the non-instrumented fast wrapper path | The wrapper tail-transfers to the leaf. The selected leaf path reads the state word and releases its lock; its alternate instrumentation and time-accounting paths are not completely characterized. |
| First temporary allocation is null | The drain calls its allocation-failure helper with size `0x80`; if it returns, `ud2` follows. |
| First record serializer returns nonzero | A buffer pointer and its capacity are passed to a release-like boundary when the capacity is nonzero, an error-like object goes to cleanup boundaries, and execution rejoins the sink call if those helpers return normally. A selected sentinel in the temporary buffer metadata also joins error cleanup. |
| First serializer succeeds | The temporary encoded buffer is retained until after the sink call and then passed to the release-like boundary if its capacity word is nonzero; the sink receives the record, not those temporary bytes. |
| Sink's word at its `+0x18` equals the signed-minimum sentinel | The sink returns before the line encoder. Other selected paths compute a bucket; when the new bucket is not greater than the stored bucket, they take the direct encoding path. A roll-helper failure has its own recorded branch. |
| Line encoder succeeds | It serializes the same record again, appends byte `0x0a` (growing if needed), and calls the buffered output helper. The second serialization happens only if the sink reaches this encoder. Serializer field failures return through error cleanup; after either normal encoder return and a normal intervening helper return, the sink proceeds to its flush boundary. |
| Buffer free space equals requested length | The buffered helper takes its fallback rather than the direct copy; direct copy requires strictly more free space. This statement assumes a valid `used <= capacity` buffer. |

For the selected unsigned sink word `n`, the bytes implement `max(n - 1, 0)` followed by multiplication by `0x346dc5d63886594b`, taking the high half and shifting by 11, then multiplying by 10000. `arithmetic.json` records that the reciprocal product exceeds `2^(64+11)` by 432, which is below `2^11`; this establishes the quotient `floor(max(n-1,0)/10000)` for the unsigned 64-bit domain. The sink compares the resulting bucket with its previously stored word. This arithmetic does not establish a filename, runtime configuration, or successful write.

`landings.tsv` decodes the supported call-site entries from the selected LSDAs, without interpreting the action/type tables. The callback's upstream call is covered by a range landing at `0x2a929d0`: that landing invokes the same cleanup and then resumes unwinding. The call to cleanup during that landing has a separate LSDA landing at `0x2a929e3`, an indirect boundary whose helper semantics are not inferred. For the drain, the height-read, first-serializer and sink calls have distinct landings `0x5a8b3be`, `0x5a8b390` and `0x5a8b380`, respectively. The first passes the saved pending value to a cleanup helper; the latter two conditionally pass a temporary buffer to a release-like helper and the assembled record to a cleanup helper before the unwind-resume boundary. Helper internals and exceptions raised during those cleanups remain boundaries. The leaf has selected lock-release and wakeup cleanup instructions; the table does not by itself prove all personality or action semantics.

### Earlier release as navigation only

The retired #94 record is bound to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; it described `l1/src/abci/state.rs:107:37` and a release-specific wrapper at `0x3273810`. The #115 Location bytes and its reference above were independently read from the authenticated #115 ELF. The older binary was not an input here, and no address, tag, object layout or behavior is transferred across releases or claimed equivalent.

### Inferences and unresolved links

The separately reviewed block-to-root packet in PR #2107 identifies an engine context at owner-body offset `0x6b0` and its pointer slot at `0xb00`. The selected owner construction here establishes those same offsets for a loader-fed expanded object; the numerical match alone does not prove that the separately analyzed block execution used this same owner instance. The upstream callback operation remains opaque in this packet because its function is already present in another open contribution.

Under the listed copy, calling-convention, normal-return, no-alias-write and callback-dispatch conditions, the expanded-object pointer produced by the loader-fed constructor can be followed into the captured owner, and its `+0x28` word can be followed into the record and sink. Those conditions are not a captured runtime execution. The prior loader relationship is contextual and depends on the separate loader-handoff evidence. The allocation error helpers, indirect dynamic binding, scheduler, full clone, all serializer subtypes, sink-open details and root/snapshot semantics remain unresolved.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler/linker flags and two-build comparison: not yet applicable. Raw/normalized binary comparison, masks, relocation or vtable closure, helper closure and whole-ELF equivalence: not yet measured. The saved target bytes are evidence and are not transplanted into an implementation. No captured node or visor was run.

## Results and limitations

`summary.json` reports 12 selected FDEs, 66 byte windows (47 selected FDE windows and 19 contextual windows), 57 operands, 41 branches, 29 calls/transfers, 94 LSDA call-site records, 14 relocations and 5 literals. These counts describe this packet only. The focused suite passed 23 tests with zero skips, including corrupted digests, real instruction and FDE changes, relocation type/addend and duplicate controls, real and synthetic LSDA corruption, Location bytes, fileless/out-of-range sections, pending-sentinel neighbors, bucket boundaries and buffer equality. The tests validate the extractor and models; they do not run target instructions. The two independent regenerations must match byte for byte.

No component gate or binary-equivalence claim is requested. Full loader-to-process-entry reachability, scheduler dispatch, alias effects, alternate helper and error behavior, snapshot handling and state-root inputs remain open. Next question: prove whether the constructor's expanded `+0x28` word preserves the loader object's corresponding field across both expansion helpers and their alternate branches.
