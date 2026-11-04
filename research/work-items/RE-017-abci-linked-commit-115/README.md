# RE-017: linked ABCI state serialization and root-result handoff

On one selected node #115 loader-to-constructor continuation, the expanded state pointer is passed into the end selector, whose linked-state branch returns a serialized buffer for a two-stage digest that consumes the previously selected 32-byte root second.

- Component ID: `abci`; the snapshot and state-root question also supports RE-009.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was used only for navigation, with no reference source copied.
- Claim status: ELF bytes, selected addresses, relocation records, encoded operands and Location records are observations. Role names, the selected value-flow join and conditional encoding models are inferences; concrete execution, alias stability and complete helper effects are unresolved.
- Scope included and excluded: the selected special end-block continuation, state snapshot closure, selected named serialization prefix and height encoding, error branches, and the two-stage digest result handed to the existing continuation. The earlier loader, earlier block selector, established GOT and save/writer bodies are boundary context. This is not the process entrypoint, a full loader-to-block identity proof, all begin/action/end-block behavior, all serializer fields, a runtime trace, or a component gate.

## Reproduce

Run from the repository root with the captured `artifacts/node/115/hl-node` and the checked-in `tools/elf_index.py` and `tools/fde_extents.py`. Set `TMPDIR` to a writable directory and use fresh output subdirectories:

```sh
python3 tools/abci_linked_commit115.py --out research/work-items/RE-017-abci-linked-commit-115
python3 -m unittest tests.test_abci_linked_commit115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
: "${TMPDIR:?Set TMPDIR to a writable temporary directory}"
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_linked_commit115.py --out "$TMPDIR/re017-a"
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_linked_commit115.py --out "$TMPDIR/re017-b"
diff -r "$TMPDIR/re017-a" "$TMPDIR/re017-b"
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-abci-linked-commit-115 "$TMPDIR/re017-a"
(cd research/work-items/RE-017-abci-linked-commit-115 && sha256sum -c MANIFEST.sha256)
```

For an independently authenticated historical comparison, if the separate old capture is available, the following command verifies both capture hashes and prints the old and current Location coordinates. It produces the same node-115 evidence files as the standard invocation:

```sh
python3 tools/abci_linked_commit115.py --old-elf references/can1357-hl/bin/hl-node-mainnet-new --out "$TMPDIR/re017-history"
```

The focused tests and regeneration were checked on x86-64 with Python 3.12.3, including a PATH containing Python without binutils. The generator authenticates node #115 before parsing or creating output. It uses the Python standard library and the two repository parsers; it does not call other programs. GNU objdump 2.42 was used only for human inspection, and its output is neither parsed nor included in generated files. The target was not executed; no network, chain or key access was used. `MANIFEST.sha256` gives the output hashes.

The generated `functions.tsv` contains the complete raw bytes and SHA-256 of the selected unwind extents. `windows.tsv`, `transfers.tsv`, `operands.tsv`, `references.tsv`, `fields.tsv`, `relocations.tsv`, `locations.tsv` and `literals.tsv` contain selected observations; `unwind_records.tsv` contains every call-site entry from the selected LSDAs and `unwind.tsv` projects 14 selected witnesses. `flow.json`, `selector.json`, `constants.json`, `synthetic.json` and `summary.json` are deterministic decoded or explicitly synthetic records. The 16 generated evidence files must match a fresh generation byte for byte.

## Evidence

Coordinates are linked ELF virtual addresses unless a column explicitly says file offset. Each extent has its `.eh_frame` range reconciled with `.eh_frame_hdr` and is checked for overlapping FDEs. An FDE is an unwind range; it does not establish an original source-function boundary, all callers, or a coverage denominator. The names below are descriptive labels. Runtime relocation binding, helper effects, no conflicting alias writes and normal returns are conditions on the inferred joins.

### Selected route and return

| Stage | VA and observed transfer | Selected observation |
| --- | --- | --- |
| Existing constructor to selector | Context `0x5a6bfb0`; new window `0x5a6c140` | The earlier loader packet traces a selected loaded-state input through the already owned clone and expansion calls. The context-result packet records the returned pointer's stack slot and preceding context copy. The new window records the following stores and the call to the existing end selector at `0x5a6c16a`. This is context in the previously owned constructor, not a newly claimed FDE. |
| Existing end selector | `0x5a08720`, context windows `0x5a08853` and `0x5a08883` | The earlier RE-017 block-root packet maps the root-producing call and the branch conditions. At `0x5a0884d`, zero `bpl` skips the link continuation; nonzero selects it. The call at `0x5a0887e` passes the address of the context's state-pointer slot to `0x5485f80`, along with the selected `freeze` or `periodic` token. The inherited selector is context only, not re-owned here. |
| Link wrapper and name | `0x5485f80`; calls at `0x5485fbb`, `0x5486000`, `0x548604b` | The wrapper dereferences its input and reads state `+0x28`, calls the existing `0x38d8240` boundary through its relocation, passes the relocated `abci_state` descriptor at `0x64aa220` to `0x5942870`, and constructs a three-pointer closure. The middle pointer addresses a word initialized to zero; the third addresses the first returned path-like triple. The closure call passes a nonzero selector. |
| Name token | `0x5942870` | For valid immutable key bytes after the possible lazy-initialization path, length 10 and both checked byte comparisons select the literal `rmp` with length 3 for `abci_state`; different length or content selects `json` with length 4. The selected token is passed to a formatter. This does not establish the final rendered path or a successful file operation. |
| Dispatch and capture | `0x4e45a30` to `0x4e363c0`; `0x4e363f9` | Both selected plain and guarded dispatches invoke the capture. It dereferences the closure's state pointer, reads state `+0x28`, forms state `+0x1c78`, dereferences the closure's default pointer, and calls the existing `0x38c2e00` boundary through slot `0x64e61d0`. The first default word is zero on this path if intervening code does not alter it. This call precedes the serializer call. |
| Serialize and output | `0x4e4b3f0`; calls `0x4e4b480` and `0x4e4b4d3` | Configuration bytes `00 04 00 01 00` are initialized and the state writer `0x5481900` is called. If its result head is `0x8000000000000004`, the produced buffer pointer and length, and the destination pointer and length from the earlier path-like triple, are passed to the existing `0x15024a0` boundary via slot `0x64e09e8`. Its attached Location is `state.rs:195:17`. |
| Return buffer | `0x4e4b4a4`, `0x4e4b5aa`, `0x4e4b6b5`, `0x4e364a2`, `0x548629b` | The serializer preserves its buffer triple across subsequent local-slot reuse and returns it. Capture combines that triple at output `+0..+0x17`, the save-helper triple at `+0x18..+0x2f`, and the height word at `+0x30`. The link wrapper forwards the 56-byte aggregate after its own checks and conditional releases. |
| Digest handoff | `0x5a08919` to `0x452aab0` to `0x457cf60` | On normal continuation the parent uses the first returned triple's pointer and length as an input span and a pointer to its previously produced 32-byte root as another input. The final 32-byte digest is placed in the parent's result buffer. |
| Existing result consumer | `0x5a08ac7` to `0x5a046f0` | The parent passes the earlier height held in `r15` and the digest-result address to the existing continuation. The pointer's identity and effects after this call are not reconstructed here. |

The two snapshot-name selectors have similar predicates but distinct FDEs. The earlier `RE-001-node115-cache-suffix` work owns `0x59429e0` and did not bind its two observed callers to the ABCI key. This packet analyzes the different entry `0x5942870` and the concrete `abci_state` descriptor used by this link wrapper. It does not claim suffix alone proves a codec or a file was created.

The constructor join is more specific than an offset match. The earlier `RE-017-abci-context-result-115` packet records the expanded result at `0x5a6c0af`, its store at stack `+0x1690`, the context base at `+0x1240`, and a `0x450`-byte copy into that base. The destination ends exactly at the saved pointer, and the source and destination ranges are disjoint. Those earlier instructions and the copy call are not re-owned here. The newly recorded continuation at `0x5a6c140` writes a qword at stack `+0x16a0`, a dword at `+0x16a8` and a byte at `+0x16ad`, all after the saved pointer's eight-byte slot, and then passes the same context register to the selector at `0x5a6c16a`. The earlier block-root packet records that the selector loads its state pointer from argument `+0x450`. Under the imported copy's normal behavior, ABI-preserving returns, and no conflicting writes, the selector therefore receives the same expanded pointer returned by the prior constructor call. `operands.tsv` and `flow.json` record only the new post-copy stores; tests corrupt those stores and the new call. The clone may be a different object from the loader's input; the earlier packet establishes only its selected projections.

This is an initialization continuation that calls the selector directly. The earlier block-root packet independently reaches the same selector through the block engine; the present join does not prove that later block engine uses this same allocated object. The selector's flag and root conditions still determine whether the linked-state branch below is reached.

### Serialization observations and conditional models

At `0x4e4b461`, the caller initializes the serializer configuration such that byte `+0xb` is 1. Following successful helpers, and assuming the configuration and inputs are not changed through aliases, `0x5481900` selects the named form. The first selected calls use map counts 1, 59 and 17 and names `exchange`, `locus` and `ctx`, then call `0x4d93030`, which uses map count 13. The map, string and integer helper extents and their buffer-growth failure windows are in `functions.tsv` and `windows.tsv`.

The checked branch instructions, immediate counts, literal references, marker stores and byte-order operations imply the following **synthetic prefix**, not bytes from an executed node or a complete fixture:

```text
81 a8 65 78 63 68 61 6e 67 65 de 00 3b a5 6c 6f 63 75 73 de 00 11 a3 63 74 78 8d
```

This opens the outer map and the three named nested maps. Other context fields precede `height`, so the prefix does not claim that the separately modeled `height` name immediately follows it. The following associations are selected name references and nearby operands, not a complete structure layout or complete schema:

| Named field | Input-state offset | Observed use |
| --- | ---: | --- |
| `hardfork_height` | `+0x10` | Word loaded and sent to unsigned writer `0x57d00b0`. |
| `height` | `+0x28` | Word loaded and sent to the same unsigned writer at `0x4d93145`. |
| `round` | `+0x30` | Word loaded and sent to the same unsigned writer. |
| `time`, `prev_time` | `+0x60`, `+0x6c` | Addresses passed to `0x4e0da40`; that helper remains a boundary. |
| `next_oid`, `next_lid`, `next_twap_id` | `+0x38`, `+0x40`, `+0x48` | Words passed to `0x4e0dd00`; that helper remains a boundary. |

The selected unsigned writer dispatches a value at the following boundaries. Payloads are big-endian on the selected successful paths, as indicated by the pinned swap and store windows; buffer growth may fail before completion.

| Unsigned value | Synthetic value encoding |
| --- | --- |
| `0..127` | One byte, the value itself. |
| `128..255` | Marker `cc`, then one byte. |
| `256..65535` | Marker `cd`, then two bytes. |
| `65536..4294967295` | Marker `ce`, then four bytes. |
| `4294967296..18446744073709551615` | Marker `cf`, then eight bytes. |

`synthetic.json` also records both sides of each width boundary and the selected map-header boundaries. These are models of the pinned paths, not captured node outputs. The eight-byte height word's higher-level validity and the remaining state serialization are unresolved.

### Digest data flow

In `0x457cf60`, selected instructions load the span pointer and length from input `+0` and `+8`, initialize a context using the recorded 32 bytes at `0x457ae0` and `0x457af0`, call the update boundary at `0x457d047`, and call the finalize boundary at `0x457d05b`. They copy 32 bytes through the input pointer at `+0x10`, initialize a second context, update it with the first 32-byte result at `0x457d155`, update it with the copied root bytes at `0x457d17c`, and finalize into 32 output bytes at `0x457d186`.

If the dynamic boundaries behave as their observed update/final calling conventions suggest and intervening calls preserve the saved buffer and root, the selected result is `D2(D1(serialized_span) || root_32)`. `D1` and `D2` denote the two observed context operations; equality of all possible runtime implementations, the exact cryptographic algorithm, and a final known digest are not established. The platform-selection slot and digest update/final slots in `relocations.tsv` are anchors only; their previously studied target bodies are not re-owned.

The earlier block-root packet binds the same update/final slots and initialization bytes to a separate helper with a `blake3/src/lib.rs:861:33` Location. That supports a BLAKE3-family inference for these shared boundaries; it does not independently validate this complete two-stage digest, all platform implementations, or a test vector.

### Branches and failure boundaries

| Condition | Selected consequence |
| --- | --- |
| End-selector link flag is zero | `0x5a0884d` bypasses this linked-state continuation. Other hash and return paths are outside its scope. |
| Name length or content differs from the selected key | The selector uses the four-byte `json` token. A lazy-initialization helper can run first; its effects are not closed. |
| Capture or snapshot probe returns nonzero; TLS is in a selected re-entry state | `0x4e45a69` or `0x4e36437` reaches the respective diagnostic path; selected TLS branches reach failure code ending in `ud2` if the diagnostic returns. These are separate from ordinary writer-result checks. |
| State writer result head differs from `0x8000000000000004` | `0x4e4b49e` branches to conditional buffer cleanup and the `state.rs:193:56` unwrap diagnostic; `ud2` follows if the diagnostic returns. No writer success is inferred. |
| Output boundary returns nonzero | `0x4e4b4e1` reaches the `state.rs:195:64` unwrap diagnostic and then `ud2` if it returns. A failed output call may already have changed external state. |
| Link check boundary returns nonzero | `0x54860a9` reaches the `state.rs:201:32` diagnostic and `ud2` if it returns. The later follow-up call is bypassed. |
| Link follow-up returns nonzero | The wrapper invokes the first method from its returned vtable and continues only if that method returns. Its meaning and any error handling inside it are unresolved. |
| Buffer growth or selected map/string/value write fails | The writers return non-success representations along the recorded growth/error windows. Subsequent wrapping is conditional on the enclosing call path. |
| An unwind crosses a selected call | LSDA entries identify bounded landing addresses, including `0x54863ba` for closure capture, `0x4e36636` for simple serialization, and `0x4e4b7e1` for the output boundary. Other entries have no landing address. This record does not assume every landing's full semantics. |

The save-helper call occurs before encoding and output. Thus a later failure is not evidence that earlier helper side effects are rolled back. The writer boundary does not by itself prove atomicity, durability, final filesystem names or crash consistency.

### Relation to previous evidence and release 94

The pending `RE-017-abci-loader-handoff-115` packet maps the node-115 loader and state expansions; `RE-017-abci-context-result-115` maps the expanded pointer into an owner; `RE-017-abci-block-root-115` maps the separate end selector and root input. The existing save boundary `0x38c2e00` is covered by `RE-011-evm-db-checkpoint-hashes-115`, and the existing output boundary `0x15024a0` by `RE-009-abci-state-export-115`. This packet uses those bodies as boundaries and contributes different FDEs. It conditionally joins the expanded pointer to a direct initialization-time selector call, but does not establish that the same allocation is later consumed by the block engine.

For context, the earlier block-root packet reports a selected begin helper that saturating-increments state `+0x28` and conditionally moves the time words at `+0x60` to `+0x6c`, plus one guarded item handler that saturating-increments `+0x16b0` and, for a particular returned tag, `+0x16b8`. Its selected block continuation reaches the end selector used above. Those prior state mutations and the present handoff form a conditional route, not exhaustive action coverage or proof that intervening helpers preserve every field. The existing checkpoint packet separately reports that its zero-fourth-argument save branch copies three `0x810`-byte records at the save subobject's `+0xf8`, `+0xa00` and `+0x1308` and attempts an output. The present capture binds that subobject to state `+0x1c78` and supplies a zero first default word before the call. This adds ordering at the boundary without claiming successful persistence or re-owning the save implementation.

The historical `RE-017-abci-state-link-94` record can be inspected at repository commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4`. Its separate #94 capture has SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The optional comparison authenticates it and independently checks old loader unwind extent `0x3273810..0x327396c`, its `state.rs:107:37` Location reference at `0x3273856`, and comparison with 2 at `0x3273871`. It also checks the current #115 `state.rs:123:37` Location record at `0x64767a8`; the earlier #115 loader packet supplies the separately observed reference and comparison with 1. The optional checker separately verifies the #94 linked-state extent `0x2208e60..0x220944c`, its `state.rs:196:9` and `:203:9` Locations and its digest-call slot. The #115 byte observations and `state.rs:193`, `:195`, `:201` Locations in this packet are independently extracted from #115. Similar names or offsets do not prove cross-release equivalence of layouts, result tags or operations.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler and linker flags, two-build comparison, and raw or normalized implementation comparison: not yet measured. The target evidence keeps raw bytes without normalization masks. Helper and call-target closure, runtime relocation resolution, remaining vtable/data relationships and whole-ELF comparison remain incomplete. No source text or target code bytes have been transplanted into an implementation.

## Results and limitations

`summary.json` reports 17 selected FDE extents, 2 previously owned contextual FDEs, 65 pinned windows including 5 contextual windows, 58 selected transfers, 23 operand records, 17 relocation anchors, 5 Locations, 22 literals, 12 selected references, 8 field associations, 65 LSDA call-site records and 14 LSDA witnesses. These are bounded selections, not function coverage. The focused suite passed 34 tests with zero skips. Its controls include altered input hashes and instruction windows, out-of-range and fileless mappings, selected and contextual FDE/header corruption and overlap, post-copy store and selector-call corruption, relocation corruption, bad Locations, all 2,550 single-byte changes to `abci_state`, serializer boundaries, return-buffer preservation, and the selected unwind records. The tests evaluate models and bytes without executing target instructions.

This packet resolves a selected loader-derived initialization, export and result path, not the full first `abci` task. It does not establish full action coverage, allocation identity in later block processing, the full state encoding, helper side effects, actual digest bytes or node equivalence. No progress gate is requested. Next question: trace the constructor's expanded allocation into the later block-engine owner and identify any writes to the state pointer, `+0x28` and `+0x1c78` before that engine calls the end selector.
