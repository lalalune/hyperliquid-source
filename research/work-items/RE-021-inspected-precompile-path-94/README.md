# RE-021: inspected private-provider handoff and frame snapshot

On its selected frame path, node #94's inspected provider route installs a separate address set and records the frame's 20-byte address field in an owned snapshot before delegating the original frame to its preserved execution callback, fixing the order a reconstruction must preserve.

- Component ID: `evm`; continuation of the RE-021 BLAKE2b precompile connection.
- Target release and full SHA-256: node #94, Linux x86-64 ELF, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation is copied.
- Claim status: **observation** for the selected ELF bytes, FDE extents, relocations, field displacements, selected control transfers and exception call-site records; **inference** for the container, callback, key and provider roles and for composing normal-return paths; **unresolved** for actual runtime reachability, dynamic helper effects and the alternate runtime's complete lookup.
- Scope included and excluded: the 15 FDE starts in `functions.tsv` are this packet's selected bodies. Existing standard registry lookup, provider B materialization, frame construction, the compression wrapper and the separately exported B-runtime body are dependencies and are not selected again. Node #115, visor, execution, emulation, chain state and network access are outside scope. No EVM completion gate is requested.

## Reproduce

Work from the repository root with the authenticated `artifacts/node/94/hl-node` present. The recorded static analysis used Python 3.12.3 on Linux x86-64. The generator imports only the Python standard library and the repository's `elf_index` and `fde_extents` modules, verifies the full input SHA-256 before parsing, rejects NOBITS/file-range errors, and invokes no external process. It does not execute any target code. Addresses in every table are linked ELF virtual addresses before load bias; `functions.tsv`, `semantic-windows.tsv`, `relocations.tsv` and the exception headers also retain file offsets. Runtime pointers require the loader's bias.

```sh
python3 tools/inspected_precompile94.py --out research/work-items/RE-021-inspected-precompile-path-94
python3 -m unittest tests.test_inspected_precompile94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-inspected-precompile-path-94 && sha256sum -c MANIFEST.sha256)
```

For the determinism comparison, replace the placeholders below with two different empty relative directories. The generator writes its 17 evidence files in each directory; README and MANIFEST are maintained separately. No time, process environment, host path or hash iteration order is emitted.

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/inspected_precompile94.py --out <tmp-dir-a>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/inspected_precompile94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The generator and focused unittest were also run with an empty program-search PATH. `MANIFEST.sha256` lists the hashes of this README and all generated files, relative to this directory. GNU objdump 2.42 was used only for human instruction-boundary review: no generated file, tool or test parses its output.

## Evidence

### Coordinates and ownership

The function entries and exclusive ends are read from actual `.eh_frame` FDEs and checked against `.eh_frame_hdr` and executable file-backed sections; they are not sizes guessed from the next index entry. `function-bytes.json` retains the complete selected FDE byte spans and their hashes, and `unwind-records.json` retains their FDE/CIE records. An FDE span is a bounded machine-code observation, not proof of a recovered source function or a complete CFG. The named control transfers and byte windows are selected sites, not a census.

| Selected FDE start | Observed contribution to this route |
| --- | --- |
| `0x37dc350` | Reads a revision byte, constructs and installs the hook, obtains the provider result, updates the context, constructs a frame and invokes the selected callback. |
| `0x37fd850` | Selects revision-dependent handler construction and stores a canonical byte. |
| `0x32ce340` | Constructs the revision-12 group of 11 callback pairs. |
| `0x37e1590` | Wraps handler callbacks and installs the private provider. |
| `0x37f3ca0` | Consuming adapter for the installed hook; calls the installer. |
| `0x34389a0` | Produces an independent address set from the provider result. |
| `0x3577310` | Copies keys from the owned registry representation to a set. |
| `0x34d6480` | Clones the set in the borrowed representation. |
| `0x36e3590` | Computes a reserve amount and extends the context's set. |
| `0x3be3e90` | Consumes the set iterator and calls the insert function. |
| `0x379c1d0` | Probes and inserts a 20-byte set key. |
| `0x37ffa30` | Allocates and appends the frame snapshot, then delegates. |
| `0x37f3a00` | Calls the same wrapper through its consuming descriptor method and conditionally releases both captured owners. |
| `0x3287ad0` | Calls the existing B-runtime boundary and releases the original frame. |
| `0x37f4b90` | Releases an owned frame on the selected cleanup paths. |

The entry is also the addend of the relative relocation at slot `0x5774020`; it identifies a callable data boundary but does not establish a complete caller census or runtime reachability. The linked call and data dependencies, without duplicating the existing bodies, are:

```text
0x37dc350 --revision byte--> 0x37fd850 --case 12--> 0x32ce340
          --install-------> 0x37e1590 --provider pair--> 0x3268ce0 [prior provider B]
          --provider result--> 0x34389a0 --> {0x3577310, 0x34d6480}
          --set extend-------> 0x36e3590 --> 0x3be3e90 --> 0x379c1d0
          --frame constructor slot--> 0x4e91cb0 [prior frame constructor]
          --callback descriptor--> 0x37ffa30 --> 0x3287ad0 --> 0x32ae320 [existing boundary]
```

`control-edges.tsv` gives the actual instruction bytes and decoded targets for 71 selected direct, conditional and RIP-slot transfers. `relocations.tsv` preserves 38 selected raw RELA records; descriptor slots use symbol-free `R_X86_64_RELATIVE` addends. `dynamic-imports.tsv` separately records the copy slot's `R_X86_64_GLOB_DAT` record and dynamic symbol bytes. A slot address is not itself its target. `descriptors.tsv` connects the installed provider and callback descriptors to their methods, while `semantic-windows.tsv` contains the reviewed fixed instruction-byte sequences. These files are derived from ELF bytes, not disassembler text.

### Revision, handler and hook

At `0x37de295`, the builder calls `0x37fd850` with the byte read from an input structure at `+0x158`. The constructor compares that byte with `0x13`, then uses the signed four-byte table at `0x59a880` or a default. `revision-cases.tsv` enumerates all 256 byte inputs directly from that table and the per-case stores; `revision-table.json` retains the table bytes. The canonical byte groups are:

| Requested byte(s), inclusive | Canonical byte |
| --- | --- |
| `0x00..0x01` | `0x00` |
| `0x02..0x03` | `0x02` |
| `0x04`, `0x05`, `0x06` | the same byte |
| `0x07..0x08` | `0x08` |
| `0x09..0x0a` | `0x09` |
| `0x0b` | `0x0b` |
| `0x0c..0x0e` | `0x0c` |
| `0x0f..0x13` | the same byte |
| `0x14..0xff` | `0xff` |

For `0x0c..0x0e`, the fourth group constructor is `0x32ce340`; the resulting canonical byte is written at handler `+0x1198`. This does not establish which byte a live node supplies. The constructor allocates 11 separate 16-byte objects, with distinct null branches retained in `callback-allocation-failures.tsv`, and writes 11 data/descriptor pairs. Its pair at group `+0x20/+0x28` has descriptor `0x56e7120`; relocation at descriptor `+0x28` selects `0x3287ad0`. Copying that group to handler `+0xe8` places the pair at handler `+0x108/+0x110`.

The builder calls `0x37e1590` directly and records hook descriptor `0x56f3ad8`. Its method relocations also select installer `0x37e1590` and consuming adapter `0x37f3ca0`. If the handler's table pointer at `+0x198` is nonzero, the installer walks a `0x1000`-byte span in `0x10`-byte pair steps, wrapping 256 entries. In each first-pass iteration it stores a sentinel data word and a temporary descriptor before allocating the replacement pair; a null allocation therefore reaches its failure tail after those stores, not before them. With a zero pointer, it calls an external helper and resumes after that loop. It then runs a second pass over the five indices `0xa0..0xa4`, which lie within the first loop's index range; this depends on normal helper and allocator returns. These are selected loop bounds, not an opcode-coverage claim.

The installer writes seven callback wrapper descriptors, listed in `installed-wrappers.tsv`. For handler `+0x108/+0x110`, it preserves the old pair in a newly allocated wrapper and installs descriptor `0x570a7b0`, whose `+0x28` method relocates to `0x37ffa30`. Separately it captures handler byte `+0x1198`, allocates the provider payload, and replaces the pair at handler `+0x48/+0x50` with descriptor `0x56df878`; its `+0x28` method is the existing provider B `0x3268ce0`. The offsets compose from independent stack displacements in `layout.json`. This assumes the retained callbacks are not subsequently replaced and the observed allocation and alignment operations succeed.

### Provider result, state and address field

The first tag check at `0x37de5b9` must observe byte `5` before the handler provider call at `0x37de5f2`. The returned representation is passed to `0x34389a0`: an owned path copies 20-byte keys from 48-byte registry buckets via `0x3577310`; a borrowed path calls `0x34d6480` to clone the set. The seed helper may initialize process state when its guard is not ready. The referenced seed storage is NOBITS; its runtime contents are not read from the file.

The builder extends the context set at `+0x80` through `0x36e3590` and publishes the five-word provider representation at context `+0xe8` at `0x37de8bd`. The former is a separate set, not the registry's value storage. In `0x36e3590`, an empty destination asks for the iterator's remaining count; a nonempty one asks for `((remaining + 1) mod 2^64) >> 1`. Thus the machine-level result for the maximum 64-bit remaining count is zero on the nonempty path; whether that state is reachable is unknown. If the amount exceeds the growth word at set `+0x10`, a reserve helper is called before iteration. `0x3be3e90` supplies each 20-byte key to `0x379c1d0`, which compares all 16 leading bytes plus the final four bytes after its fingerprint filter. The matching-key path returns with `AL=1`; a newly published key returns with `AL=0`. If the growth word is zero, the code can reserve before the match is discovered; this evidence does not claim that a duplicate insertion always has no allocation side effect.

A second tag check, a subtraction guard and a third tag check precede the frame path. When the relevant environment byte at `+0x294` equals 1, the builder passes environment `+0x158` to the frame constructor through slot `0x5774588`; its relocation identifies the existing `0x4e91cb0`. Under the frame-layout result of open PR #1563, environment bytes `+0x295..+0x2a8` become frame bytes `+0x60..+0x73`. This is a dependency on that prior result, not a second selection of its FDE.

### Snapshot, delegation and failure paths

At `0x37ffa30`, the wrapper checks a word at state `+0x10`, sets it to `-1` only on the zero path, allocates 160 bytes, invokes an embedded dynamic clone operation and constructs a temporary frame-shaped value. The explicit loads from original frame `+0x60` and `+0x70` store 16 and four bytes at corresponding offsets in the temporary; the call at `0x37ffb34` passes that temporary, the allocation and length 160 through slot `0x576dfe0`. Its symbolic relocation names `memcpy`; its actual runtime implementation remains an external boundary. This is not a claim that the entire snapshot is a byte-for-byte copy of the original frame: a dynamic clone supplies part of it and padding is not characterized.

The wrapper compares vector length at state `+0x28` with capacity at `+0x18`. Equal values call the growth slot; otherwise the code proceeds to store the new pointer via state `+0x20`. It increments length, restores the guard word by incrementing it, and only then calls the retained descriptor's `+0x28` method with the original frame. For the installed revision-12 pair, the relocation/offset chain binds that method to `0x3287ad0`, which calls existing boundary `0x32ae320` and then releases the original frame on normal return. Result bytes are copied out after delegation. The 20-byte interpretation depends on the preceding constructor and on ordinary nonaliasing and helper returns; the test fixture is synthetic, not a target execution.

The wrapper descriptor's separate `+0x18` method is `0x37f3a00`. It calls `0x37ffa30`, then decrements two captured counters, using a locked decrement for the second; each zero result calls its corresponding release slot. The builder's displayed normal call uses `+0x28`, so the consuming method is a separately bound lifecycle entry, not an asserted step of that normal call. Its exception table records a cleanup helper when the wrapper call unwinds, and a separate landing that conditionally releases the second captured owner if the first release unwinds.

After the wrapped callback, result word 4 takes the packaging path at `0x37df09a`; the code stores sentinel `0x8000000000000002` and rejoins the handler at `0x37dea7d`. It copies a 144-byte temporary through the `memcpy` import and invokes handler pair `+0xc8/+0xd0`, then invokes pair `+0xd8/+0xe0`. If the first callback's returned word still equals that sentinel after the second callback, the builder copies selected fields into its output, calls external cleanup helpers `0x37f4e70` and `0x33fe990`, and jumps to the return at `0x37dee7a`. Other returned words branch elsewhere. The two indirect callback implementations and cleanup-helper effects remain unresolved; reaching this return assumes their normal behavior and does not classify the result as success or failure.

| Condition or covered call | Observed transfer or state action | What remains unknown |
| --- | --- | --- |
| First or post-registry tag differs from 5 | Branches to `0x37dea53` instead of continuing this selected provider/frame sequence. | Complete meaning of each returned tag. |
| Pre-frame tag differs from 5 | Branches to `0x37dee8f`, which rejoins result handling. | Full result algebra. |
| Pre-frame subtraction borrows | Branches to `0x37e0966`, which invokes a separate failure slot. | External failure-helper behavior. |
| Environment discriminator differs from 1 | Branches to `0x37deed9`, an alternate frame path. | Alternate path semantics. |
| Frame constructor returns null | Branches to `0x37e08e2`, then a failure helper. | Allocation and helper internals. |
| Callback result word equals 4 | Packages adjacent words at `0x37df09a` and jumps to the common result handler; if the first callback's result still holds the sentinel after the second callback, the builder writes output, calls two cleanup helpers and returns. Other initial values branch to `0x37df0c8`. | Dynamic callback behavior, remaining result variants and their source-level meaning. |
| Installer sees a zero table pointer | Calls `0x341db40` and joins after the 256-entry loop. | Helper's complete effects. |
| Installer's selected allocations return null | Separate conditional branches reach allocation-failure tails. | All allocator and rollback effects. |
| Old provider drop at `0x37e1cf0` unwinds | LSDA landing `0x37e1e4a` publishes the new provider pair before the unwind-resume call. | Caller-wide unwind disposition. |
| Snapshot guard is nonzero | Branches to `0x37ffbdf`, calls a failure slot and reaches a trap if it returns. | Whether a particular runtime input reaches it. |
| Snapshot allocation returns null | Branches to `0x37ffbee`, invokes an allocation-error slot and reaches a trap if it returns. An unwind from that slot lands at `0x37ffc2c`, restores the guard and continues original-frame cleanup. | Allocator and failure-helper implementation. |
| Snapshot clone call at `0x37ffa94` unwinds | Landing `0x37ffc13` releases the allocation, restores the guard and proceeds to original-frame cleanup. | Dynamic clone semantics. |
| Vector growth at `0x37ffb48` unwinds | Landing `0x37ffc00` drops the new frame, restores the guard and proceeds to original-frame cleanup. | Growth-helper internals. |
| Consuming wrapper call at `0x37f3a0a` unwinds | Landing `0x37f3a64` calls an external cleanup helper before unwind resume. | Cleanup-helper internals. |
| First owner release at `0x37f3a1a` unwinds | Landing `0x37f3a42` decrements the second counter and conditionally calls its release slot. | Behavior of the release slots. |

`exception-sites.tsv` and `exception-headers.json` retain the selected FDEs' LSDA call-site rows, encodings, and raw call-site bytes. Action indices are recorded but their action chains, type tables and personality semantics are not interpreted. Rows are static table entries, not a claim that every path was reached or that every failure branch in the component was recovered.

### Relationship to address 0x09

The existing `RE-021-blake2b-compress-94` packet identifies the address-09 object and wrapper; its `REVIEW.md` limits the reviewed result to static evidence and retains the captured-execution gate. Open PR #1373 associates the standard registry's mode 3 lineage with that entry. Open PR #1413 reports that provider B maps canonical byte `0x0c` to mode 3 and conditionally preserves the standard value while adding private addresses. Our independently extracted constructor and provider-descriptor binding supply the missing inspected-handler association. Consequently, **if** those prior results hold, the selected provider returns normally, no later override replaces the callback, and the frame address field is 09, the installed context can contain that standard entry and the wrapper records that address before handing the frame to the B-runtime boundary.

This does **not** independently prove that `0x32ae320` probes the installed map, reaches the standard dispatcher, or calls the compression wrapper for this inspected route. Its FDE already appears in `foundation-keyed-multiply-xor-mixer-94/caller.objdump.txt`; it is not included in this packet's new FDE set. The earlier full A-provider runtime claim and the B-provider materialization comparison do not by themselves prove B-runtime equivalence. The unresolved B-runtime lookup edge is the specific boundary for further review, subject to existing-work ownership.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, compiler and linker flags, two-build comparison, normalized byte comparison, helper closure, captured target behavior and whole-ELF equivalence: **not yet measured**. No relocation masking or claim of byte equivalence is made. No target bytes were executed or emulated.

The 26 focused Python unittest methods check authenticated-input rejection, FDE/index correspondence and corruption, file-backed range and NOBITS rejection, all 64 fixed windows and 71 selected transfers under mutations, relative and symbolic relocation and imported-name corruption, all 256 revision inputs, callback allocation and wrapper bindings, cross-function offsets, frame-copy displacements, selected result handling, set-comparison bytes and malformed LSDA records. Synthetic controls model the set's 20-byte lane comparison and the reserve hint at unsigned 64-bit boundaries; they do not execute target instructions. Tests do not substitute for independent target behavior.

## Results and limitations

`summary.json` records 15 selected FDEs comprising 31,903 bytes; 64 fixed semantic windows; 71 selected control transfers; 256 revision inputs reaching 15 case destinations; 11 callback pairs and 11 null checks; seven installed wrapper records; 38 selected relative relocations; and one selected symbolic relocation. Eleven selected FDEs carry parsed LSDAs, containing 403 call-site records, of which 337 have landing addresses. All are denominators for this selected corpus, not whole-node coverage. The 26 focused tests passed with no skips; the two different-environment regenerations matched byte-for-byte, as did the 17 checked-in generated files. Artifact verification and catalogue consistency passed. The full repository suite was not run.

The supplied local PR inventory and existing repository evidence were checked for overlap; a fresh public main/PR check was unavailable because this run does not access the network, and submission must repeat it. Provider B's actual runtime lookup, arbitrary registration replacement, source types, live revisions and seeds, helper/callback side effects, and complete failure or CFG coverage remain open. The full first HyperEVM component task remains unfinished and its existing 0/4 gates are unchanged.

Next question: under existing-work ownership, connect the B-runtime boundary to the exact installed registry and generic dispatcher, or validate that missing edge with a separately authorized target-grounded fixture, before asserting an address-09 invocation for this instrumented route.
