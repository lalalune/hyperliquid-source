# RE-017: node 115 ABCI loader startup handoff

This packet links one node #115 startup continuation and a second parent-stage variant to the state-location loader and follows the first path through selected mutations, completed-object cleanup, validation, record construction, and delivery to a later constructor, providing a concrete ordering for an independent reconstruction.

- Component ID: `abci`; RE-017 is connected to the RE-009 storage/state-root task.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23` was consulted for navigation only, not copied. The historical #94 packet is available at commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4`.
- Claim status: observations below are selected static bytes and decoded operands; the data-flow interpretations and remaining unknowns are explicitly identified.
- Scope included and excluded: the selected normal and suspended startup path, a second parent-stage variant, the named failure branches and two downstream byte ranges; not all paths in these FDEs, the program entrypoint, complete block execution, state roots, runtime behavior, or any component gate. Existing loader, Location, GOT and materializer points are boundary anchors, not newly owned discoveries.

## Reproduce

From the repository root with the authenticated `artifacts/node/115/hl-node` present and the repository's `tools/elf_index.py` and `tools/fde_extents.py` available:

```sh
python3 tools/abci_loader_handoff115.py --out research/work-items/RE-017-abci-loader-handoff-115
python3 -m unittest tests.test_abci_loader_handoff115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
: "${TMPDIR:?Set TMPDIR to a writable temporary directory}"
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_loader_handoff115.py --out "$TMPDIR/re017-a"
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_loader_handoff115.py --out "$TMPDIR/re017-b"
diff -r "$TMPDIR/re017-a" "$TMPDIR/re017-b"
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-abci-loader-handoff-115 "$TMPDIR/re017-a"
(cd research/work-items/RE-017-abci-loader-handoff-115 && sha256sum -c MANIFEST.sha256)
```

Use empty temporary output directories. The tool checks the entire target SHA-256 before parsing and uses Python's standard library plus the two repository parsers. It does not run the target or invoke external programs. Generation and tests were checked with Python 3.12.3 and with a PATH containing Python but no binutils. Exploration used GNU objdump 2.42 only for human inspection; no objdump output is parsed by the extractor or included as generated evidence. The extractor writes the 15 TSV files listed in `summary.json` and `summary.json` itself; `MANIFEST.sha256` also covers this README. There are no network or execution side effects.

## Evidence

All hexadecimal instruction and table coordinates below are linked ELF virtual addresses, not file offsets. Each TSV includes its associated file offsets where applicable. `ranges.tsv` reconciles each selected `.eh_frame` FDE with `.eh_frame_hdr`, hashes that range, and records an exclusive end; an FDE is an unwind range, not proof of complete function boundaries or all callers. `windows.tsv` records 79 exact selected byte windows. `edges.tsv` decodes only the 122 listed pinned branch/call forms. `tables.tsv` reads 44 selected signed-relative table entries; none of those counts is a whole-binary coverage denominator.

### Selected route and ownership boundaries

| Stage | Entry FDE or selected instruction | Observation |
| --- | --- | --- |
| Selected upper entry | `0x2cb6500` | Call `0x2cb7771` passes a subobject initialized with byte `+0x21 = 0`; a returned tag of `2` takes a suspension path. The other parent stage below is examined independently. |
| Parent A / B | `0x2af0660` / `0x2cbbbe0` | The selected non-`2` input route creates a `0x1158`-byte middle object, initializes its state byte to zero, and calls the shared stage at `0x2af0a5f` / `0x2cbc06b`. |
| Shared stage | `0x2b41b70` | The initial state-table entry at `0x60499c` leads through an input-bit test to the selected loader call at `0x2b41f2d`. The `rax` result is saved at middle-object `+0x40`. |
| Existing loader boundary | `0x3c12800` | Calls the state-Location boundary at `0x3c128a2`, checks the returned registers, and performs the selected writes listed below. Slot `0x64e7728` is included only to join this route to the boundary. |
| Existing state-Location boundary | `0x3c13520` | References `l1/src/abci/state.rs:123:37` at `0x3c1352f` and calls the materializer boundary on one path. The associated GOT slots and old call sites are included as context only. |
| Completed middle drop | `0x2a973a0` / `0x2c85400` | Index 1 in the two destructor tables leads directly to return sequences at `0x2a975be` / `0x2c8577e`, with no call in those sequences. The parents then release the `0x1158`-byte middle allocation. |
| Returned-state consumers | `0x24b7920`, `0x2cbfd10` | Both parent lanes call the record lookup and the consumer with a pointer to the saved state-pointer field. The consumer reads state offsets `+0x18`, `+0x20`, `+0xb9a`, and the subobject at `+0xd88`; its selected return copies `0x90` bytes. |
| Outer delivery and next constructor | `0x2cb7a0f` to `0x5a6bfb0` | The selected upper caller loads the returned state pointer from result offset `+0x380` and passes it in the first argument register; the next constructor calls `0x55ea030` and `0x548ce30`. |

The selected resumption entries are not guesses from executable-section membership: parent A tables `0x6042a8` and `0x6042bc` select `0x2af074c` and `0x2af0a45` at index 3; parent B tables `0x60bc10` and `0x60bc34` select `0x2cbbcb2` and `0x2cbc051`. The latter two inner entries call the already stored middle object rather than repeating the preceding allocation. The completed middle path stores state byte 1; table entries 1 and 2 of both selected drop tables share the direct return. Other drop states remain outside this claim.

### Branch and failure observations

| Test in selected path | Byte-backed consequence |
| --- | --- |
| Parent input byte differs from `2` | A `0x2af06dc` and B `0x2cbbc61` take their construction routes. The input value `2` takes another route, not mapped end to end here. |
| Shared-stage initial input low bit is zero | `0x2b41bd0` goes to `0x2b41d2a`. At `0x2b41d36`, byte `+1 != 1` skips the optional helper; byte `+1 == 1` checks the helper result. After the loader, byte `+1 != 0` follows the direct-result route. |
| Middle result word at output `+8` equals `0x8000000000000001` | Parents branch from `0x2af0a85` / `0x2cbc08a`, mark nested state 3, write result tag 2 and return. Neighboring values are negative controls, not asserted runtime test inputs. |
| Other shared-stage calls | Selected calls `0x2b420f8`, `0x2b42429`, `0x2b42641`, and `0x2b428c9` have distinct result checks and suspension transfers in `edges.tsv`; their helper semantics and full failure cleanup are unresolved. |
| Loader preparation overflows | The `neg` overflow branch at `0x3c12856` reaches the `state.rs:76:77` Location. The helper return compared to `1` at `0x3c128af` reaches `state.rs:79:100`; a loaded-state/request mismatch at `0x3c128d7` reaches `state.rs:82:21`. |
| State mode differs from parent mode | `0x2af0b2a` / `0x2cbc12f` go to records for `node/src/startup.rs:92:13`. |
| Selected record lookup finds no match | `0x24b7be5` transfers to `0x24b87a4`. The loop compares 16 bytes plus 4 bytes against a 20-byte key, with record stride `0x70`; a matched record contributes the dword at `+0x50`. |
| The selected clone count is too large or its allocation returns null | `0x55ea0e6` enforces the size guard; overflow calls `0x64df498` with first argument zero. A null allocation takes `0x55f2efa`, sets that argument to 8, and joins the same call. If it returns, execution reaches `ud2` at `0x55f2fd6`. |
| The late checker returns nonzero | `0x2af07c7` / `0x2cbc53e` go to separate paths which reference the same length-prefixed literal `failed to validate hardfork version: ` and Location `node/src/startup.rs:60:21`. Their error calls are followed by branches to `ud2` if the calls return. The checker's implementation is an existing boundary and is not assigned here. |
| Selected `0x1158` allocation returns null | `0x2af0a1f` / `0x2cbc02b` go to size-specific failure calls, then to `ud2` if those calls return. The later `0x42c8` and `0x4e38` allocations have separately recorded failure branches. |

### Selected state writes and projections

On the non-`1` helper-result branch, after the word at state `+0x28` equals the request word at `+0x18`, the instruction window beginning `0x3c128ca` performs these writes in order. They are observations at the stores, not a guarantee that later calls leave the values unchanged.

| State offset | Selected write |
| --- | --- |
| `+0x10` | Request word. |
| `+0x18` | Increment previous unsigned word, saturating at `0xffffffffffffffff` through `inc` and `cmovne`. |
| `+0x20` | Current word loaded from state `+0x30`. |
| `+0x10e8` | Zero eight bytes. |
| `+0xdf0` | The same word previously loaded from state `+0x30`. |
| `+0xef8` | Reload state `+0x30` after two calls and store that reloaded word. |
| `+0x3e28`, `+0x3ee0`, `+0x39b0` | Store zero to two 16-bit fields and store byte 2, after additional helper calls. |

The parent then copies state `+0x10`, `+0x28`, `+0x18..+0x27`, and `+0x30` to relative offsets `+0x10`, `+0x18`, `+0x20..+0x2f`, and `+0x38` of its `0x2b8` record. A `0x90`-byte consumer result and a `0xb8`-byte lookup result are copied into the same record. The record is copied from parent `+0x568` to `+0x820`; these two ranges are adjacent. The selected projection instructions are identical in both parent variants and are represented by `projection.tsv`, `fields.tsv`, and `copies.tsv`.

For final delivery, `handoff.tsv` verifies that both parent variants write the pointer at result `+0x380` and copy `0x3b8` bytes into their caller's result. The selected upper caller for parent B copies the `0x380`-byte prefix before separately loading the pointer at `+0x380`. The separate load is essential: the prefix copy itself excludes that pointer.

The next constructor passes that pointer as the second argument of `0x55ea030`, then copies a `0x42c8`-byte temporary into an allocation and calls `0x548ce30`. The latter allocates and copies `0x4e38` output bytes. `expanded-projection.tsv` records four contiguous source ranges, `+0xd88..+0x37df`, placed at output `+0x18f8..+0x434f`. Two 16-byte loads/stores in `0x55ea030` at `0x55f21a1` and `0x55f22bf` preserve offsets `+0x10e8` and `+0x10f8` in its selected input/output pair; `forwarding.tsv` joins those offsets to the later output offsets `+0x1c58` and `+0x1c68`. The clone function has many other branches and helpers; these two transfer observations do not establish the contents of the remaining bytes.

The clone also reads a count at input `+0xa0` and, for a nonzero allocation, a source pointer at `+0x98`. The selected guard multiplies the count by 32, rejects high bits and a byte size greater than `0x7ffffffffffffff8`, and therefore accepts at most `0x3ffffffffffffff` elements. Zero length skips allocation and produces the raw value 8 for this intermediate pointer; on the selected nonzero allocation path, the loop copies one 32-byte chunk per iteration. `clone-guard.tsv` derives the count bound and operand offsets directly from the checked instruction bytes. This does not identify the source-level container type or prove the other clone paths.

### Historical #94 cross-check

The earlier RE-017 packet was bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`: it records caller `0x32725d0`, call `0x3272785`, callee `0x3273810`, Location `l1/src/abci/state.rs:107:37`, and a result first-word check against 2. That historical record can be inspected with:

```sh
git show c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4:research/work-items/RE-017-abci-state-link-94/README.md
```

The old binary is not an input to this packet and its record is not re-run here. For #115, ELF relocations, direct call bytes, FDEs and Location data independently establish the contextual `0x3c12800` -> `0x3c128a2` -> `0x3c13520` chain and Location `state.rs:123:37`; this chain checks `rax` against 1. Similar call topology is a navigation clue, not proof that the release-specific Rust types, tags, addresses, or full function semantics are equivalent.

### Inferences and unresolved questions

Under the selected branch conditions, conforming calling conventions, normal helper returns, and no conflicting alias writes, the returned pointer is carried from the loader through the selected parent B and upper continuation into the later constructor. This is a data-flow inference from the pinned instructions, not a recorded execution. Likewise, the two clone-to-expanded projections identify possible value flow only if intervening calls and aliases preserve those bytes. The source-level meaning of each word, actual dynamic binding of `memcpy`, the lookup's higher-level role, and effects of helper calls remain unresolved. The literal supports the description of the validation failure but does not prove the checker's implementation or input type.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler/linker flags and two-build comparison: not yet applicable. Raw and normalized byte comparisons, masks, helper/call-target closure, relocation/vtable/data closure, and whole-ELF comparison: not yet measured. The raw selected target windows and FDE hashes are preserved; no transplanted target bytes are used as implementation. Public repository metadata and pull-request diffs were read for overlap checks; no node or visor was run and no keys, chain access, node networking or public data synchronization was used.

## Results and limitations

`summary.json` reports 14 selected FDEs, 79 byte windows, 122 transfers, 44 jump-table entries, 52 operand records, 13 relocation anchors, 12 Location records, 14 RIP-relative references, 6 literals, 14 copy sites, 4 parent projections, 3 result handoffs, 4 expanded-object projections, 2 forwarding joins and 1 clone-size guard. These are selected records only, not coverage rates. The focused suite has 45 passing tests and zero skips, including changed digest, instruction bytes, call/branch displacements, FDE bounds, invalid/NOBITS addresses, relocation type/addend, duplicate records, Location/string corruption, table entries, copying lengths, pointer offsets, descriptor framing, clone size boundaries and each byte of the 20-byte comparison. Tests model the pinned counter and mask operations; they do not execute node instructions. Deterministic regeneration is checked across hash seeds and time zones.

The loader call is reached from one selected upper startup continuation and a second parent-stage variant, and is not traced from the process entrypoint. The complete clone, all alternate paths, the allocator and error helpers, dynamic bindings, begin/action/end-block functions and state-root inputs remain open. This packet does not request a component gate or claim an equivalent node build. Next question: trace the selected `0x55ea030` helper calls that can touch state `+0x10e8..+0x1107`, then establish which later consumer of the `0x4e38` result leads to a binary-backed block or root operation.
