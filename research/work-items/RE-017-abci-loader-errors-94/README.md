# RE-017: state-loader error object and release paths

The Location-linked node #94 loader returns a boxed, 80-byte error record whose selected callback table connects JSON and MessagePack failures to distinct cleanup paths and to a conditional unwind in the caller.

- Component ID: `abci` / RE-017.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was an unlicensed lead only, and no reference implementation was copied.
- Claim status: observed byte, relocation and LSDA relationships below; inferred labels and unresolved behavior are identified separately.
- Scope included and excluded: 14 newly selected FDE-described ranges, their selected branches, error-record data, selected calls and cleanup paths. The already owned loader and callers are cited only as boundaries; their earlier GOT and call sites are not re-owned. No node #115 or visor claim.

## Reproduce

From the repository root with Python 3.12.3 on Linux x86-64:

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/abci_loader_error94.py --out research/work-items/RE-017-abci-loader-errors-94
python3 -m unittest tests.test_abci_loader_error94
(cd research/work-items/RE-017-abci-loader-errors-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_loader_error94.py --out work/re017-errors-a
PYTHONHASHSEED=31337 TZ=Pacific/Honolulu python3 tools/abci_loader_error94.py --out work/re017-errors-b
diff -r work/re017-errors-a work/re017-errors-b
```

The generator authenticates the whole input before creating its output directory. It uses Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it does not run binutils, a subprocess, the captured binary, or a network service. `MANIFEST.sha256` hashes this README and every generated file. The two comparison directories contain generated files only. The focused tests and independent regenerations also passed with an empty `PATH`.

The additional import-pin check can require writable Git LFS temporary storage in a restricted checkout:

```sh
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=lfs.storage GIT_CONFIG_VALUE_0="$TMPDIR/re017-lfs" python3 tools/verify_imports.py
```

## Evidence

Addresses are linked ELF virtual addresses; machine records also give file offsets. Binary measurements and address lists are read or calculated from ELF bytes, and synthetic inputs are identified separately. `functions.json` preserves each complete selected FDE's raw bytes and hash; `instructions.tsv`, `branches.tsv`, `edges.tsv`, `slot-sites.tsv`, `relocations.tsv`, `layout.tsv`, `rmp-cases.tsv` and the unwind tables contain selected byte-level witnesses. FDE extents are unwind ranges, not a complete function census. Branches and calls are selected, not a recovered whole-program CFG.

### Entry and result handoff

Earlier [round-clock research](../staking-round-clock-94/README.md) places the reload caller under an existing host, while [RE-017](../RE-017-abci-state-link-94/EVIDENCE.md) and [RE-019](../RE-019-rmp-json-loader-94/EVIDENCE.md) bind the `state.rs:107:37` Location to the path-selected loader. This packet leaves those pre-existing call and GOT sites as prior boundaries; the conditions that reach the host's reload call remain a separate question. Within the prior-owned loader, five distinct direct calls target new factory `0x365e7e0`: `0x3c15641`, `0x3c15810`, `0x3c15906`, `0x3c15a40`, and `0x3c15b3e`. After each call, the selected boundary bytes store the returned pointer at output `+0x8` and word `2` at output `+0x0`. The first three correspond to the earlier missing/read/text-read labels; the last two correspond to the earlier JSON and MessagePack decode labels. These format labels are prior-work context, not proof of a concrete input reaching a branch.

The previously documented wrapper propagates that tag and pointer. The prior outer caller's newly examined boundary at `0x3272a13` places the pointer in a local slot and prepares the length-bounded diagnostic `called \`Result::unwrap()\` on an \`Err\` value` at `0x5853b4`. Its call at `0x3272a3f` is followed by a jump to `ud2` if it returns. The call-site LSDA row selects landing pad `0x3272a9c` if that call unwinds; the pad loads the pointer's first word and calls the first entry of the pointed-to table. The record constructor installs table `0x56f1668`, whose first RELATIVE entry names `0x365e520`. Thus, conditional on the pointer being forwarded unchanged and the diagnostic call leaving its local slot intact, an unwind through this landing pad dispatches to the selected record release. No unconditional unwind or runtime reachability is claimed.

### Boxed record and callbacks

Factory `0x365e7e0` passes a stack buffer to an existing external slot, copies 48 bytes from that buffer, and passes the copy with the three-word formatted input to `0x365e850`. The external callee's initialization contract is unresolved. The latter function stages and allocates `0x50` bytes:

| Record offset | Byte-grounded observation |
| --- | --- |
| `+0x00` | Pointer to `0x56f1668` is copied into the allocated record. |
| `+0x08..+0x38` | Three 16-byte chunks of the auxiliary value are copied. The dword at `+0x08` is later compared with `2`. |
| `+0x38`, `+0x40`, `+0x48` | Three input words are copied; selected cleanup tests the first and passes the second and first to the release slot. |

The null-allocation route calls the allocation-failure slot and is followed by `ud2`. If that call unwinds, its LSDA row names a landing pad that invokes stack cleanup `0x35abb30`. If the auxiliary constructor itself unwinds, the factory's separate landing pad conditionally releases the original input buffer. The LSDA row covering the later allocator call has no landing pad in that factory; the stack-record cleanup belongs to the allocator's selected failure route.

These six adjacent RELATIVE entries are examined; no claim is made that they exhaust a larger table:

| Table offset | Target | Selected behavior |
| --- | --- | --- |
| `+0x00` | `0x365e520` | If dword `+0x08` is `2`, call `0x34d9000` on `+0x10`; conditionally release the `+0x38/+0x40` buffer, then release the `0x50`-byte record. |
| `+0x08` | `0x365e3d0` | Return record `+0x38` and a second static address. |
| `+0x10` | `0x365e5e0` | Return the record and a second static address. |
| `+0x18` | `0x365e620` | Compare all 16 input bytes with a constant; return record `+0x38` on equality, zero otherwise. |
| `+0x20` | `0x365e6b0` | Conditionally call the auxiliary cleanup and release the `0x50`-byte record; no message-buffer release is observed in this entry. |
| `+0x28` | `0x365e5a0` | Return zero. |

When the auxiliary cleanup call in the first entry unwinds, its selected LSDA row reaches a pad that still conditionally releases the message buffer, releases the outer record, and resumes unwinding if the cleanup calls return. `0x35abb30` has the corresponding stack-record cleanup but does not release an outer heap record.

### Original error values and nested cleanup

| New FDE | Entry condition and normal release behavior |
| --- | --- |
| `0x3c1b1f0` | A raw word with low two bits other than `1` returns. For low bits `1`, optionally call the descriptor's first function, conditionally release its nonzero-size payload, and release the 24-byte wrapper. This helper is reached on the selected read-error unwind paths. |
| `0x3c1b2c0` | Seven table entries cover tags `0..6`: `0` and `1` select tagged-pointer handling, `2..4` return, and `5..6` conditionally release the buffer at `+0x10` using the size at `+0x08`. Values above `6` take the return branch. |
| `0x3c1b4f0` | Outer word `0` conditionally releases a buffer; word `1` selects tagged-pointer handling; other values skip the nested release. On normal return each route releases the 40-byte outer object. |

For the tagged-pointer arms, the tested pointer word is adjusted by minus one. The descriptor's first function is optional; its `+0x08` word gates payload release, and its `+0x10` word participates in the observed trailing-zero/size comparison that forms the third release argument. If the indirect callback unwinds, each selected LSDA landing pad releases the applicable inner allocation and wrapper before resuming; the JSON arm also releases its outer object. Those statements are conditional on the called release operations returning.

`0x34d9000` handles the auxiliary subrecord. Its mode `2` returns directly; modes `0` and `3` walk elements at stride `0x38` via `0x3bbcd60`, then conditionally release the backing block; other modes reach a diagnostic call. The latter helper walks selected nested elements at stride `0x48`, with distinct zero/minimum-signed and tag-2 skips, and conditionally releases its backing block. `synthetic-cases.tsv` and the focused tests model these actions for bounded raw fixtures; they do not execute machine instructions or deallocate target memory.

### Interpretation and prior-work boundaries

The 48-byte value and `trace_*` identifiers are descriptive labels: its exact type and the behavior of its producer remain unresolved. The copied three-word value is consistent with an owned formatted string, and the returned tag is consistent with an error result; neither Rust type identity nor valid raw-state domains are established here. The two table view entries' static metadata, the 16-byte comparison constant's source type, allocator internals, callback implementations, and all unselected exits remain open. `unwind.tsv` records call-site rows and action indices; it does not interpret personality routines or action/type tables.

## Implementation and comparison

Not yet implemented. There is no reconstructed Rust component, build, differential execution, source-to-binary comparison, normalization mask, or claim about live behavior. No target executable, dataset, key, chain action or network is used.

## Results and limitations

The deterministic extractor records 14 selected FDEs spanning 1,851 bytes, 55 selected instruction windows, 46 selected conditional branches, 17 selected direct calls, 15 selected indirect slot sites, six descriptor relocations and five previously existing external-slot relocations, seven RMP table entries, 31 LSDA rows and 16 selected LSDA witnesses. It also emits 326 synthetic cases. These are explicitly selected records, not coverage denominators. The focused suite passed 23 tests with zero skips, including a modified target byte and FDE, wrong digest, duplicate/changed relocation, out-of-range and in-range wrong table targets, malformed LSDA data, all 256 RMP tag bytes, all 16 comparator byte positions, nested cleanup and conditional unwind controls.

No component progress gate is requested: begin/action/end-block and state-root closure are not recovered, and the `abci` component remains 0/4. Next question: establish the typed contents and producer of the auxiliary value, and trace the separately owned success path into begin/action/end-block and state-root inputs without duplicating existing work.
