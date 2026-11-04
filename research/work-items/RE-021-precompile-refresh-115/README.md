# RE-021: node 115 precompile registry refresh and compact projection

The node #115 reconstruction can now distinguish a raw selector change from a mode change and specify how a replacement precompile address set is copied into a compact bit projection and a full-key set, including the conditions under which address `09` contributes bit 9.

- Component ID: `evm`. RE-021 is a bounded extension of RE-011, not an official TASKS row.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; the earlier #94 work item is available in that commit's parent. No inferred reference source was copied.
- Claim status: selected raw bytes, FDEs, relative relocations and LSDA intervals are observations; the set, map and projection names and normal-return relationships are inferences. Live configuration, source types, source lineage and runtime memory remain unresolved.
- Scope included and excluded: the selected context entry, changed/unchanged selector branches, replacement-set call sites, reserve and full-set replacement, compact bit projection, optional nested 32-byte-key map, and selected failure and unwind paths. The upstream construction of the original address set, callback execution and rollback are separate prior boundaries. This is not a full reth/revm fork boundary or state-transition inventory.

## Reproduce

From the repository root with the authenticated #115 artifact and Python 3.12 available:

```sh
python3 tools/re21_registry_refresh115.py --out research/work-items/RE-021-precompile-refresh-115
python3 -m unittest tests.test_re21_registry_refresh115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For repeatability, replace `<tmp-dir>` with an existing writable directory:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/re21_registry_refresh115.py --out <tmp-dir>/one
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/re21_registry_refresh115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The generator first authenticates the entire node file against the full SHA-256 above. It imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`, uses only Python's standard library, never runs an external process or target code, and excludes SHT_NOBITS sections from file-byte reads. Python 3.12.3 was used. GNU objdump 2.42 was used only for manual instruction interpretation; generated records and tests do not parse its output. The generator writes the JSON and TSV evidence only, leaving this README and `MANIFEST.sha256` alone. The manifest covers every other file in this directory.

The two manual inspection windows below are optional and are not inputs to the generator or its tests:

```sh
objdump -d --start-address=0x2a6b7a0 --stop-address=0x2a6b875 artifacts/node/115/hl-node
objdump -d --start-address=0x5bdf7ba --stop-address=0x5bdf830 artifacts/node/115/hl-node
```

## Evidence

Addresses below are linked ELF virtual addresses before load bias. Relocation values are `R_X86_64_RELATIVE` addends, not runtime addresses. `functions.json` joins each selected start with both `.eh_frame_hdr` and its full FDE and contains the actual exclusive end, file offset, body bytes, SHA-256, FDE and CIE bytes. These are selected unwind intervals, not a complete function census. `windows.tsv` and `edges.tsv` contain selected raw instruction windows and decoded relative transfers, not a complete disassembler or CFG.

| Inferred role | FDE start | FDE end, exclusive |
| --- | --- | --- |
| Context preparation | `0x2668a20` | `0x2668e7a` |
| Nested map cleanup | `0x2a03a10` | `0x2a03b0f` |
| 20-byte map probe | `0x2a318d0` | `0x2a31a25` |
| Nested 32-byte key insertion | `0x2a32b00` | `0x2a32c97` |
| Raw selector update | `0x2a6b7a0` | `0x2a6b875` |
| Replacement-set builder | `0x38be4a0` | `0x38be7f6` |
| 20-byte set cleanup | `0x3ec3f40` | `0x3ec3f7b` |
| Full-set copy or replacement | `0x5bdf390` | `0x5bdf60e` |
| Compact projection and copy | `0x5bdf610` | `0x5bdf8d7` |
| 20-byte set reserve | `0x5be4f10` | `0x5be533a` |

### Selector and update path

At `0x2668a3e` the entry reads the byte at context +`0x268`, stores it at +`0x396`, and calls `0x2a6b7a0` with context +`0x3e0`. If the helper returns nonzero **or** the word at context +`0x2d0` is zero, the call at `0x2668a83` uses relocation slot `0x64e5ff0` to reach `0x5bdf610`, with destination context +`0x2b8` and source context +`0x3f0`. If the helper returns zero and that word is nonzero, the call is skipped. The normal exit writes `0x25` into the output word; its source-level variant name is unknown.

| Selector comparison | Context word +`0x2d0` | Selected normal-return path |
| --- | --- | --- |
| Same raw byte | Nonzero | Updater returns zero and compact/full-set projection is skipped. |
| Same raw byte | Zero | Updater returns zero and projection is called. |
| Different raw byte | Either | Updater takes the replacement path; after its normal return, projection is called. |

`0x2a6b7a0` compares the new low byte with the prior byte at provider +`0x08` **before** indexing the table at `0x606f1f`. Equality returns zero without rebuilding. For a different byte it indexes this table, multiplies the result by the 96-byte registry-slot stride, and conditionally calls the existing once-initialization boundary if slot +`0x58` is nonzero. It writes the slot pointer and new raw byte at `0x2a6b7e7` and `0x2a6b7ea`, then calls the replacement builder through relocation slot `0x64e7158`, releases the prior set when indicated, copies the new 40-byte set header, and returns one. The selected initialization helper body is outside this packet.

`mode-cases.tsv` records the 15 inspected bytes, without claiming the full table domain. Entries 7 and 8 both contain mode 3, yet a 7-to-8 transition takes the changed-byte path. This is relevant when rebuilding a context: equality of decoded modes alone does not justify skipping the selected refresh. The stores of the new pointer and selector occur before the builder call. The exceptional outcome of that partial update is not established by this ordering alone.

If the selector byte is above 9, `0x2668a8e` writes 1 at context +`0x320` and copies 20 bytes from +`0xa8` to +`0x321`; the other branch skips those writes. This does not establish the prior or later value of the destination.

### Set construction and address 09

The builder at `0x38be4a0` passes the chosen registry slot +`0x28` to the copy-shaped helper boundary `0x3ec4290`, with a 40-byte temporary as its output. It chooses a reserve hint of 21 when a count-shaped word in that output is zero, otherwise 11, and calls the reserve helper if the hint exceeds the growth-shaped word. Its 21 fixed-shape copy/call windows then load their full 20-byte keys from file-backed data and call `0x3ed7620`. `set-copies.tsv` retains the source and call coordinates, source bytes, call bytes and callee. In insertion order the key suffixes are `0800`, `0813`, `0801` through `0812`, then `0814`; none is `09`. A normal return copies the resulting set header to the caller. Open PR 2104 records `0x3ec4290` and `0x3ed7620` as call boundaries in a different initial-provider route; their bodies are not selected or analyzed here. The update-specific 21 call sites are distinct from the initial-provider sites.

The selected reserve helper checks count addition and allocation arithmetic; it either calls a separate in-place rehash boundary or allocates and rehashes. For a valid power-of-two bucket count `mask + 1`, its capacity is `mask` when `mask < 8`, otherwise `(mask + 1) - ((mask + 1) >> 3)`. If `count + additional` is at most half that capacity it selects the separate in-place rehash boundary; otherwise it selects a checked new allocation. Size overflow and null allocation reach separate failure paths. The synthetic reserve tests compare the selected capacity and allocation arithmetic against a separate capacity-based oracle; they do not execute the target. The called clone and insertion bodies are external boundaries for this packet, so preservation of an incoming member is an explicit assumption rather than a newly established fact.

The `09` dependency is anchored in #115 data separately from those 21 keys. At `0x64c0730`, the 56-byte record has little-endian tag `0x8000000000000009` and its 20-byte field at +`0x20` ends in `09`; its +`0x18` relocation names `0x5c165b0`. `dependency-anchor.json` retains the bytes, file offset and relocation. Open PR 2049 analyzes how this record enters the ordinary mode-dependent callback registry and how the ordinary lookup invokes it; that is a prior, still-open dependency and its code is not included as a selected FDE here.

**Conditional inference:** if the registry's source set already contains the full `09` key, if its clone and the 21 insertions return normally and preserve existing distinct keys, and if later mutation does not remove it, this builder leaves `09` in the replacement set. The mere existence of the callback record does not prove that this separate source set contains it. Establishing that link, the live selector and the runtime call remains future work.

The selected nested-map probe at `0x2a318d0` hashes a 20-byte row key using two little-endian 64-bit words and one little-endian 32-bit word. With `fold(a,b) = low64(a*b) XOR high64(a*b)`, observed instructions yield `fold(fold(u0 XOR seed, u1 XOR secret) XOR u2, secret)`. The high seven bits are the control fingerprint; the full key is then compared. The secret's relocation points into a NOBITS section, which has no file-backed runtime value; `runtime-boundary.json` records the section and leaves the value null. Tests use explicitly synthetic secrets and controls only.

### Compact projection and optional nested state

`0x5bdf610` derives a bit-span bound from destination +`0x58` and scans occupied full-set entries. For each 20-byte key it requires the first 18 bytes to be zero, reads the final two bytes as a big-endian number, and checks the immediate `0x12c` at `0x5bdf7f2`. Values at least 300 skip the compact-bit operation. Values below 300 take a second bounds check; if the derived bound is not greater than the index, execution branches to the failure path at `0x5bdf884`. Otherwise `0x5bdf829` ORs a single bit at the calculated location. The representation includes a head offset, so “bit 9” means logical index 9, not necessarily bit 9 of the first machine word.

`key-projection.tsv` derives the comparison for the 21 observed builder keys and the record's actual 20-byte `09` field. All 21 builder keys fail the `< 300` test, while `09` passes with index 9. Thus, on an occupied `09` entry and with bound greater than 9, the selected path ORs the logical bit for 9. This conclusion is conditional on `09` actually being in the source set. After the scan the function writes a byte at destination +`0x7d`, calls `0x5bdf390` to copy or replace the **full** set, and copies the source seed word. A key that skips the compact-bit operation is not thereby removed from the full-set copy.

| Source and destination set masks | Selected `0x5bdf390` branch |
| --- | --- |
| Source mask zero | Publish the empty header and release old backing when indicated. |
| Equal nonzero masks | Make two copy-shaped calls and copy the selected header fields. |
| Different masks | Check size, allocate, publish the new header, release old backing when indicated, and reach the two copy-shaped calls. |

These descriptions assume normal return from the indirect copy and release boundaries. The separate LSDA cleanup below is the observed exceptional alternative, not a complete transactional guarantee.

If the byte at context +`0x1f1` is nonzero, `0x2668a20` also processes rows using pointer and count at +`0x178` and +`0x180`, with a 48-byte stride. Each row contributes a 20-byte key at +`0x18` and a nested pointer/count at +`0x08`/`0x10`. `0x2a318d0` probes a temporary map of 64-byte entries; a miss follows an insertion path and a hit reuses its entry. For each nested 32-byte key, `0x2668d40` loads four words, byte-swaps each and writes them in reverse word order before `0x2a32b00` inserts it. For these four complete words the resulting 32-byte sequence is the reverse of the input byte sequence. The destination's prior map at context +`0x2e0` is cleaned up and replaced with the temporary 40-byte header only on the selected normal completion. A zero feature byte skips that nested-map replacement. This is a byte-level map description, not proof of the source-level meaning of the rows or of every exceptional path.

The two nested growth checks have different ordering. The 20-byte map probe searches first: a matching full key returns the existing entry, while a miss checks the growth word and may call its reserve boundary before handing a miss descriptor to the caller. The caller then writes a new 64-byte record and mirrored controls. In contrast, the 32-byte nested helper checks its growth word before looking for a duplicate; its match branch compares both 16-byte halves, and a new entry writes the full 32-byte key and mirrored controls. The helper implementations behind the reserve slots are outside this packet.

### Failures and unwind evidence

| Condition or call | Selected observed consequence |
| --- | --- |
| Changed selector, then builder throws | Pointer and selector stores precede the builder call; this packet does not establish rollback of those stores. |
| Set reserve or full-set replacement size overflow | A branch reaches an error helper; exact source exception type is unresolved. |
| Allocation returns null | Reserve and replacement have separate failure paths; allocator internals are not modeled. |
| Projection index outside the derived bound | The selected branch reaches `0x5bdf884` before the normal full-set copy. |
| Any of 21 builder insert calls unwinds | The decoded LSDA maps each selected call to landing `0x38be7e1`; it calls `0x3ec3f40` for the temporary set, then the unwind-resume boundary. The reserve call has landing `0x38be7df`, which joins the same cleanup. |
| Selected optional nested-map calls unwind | Their LSDA entries select `0x2668e63` or `0x2668e65`, leading to `0x2a03a10` for the temporary nested map and then unwind-resume. |
| Full-set replacement's old-drop call unwinds | Its LSDA selects `0x5bdf5b0`, which clears selected destination bookkeeping/control bytes before unwind-resume. |

`lsda-headers.json`, `lsda-call-sites.tsv` and `selected-call-sites.tsv` retain four decoded table headers, 15 call-site records and joins for 42 selected call sites. A zero landing or absent selected table entry does not prove a call cannot unwind. LSDA action/type semantics and unselected helpers are not decoded.

### Historical release separation

The earlier `RE-021-blake2b-compress-94` packet belongs to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. It reported address-09 object/callback coordinates `0x574f0b0` and `0x574f0c0`, wrapper `0x4e9d2a0`, and a compression candidate at `0x4e9a8a0`. Those are #94 coordinates only. Its prior review and any historical execution receipts were not rerun. The present #115 record, relocation, set keys, FDEs and bytes are independently extracted from the authenticated #115 artifact; they are not byte-equivalence evidence between releases. The #94 artifact was unavailable for a new direct comparison.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo graph, compiler/linker settings, repeat builds and raw or normalized native comparisons: not yet measured. No normalization masks, helper/call-target closure, vtable/data closure or whole-ELF equivalence are claimed. The tests cover corrupted artifact bytes, selected FDE bounds and hashes, relocations, opcode/data shapes, unbacked ranges, LSDA tables, all 160 key bits, compact-index boundaries, nested-key length and byte-order boundaries, and synthetic grouped-probe and reserve overflow/size cases. They are static controls, not target execution or an independent behavioral oracle.

## Results and limitations

The reproducible selection contains 10 FDE intervals totaling 5,658 bytes, 39 raw windows, 47 selected transfers, 9 relative-relocation records and 21 replacement insertion calls. These denominators describe this deliberately bounded selection, not total coverage. The focused suite passed 32 tests with zero skips; artifact verification and the catalogue check passed. Two regenerations with different hash seeds and time zones were byte-identical, including with binutils absent from PATH. No node or captured code was executed.

The original registry's `09` set membership, live selection, synchronization and external helper semantics, complete exception behavior, callback computation, reth/revm private-fork boundaries, state transitions and Rust reconstruction remain unresolved. The `evm` progress gate stays at 0/4; no gate change is requested. Next, trace how the address-09 callback record is inserted into the particular registry +`0x28` source set, using a previously unowned function path and an explicit join to the already-reviewed registry construction.
