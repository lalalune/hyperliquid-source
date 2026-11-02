# RE-017: JSON state tail rejection and temporary-state cleanup

On node #94, a disallowed byte after a decoded JSON result whose tag is not `2` selects error code `0x16`, changes the result to tag `2`, and routes the temporary state through distinct nested cleanup loops, allowing a reconstruction to preserve this failure path.

- Component ID: `abci`, RE-017; bounded to the JSON arm of the state loader.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was an unlicensed lead, not an implementation source.
- Claim status: the selected instructions, displacements, FDEs and LSDA rows are observations. The Result, parser, vector and release names are interpretations; their assumptions and unresolved parts are below.
- Scope included and excluded: seven newly selected FDE ranges, their selected normal and unwind continuations, one prior JSON-reader boundary and the documented earlier loader context. The original RE-017 GOT and call sites are not re-owned. Other JSON values, the MessagePack arm, full helper closure, runtime reachability, node #115 and visor are excluded.

## Reproduce

Use Python 3.12.3 on Linux x86-64 from the repository root. The node #94 artifact is required. Replace `<tmp-dir>` with an initially empty writable directory:

```sh
python3 tools/artifacts.py verify
python3 tools/abci_json_tail_cleanup94.py --out research/work-items/RE-017-abci-json-trailing-cleanup-94
python3 -m unittest tests.test_abci_json_tail_cleanup94
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_json_tail_cleanup94.py --out <tmp-dir>/first
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/abci_json_tail_cleanup94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/first research/work-items/RE-017-abci-json-trailing-cleanup-94
(cd research/work-items/RE-017-abci-json-trailing-cleanup-94 && sha256sum -c MANIFEST.sha256)
```

The producer first authenticates the entire artifact, reads it through a read-only mapping and imports the repository's `elf_index.py` and `fde_extents.py`. It rejects NOBITS, ambiguous and out-of-range byte mappings. It reads the selected bytes, actual CIE/FDEs, unwind-index entries and supported LSDA call-site tables directly. Neither producer nor tests start external programs or execute the artifact. GNU objdump 2.42 was used only for bounded human inspection; its text is not a producer input. The generated files are `functions.json`, `windows.tsv`, `branches.tsv`, `edges.tsv`, `operands.tsv`, `layout.json`, `unwind.json`, `unwind.tsv`, `normalized-pair.json`, `suffix-byte-cases.tsv` and `summary.json`. The manifest covers those files and this README.

## Evidence

All addresses are unrelocated ELF link-time virtual addresses. Generated records retain the corresponding file offsets and original bytes. An FDE is a described unwind extent, not proof of every source-function boundary. The seven selected extents below are distinct from the earlier loader and are not a component-wide function census.

| Selected role | FDE start | Exclusive end | Selected observation |
| --- | --- | --- | --- |
| Error-position helper | `0x2fe32d0` | `0x2fe3388` | Scans a bounded byte prefix into two counters and tail-transfers through an existing slot. |
| Parsed-payload cleanup | `0x2ff8b70` | `0x2ff9627` | Enters the group cleanup, then walks two differently sized outer sequences. |
| Group-vector cleanup | `0x3005ef0` | `0x30061f4` | Walks `0x2f0`-byte entries and has a remaining-entry unwind loop. |
| Outer-A item cleanup | `0x3bbd260` | `0x3bbd379` | Walks `0xd8`-byte nested entries and has a remaining-entry unwind loop. |
| Group item cleanup | `0x3bbe610` | `0x3bbe81d` | Walks `0x30`-byte inner entries and conditionally calls the release slot. |
| Outer-B item cleanup | `0x3bb9d50` | `0x3bb9ea9` | Walks tagged `0xf8`-byte entries and releases selected child allocations. |
| Outer-A nested item cleanup | `0x3bbf380` | `0x3bbf4d9` | Has the corresponding tagged-entry path with the same selected targets. |

### Prior entry and new result boundary

Earlier [RE-017](../RE-017-abci-state-link-94/EVIDENCE.md) binds the state Location to its loader, and [RE-019](../RE-019-rmp-json-loader-94/EVIDENCE.md) identifies the loader's JSON arm and its `0x1fc8`-byte payload. The previous JSON reader `0x2fe2fe0` is a **boundary**, not a newly selected function. Its new selected continuation calls the already studied state reader `0x315ba80`, tests the output dword, and passes the non-`2` output and a stack destination to the previously identified copy slot with length `0x1fc8`. The following selected instructions use the copied stack temporary for the error cleanup. The interpretation that it is a copy depends on the prior slot attribution and ordinary copy behavior.

The resulting **conditional** route joins this new continuation to prior observations: the `state.rs:107` wrapper `0x3273810` calls the path loader `0x3c155a0`, whose JSON arm calls the boundary `0x2fe2fe0`. If the new rejection and its cleanup return normally, the loader's previously studied JSON-error branch formats and boxes a new error. RE-017 records that the wrapper propagates the loader's tag `2` and second word; the round-clock packet and open PR #1880 place the outer caller `0x32725d0` on a diagnostic path for that tag. Boxing changes the error object, so the JSON error pointer is not asserted to be the same as the propagated boxed pointer. The prior functions and their existing call sites remain context rather than new ownership; reaching the initial loader path is not established here.

The human-readable excerpt below corresponds to the raw windows and edges, not a generated disassembly file:

```text
0x2fe3047  83 3b 02                 cmp dword [rbx], 2
0x2fe304a  0f 84 93 00 00 00        je  0x2fe30e3
0x2fe3055  ba c8 1f 00 00           mov edx, 0x1fc8
0x2fe3095  48 83 ff 20              cmp rdi, 0x20
0x2fe309b  48 0f a3 fe              bt  rsi, rdi
0x2fe30ce  48 89 43 08              mov [rbx+8], rax
0x2fe30d2  48 c7 03 02 00 00 00     mov qword [rbx], 2
0x2fe30de  e8 8d 5a 01 00           call 0x2ff8b70
```

The length and cursor are compared unsigned. A cursor at or above length bypasses the selected scan. Otherwise, the mask loaded at `0x2fe307d` is `0x100002600`; a byte must be at most `0x20` and have its mask bit set. The 256 synthetic one-byte cases generated from that instruction admit exactly `0x09`, `0x0a`, `0x0d` and `0x20`. Accepted bytes advance the stored cursor. A different byte leaves that cursor at the rejected byte, places `0x16` in a local word, calls `0x2fe32d0`, writes its returned word at output `+8`, writes qword `2` at output `+0`, and passes the stack temporary to `0x2ff8b70`. The selected non-`2`, all-accepted suffix path bypasses this error construction. These are conditional static paths, not examples of an executed snapshot.

The position helper first rejects a cursor equal to the maximum unsigned word through a diagnostic path. Otherwise it scans `min(cursor + 1, length)` input bytes, starting its first counter at 1 and the second at 0. Byte `0x0a` increments the first and clears the second; every other byte increments the second. Both increments have overflow branches. On the rejected-suffix path, the bad byte is included because the earlier scan did not advance past it. This is byte counting, not a claim about Unicode character columns. The helper's final slot is a previously recorded boundary; this packet does not re-publish or claim that slot's relocation or the external callee.

### Selected cleanup layout

Offsets are relative to the temporary payload, except where the table names an outer or group item. `layout.json` derives them from the corresponding instruction operands and selected call displacements. Labels such as capacity and count describe how the values are used; the exact Rust types remain unknown.

| Container | Capacity, pointer, count offsets | Item stride | Selected item target |
| --- | --- | --- | --- |
| Payload group sequence | `+0x5b8`, `+0x5c0`, `+0x5c8` | `0x2f0` | `0x3bbe610` via `0x3005ef0` |
| Payload outer A | `+0x1848`, `+0x1850`, `+0x1858` | `0x138` | `0x3bbd260` |
| Payload outer B | `+0x1860`, `+0x1868`, `+0x1870` | `0xd8` | `0x3bb9d50` |
| Outer-A item sequence | `+0`, `+8`, `+0x10` | `0xd8` | `0x3bbf380` |
| Group-item child sequence | `+0`, `+8`, `+0x10` | `0x30` | Inline conditional release |
| Selected `0xd8` item sequence | `+0`, `+8`, `+0x10` | `0xf8` | Inline tag and conditional release |

On each selected normal sequence, the count controls the item walk and a nonzero capacity controls the later backing-allocation release. The multiplication for the release size is performed in a 64-bit register; the packet does not infer a separate overflow check or validity of arbitrary corrupt headers. The group item's child loop loads a size and pointer from each `0x30`-byte entry, skips the selected release when the size is zero, and otherwise calls the previously known release slot. Its backing-size computation independently gives the same `0x30` multiplier as the loop stride.

The two `0xd8` item functions visit embedded offsets `0x80` and `0x98`, then inspect a nested sequence. Each `0xf8` entry uses a dword at entry `+0` as a tag. Tag `2` skips its selected child release; otherwise a zero word at `+0x50` also skips it. A nonzero word supplies eight times that value as size and the word at `+0x58` as the pointer. An earlier order-export packet (open PR #1598) independently reports the same payload offsets `+0x5c0` and `+0x5c8` and stride `0x2f0`; the matching operands establish compatible local layouts, not identity between the rejected temporary and any later exported or live state.

The paired `0x3bb9d50` and `0x3bbf380` FDE bodies are each 345 bytes. Their raw bytes differ at 35 positions. After masking exactly the 14 four-byte relative displacement fields enumerated in `normalized-pair.json`, the bodies match; each masked instruction is independently required to resolve to the same pinned absolute call or slot target. This is a comparison of these captured bodies only. It does not establish equivalence of external helper internals, dynamic bindings, data, relocations, vtables or whole ELFs.

### Selected failure and unwind paths

`unwind.json` preserves all selected LSDA call-site rows; the action numbers are raw selectors, not interpreted personality actions. The key conditional relations are:

| Call site | If its LSDA landing is selected | Observed continuation |
| --- | --- | --- |
| `0x2fe30c9` | `0x2fe3105` | Calls `0x2ff8b70` on the temporary before the later unwind-resume path. |
| `0x2fe30de` | `0x2fe311a` | Enters the later cleanup/resume path after the result has been tagged. |
| `0x2fe310d` | `0x2fe3114`, action 1 | Transfers through a separate existing slot; its personality semantics are unresolved. |
| `0x2ff8bb0` | `0x2ff9469` | Continues with remaining outer-A entries, then its backing-release path. |
| `0x2ff8c00` | `0x2ff9423` | Continues with remaining outer-B entries, then its backing-release path. |
| `0x3005f30` | `0x3006132` | Continues the `0x2f0`-stride group walk, then its backing-release path. |
| `0x3bbd290` | `0x3bbd30a` | Continues the nested `0xd8`-stride walk, then its backing-release path. |

Statements about a later cleanup call or unwind resume are conditional on prior helpers returning and on the stated LSDA landing being selected. The packet does not interpret the type or action tables, prove a particular exception is thrown, or claim that selected release calls actually free memory in every runtime binding.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, target execution, differential fixture, reconstructed-source comparison or complete helper/data/relocation closure is claimed. The single normalization described above compares two original target FDE bodies; it is not a source-to-target identity result. The captured binary and its inputs are read-only, and no network or chain action is used.

## Results and limitations

The producer records 7 selected FDEs plus 1 prior boundary, 14 fixed windows, 37 branches, 23 selected transfers, 45 extracted operands, 6 projected vector layouts, 8 LSDA tables with 97 call-site rows and 13 selected unwind witnesses. It emits 256 synthetic suffix-byte cases, of which 4 are admitted. The focused suite passes 23 tests with no skips; it mutates the digest, actual FDE, bytes, each selected branch and operand, each transfer, LSDA headers/tables and every normalized displacement, and rejects invalid, ambiguous or fileless mappings. The producer and tests require no binutils in `PATH`.

This establishes a bounded failure continuation, not the requested complete begin/action/end-block and state-root path. The complete JSON reader, all nested destructors and allocator behavior, the old loader-to-live-state identity, scheduling, remaining exception actions, and a Rust reconstruction remain open. The `abci` gate remains 0/4 and no milestone change is requested. Open-PR ownership review used the supplied snapshot and locally available draft contents; some open PR bodies were unavailable offline.

Next question: connect an unowned successful-loader transfer to a specific live block receiver and state-root input, while accounting for intervening copies and writes, without re-owning the loader or established worker functions.
