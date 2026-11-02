# RE-009: EVM user-state collection codec

The node's selected EVM user-state collection codec associates a 20-byte user key with a four-field value, giving a reconstruction the field layout, omission predicates, reader branches, and duplicate-key behavior for this storage path.

- Component ID: RE-009, storage and state roots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23` was not used as authority or copied.
- Claim status: observations for authenticated code, data, calls, and branches; inference for the corresponding collection and value roles; unresolved for full format and persistence semantics.
- Scope included and excluded: selected collection reader and writer routes, nested value layout, key dispatch, field omission, defaults and selected failure branches. No claim about full snapshot format, state-root construction, all callers, helper internals, runtime behavior, other releases, or full function coverage.

## Reproduce

From the repository root on Linux x86-64, using Python 3.12.3, the standard library, and the repository's shared `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/evm_user_state94.py --out work/evm-user-codec-94
python3 -m unittest tests.test_evm_user_state94
cmp work/evm-user-codec-94/evidence.json research/work-items/RE-009-evm-user-codec-94/evidence.json
cmp work/evm-user-codec-94/fields.tsv research/work-items/RE-009-evm-user-codec-94/fields.tsv
cmp work/evm-user-codec-94/fixed-headers.tsv research/work-items/RE-009-evm-user-codec-94/fixed-headers.tsv
(cd research/work-items/RE-009-evm-user-codec-94 && sha256sum -c MANIFEST.sha256)
```

The generator admits only the full target digest, reads file-backed ELF sections, checks FDE starts and extents against the unwind index, authenticates each selected body and byte window, decodes fixed instruction shapes and relocations, and writes the three generated files. Their hashes and the README hash are in `MANIFEST.sha256`. `SHT_NOBITS` is excluded from file-byte lookup. The generator and tests use no external programs, clock, network, or target execution. GNU objdump 2.42 was used only to inspect selected code manually, never as generator or test input. No fixture, key, database, chain access, or node execution was used.

## Evidence

Addresses are unrelocated ELF virtual addresses; file offsets and exclusive FDE endpoints are recorded in `evidence.json`. An FDE extent is unwind metadata, not proof of a complete source-level function or cold-part boundary. The selected 16 extents are not a coverage denominator. Raw bytes for 50 bounded windows, 47 direct call sites, 61 conditional transfers, two 33-entry relative tables and four relocation records are retained in that file. The analysis is limited to these selected ranges.

### Collection routes

| Path | Selected call chain or test | Observation |
| --- | --- | --- |
| JSON-shaped collection reader | `0x3619930` -> `0x3023060` -> `0x3157280` | The collection calls the value reader before insertion. The value reader's type-error descriptor has an `R_X86_64_RELATIVE` relocation to the formatter at `0x37609b0`, which supplies `struct EvmUserState`. |
| Binary collection reader, map | `0x18b68c0` -> `0x2655570` -> `0x1a51b00` | The key child receives the literal `User` and the value child parses the four fields. |
| Binary collection reader, rows | `0x18b68c0` -> `0x26a5e90` -> `0x19b1850` -> `0x1a51b00` | A separate outer sequence of entries reaches the same binary value reader. |
| Collection writer | `0x25df210` -> `0x1e4acb0` -> `0x1dd2920` -> `0x275db60` or `0x275d830` | The adapter calls a separate collection helper, then a row loop. The row loop advances by 16 bytes and calls the entry writer; the entry writer selects a direct or generic value writer. The direct entry route writes marker `0x92` before the entry children. |

The helper at `0x256df50` is an unresolved boundary: the present packet does not re-analyze its ordering, ownership, or allocation. Prior `RE-009-app-hash-builder-94` is useful context for the containing state-root pipeline; the prior closure is outside the extents claimed here. The binary and JSON reader/value-writer correspondence is inferred from the field labels, value offsets, child calls, and duplicate handling; the formatter establishes the JSON reader's type label, not recovered Rust source.

On the selected fresh-byte route, `0x18b6c48` tests a raw negative byte against `0x90`, and the array branch at `0x18b6d98` tests `0xa0`; both mask the low nibble as the count. The 32-byte decision table `fixed-headers.tsv` lists every marker from `0x80` through `0x9f`: `0x80..0x8f` go to the map child, and `0x90..0x9f` to the row-array child. This table does not claim to enumerate cached token states, extended markers, or all malformed inputs. Insufficient bytes, nesting limits, child errors and remaining-entry checks have distinct exits in the selected bodies; not all of their callees are closed.

The JSON and map-reader insertion calls at `0x3619c6c` and `0x2655843` reach `0x3396d00` and `0x2856720`. Both selected comparison windows call the relocated `memcmp` slot with length 20. The equal branch copies a 32-byte value, and the caller's non-sentinel result builds `duplicate key` before returning an error. These are observed duplicate-key paths; the packet does not establish iteration order or a complete duplicate policy for the separate row-array route.

### Value fields and writer decisions

The compact and JSON dispatch tables at `0x3aaddc` and `0x57c60c` each span 33 entries for the inclusive byte range `T` through `t`. Four entries select the field cases below; the other 29 in each selected table share that table's fallback. The binary reader has additional string-decoding routes; this observation is not a complete string grammar. `fields.tsv` supplies literal addresses and both field-case targets, all extracted from authenticated bytes.

| Field | Input offset | Selected writer condition | Binary case | JSON case |
| --- | --- | --- | --- | --- |
| `g` | `+0x00` | emit if its 64-bit word is nonzero | `0x1a52b21` | `0x3157560` |
| `t` | `+0x08` | emit if its 64-bit word is nonzero | `0x1a52bc2` | `0x3157628` |
| `b` | `+0x1c` | emit if the valid boolean byte is true | `0x1a52c83` | `0x31575d2` |
| `T` | `+0x10` | emit if its three 32-bit words differ from the writer's default | `0x1a52c40` | `0x315746f` |

The generic writer `0x275d830` computes the selected-field count in that order. Its default comparison calls the relocated helper at `0x151f6f0` with immediate `0xaf93b`, and compares its nonzero result with the first `T` word while requiring the next two words to be zero. A zero helper return follows a separate error path. For serializer mode byte `+0xb` equal to 1, selected names precede their values; for 0, the array-header route omits names. Other mode-byte values are outside the claim. Both numeric children use `0x25ac0d0`; the meaning and signedness of the words are unresolved. The direct writer has corresponding literal stores and predicates. Failures in header, name, and value children take selected error transfers recorded in `evidence.json`.

### Reader branches and failures

On either selected map path, `g` and `t` have separate presence slots, so a successfully read zero still marks the field present. The `b` cases compare a sentinel value 2 before accepting the field. The `T` cases instead test whether the first 32-bit word is nonzero: the duplicate branch is established when that word is nonzero, and behavior after a child returns a zero first word remains a distinct case. Each selected duplicate branch supplies its field byte to common `duplicate field` format data; the generator verifies both the name pointers and that format prefix. Failed child parsing follows separate exits before the successful field update.

When absent at map completion, the observed `g`, `t`, and `b` values become zero, zero, and false. The JSON `T` default path calls the helper with `0xaf93b` and uses zero for the remaining eight bytes; the binary reader calls a separately relocated default constructor. The equality of every possible helper result is not assumed. Unknown fields enter separate value-handling paths through `0x19682d0` and `0x2fe3390`; their selected success and error transfers are recorded, but their full semantics are not reconstructed.

The binary value reader's selected short-array route reads `g`, then `t`, then `b`, then `T`. With successful children, counts 0 through 4 reach the appropriate prefix and default the remainder; counts above 4 take the remaining-elements error route. Malformed child values may take precedence over the count error. Branch sites and raw windows are in `evidence.json`; this is a reading of selected machine code, not a captured input/output run.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No compiler flags, build, binary comparison, normalized mask, helper closure, runtime fixture, or target execution is claimed. The focused tests exercise digest mismatch, selected body and window mutation, wrong call and branch bytes, NOBITS and range rejection, FDE/index disagreement, duplicate or missing relocation, field-name and duplicate-format mutation, table targets, header endpoints, and child-error transfers.

## Results and limitations

The extractor checks 16 selected FDE extents, 50 windows, 47 direct calls, 61 conditional transfers, four relocations, two 33-entry field tables and 32 fresh-byte short-container cases. Fifteen focused unittest methods passed with no skips. These are bounded evidence counts, not overall function coverage or equivalence. No milestone gate is requested. The exact on-disk embedding, ordering of nonempty collections, long container headers, complete malformed-input grammar, default-constructor equivalence, `T` representation, and domain meanings of the four fields remain open.

Next question: trace the unclaimed parent and separately owned collection helper to establish the snapshot entry point and ordering, then compare complete offline fixtures when target execution is explicitly authorized.
