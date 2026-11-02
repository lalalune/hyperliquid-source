# RE-006: how the first insertion's fill vector reaches the two-insert handoff

On the successful first-insertion path, a `0x228`-stride collector retains the input base and capacity, and a later size-bounded clone normalizes record tags before the prior result can reach the two-insert merge.

- Component ID: RE-006, order-book state transitions.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; no reference code is incorporated.
- Claim status: instruction bytes, FDE ranges, fixed calls, relocation records and branch destinations are observations; the names fill, insertion, error and vector are inferences supported by caller context and prior work, not recovered symbol names. Target execution is not claimed.
- Scope included and excluded: six selected FDEs for the first-result adapter, its collector and record clone; specific windows in two calling hosts; and the selected direct and indirect edges. The existing two-insert merge work leaves construction of its prior record outside scope. The existing insertion bodies, common processor, merge implementation, allocator implementations and unrelated host paths are boundaries here. The first result's complete non-vector payload, the book mutation itself, full rollback, and all possible callers are not established.

## Reproduce

From the repository root with the captured node #94 installed at its artifact location, choose two distinct empty output directories represented by `<tmp-dir-a>` and `<tmp-dir-b>`:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/book_fill_handoff94.py --out <tmp-dir-a>
PYTHONHASHSEED=8675309 TZ=Pacific/Honolulu python3 tools/book_fill_handoff94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
python3 -m unittest tests.test_book_fill_handoff94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Compare each of the four generated files in either temporary directory with the file of the same name beside this README. `MANIFEST.sha256` records the hashes of this README and those generated files. The extractor authenticates the whole input before parsing and uses the repository's `tools/elf_index.py` and `tools/fde_extents.py` for ELF sections and FDEs. It does not run the artifact or external programs. `evidence.json` preserves all selected body and caller-window bytes and hashes, while the tabular files present selected calls, conditional branches and instruction witnesses. Each output is deterministic and contains no timestamp or local pathname. Human inspection used GNU objdump 2.42; its text is neither a generator input nor a test oracle. The recorded run used CPython 3.12.3 on Linux x86-64.

## Evidence

All addresses below are linked ELF virtual addresses; `evidence.json` also gives zero-based file offsets. Ends and byte masks are exclusive. FDE extents are unwind-described ranges, not a census of all functions; each selected extent is checked against both the decoded `.eh_frame` and its `.eh_frame_hdr` entry.

| Role inferred from use | FDE start | End | FDE record | Body bytes |
| --- | --- | --- | --- | ---: |
| First-host adapter | `0x4484510` | `0x44845aa` | `0xed48e8` | 154 |
| Sibling adapter | `0x44850d0` | `0x448516a` | `0xed4914` | 154 |
| Sibling collector | `0x454d800` | `0x454d8a9` | `0x1259dd0` | 169 |
| First-host collector | `0x454dca0` | `0x454dd49` | `0x1259f04` | 169 |
| Per-record copy/normalization | `0x47dcfd0` | `0x47dd5a2` | `0xefe514` | 1490 |
| Vector clone | `0x4847b70` | `0x4847d0b` | `0xf0c95c` | 411 |

The first host calls the known insertion entry at `0x4d13b41`. It saves the result's first qword and uses `neg` followed by overflow at `0x4d13b7b`; only `0x8000000000000000` takes that overflow edge. On the other edge, it forms an iterator with a byte end computed from a count times `0x228` and calls `0x4484510` at `0x4d13c1b`. The sibling calls a different first-insertion entry at `0x4d163d1`, takes its matching overflow edge at `0x4d1640b`, and calls `0x44850d0` at `0x4d164ab`. The adapters call their respective collectors, and both collectors call the same pre-existing processor `0x444d7d0`; that processor is an external boundary to this packet.

On the adapter-success path the host rebuilds a prior record at stack `+0x1e0`; its first three words are the transformed vector header. The result of the adapter is tested against the same high-bit tag at `0x4d13c3e`. A tagged adapter result follows an early error-handling route; a non-tagged one is incorporated into the record. A first-insertion high-bit result bypasses the adapter and supplies the high-bit word to this later record. At `0x4d13f10`, a non-high-bit first word calls the vector clone at `0x4d13f9a`; the high-bit arm instead constructs an empty vector with words `0, 8, 0`. The clone writes a separate header at stack `+0x468`; the host later passes the prior-record address at `+0x1e0` to the merger. The sibling also calls that clone at `0x4d1682a`. Later, on the conditional second-insertion path, `0x4d14617` calls the insertion entry again, and `0x4d14654` passes the newly returned record and the prior record at stack `+0x1e0` to the known merger. These are observed static paths, not a claim that every edge is reachable for valid orders. The wider window from `0x4d13c20` through `0x4d13f9f` is retained to expose the intervening register and stack data flow.

### Adapter and collector branch table

The adapter initializes a stack byte to `0x27`, supplies its address to the collector, then compares the byte after return:

| Byte after collector | Observed adapter result | Additional action |
| --- | --- | --- |
| `0x27` | Copy the collector's three-qword vector header to the result | None in the adapter |
| Any other byte | Store `0x8000000000000000` at result `+0`; store the byte at `+8` | If returned capacity is nonzero, call the slot `0x576e010` with pointer and capacity times `0x228` |

A write of `0x27` is indistinguishable here from leaving the byte unchanged; no collision-free status convention is assumed.

The collector obtains its base pointer from input `+0`, its capacity from input `+0x10`, and calls the common processor with the same base as both initial bounds. After the processor returns, it constructs a header from that base, capacity and a calculated count. The count calculation shifts the returned-end-minus-base by 3 and multiplies modulo `2^64` by `0xf128cfc4a33f128d`, the modular inverse of 69. For non-wrapping byte spans divisible by `0x228`, this yields the record count; no quotient contract for malformed or unaligned spans is asserted. Both collector FDEs have LSDA pointers; their local unwind paths check capacity, call the same release slot for nonzero capacity with `capacity * 0x228` bytes, then call the unwind-resume PLT entry. Allocation ownership beyond these local operations remains an inference.

### Clone and record fields

The clone reads the source vector length at `+0x10` and its pointer at `+8`. It calculates `length * 0x228`, compares the unsigned length with `0x3b5cc0ed7303b5` (`floor((2^63 - 1) / 0x228)`), and sends larger values to the failure slot `0x576dfb8`. The nonzero-byte path calls slot `0x576dfd8`; a null return reaches the same failure slot. These slots have distinct RIP-relative call instructions and `R_X86_64_RELATIVE` relocation records in the generated evidence; their runtime binding and complete behavior are not established. The zero-byte path uses pointer value `8`, and the returned header is `capacity = length`, pointer, `length`. For the observed nonzero loop, each row is processed at stride `0x228`: the call at `0x4847c4e` processes fields within its first `0x1f0` bytes, and the caller copies fields in the remaining region before two indirect `0x228`-byte copies. This describes instructions and observed control flow, not a general allocation guarantee. The raw relocation records are:

| Call slot | ELF relative-relocation addend | Local use |
| --- | --- | --- |
| `0x576dfb8` | `0x1346068` | Over-limit and null-result failure edges |
| `0x576dfd8` | `0x54c06b0` | Nonzero-byte allocation-shaped call |
| `0x576e010` | `0x54c8cb0` | Capacity-guarded release-shaped calls |

Each record has relocation type 8 and symbol index 0 in the static ELF. The addend is not a claim about a resolved runtime pointer.

Within the first `0x1f0` bytes, the record helper has two structurally parallel regions at bases `0` and `0xf8`. For each base the following offsets are relative to that base:

| Input field | Tested operation | Output field on the indicated path |
| --- | --- | --- |
| `+0`, 32 bits | Compare to 1 | qword at `+0` is 1 iff equal, otherwise 0 |
| `+0x28`, 32 bits | Compare to 1 | qword at `+0x28` is 1 iff equal, otherwise 0 |
| `+0x60`, 64 bits | Compare to 2; if unequal test low bit | qword at `+0x60` is 2 when equal, otherwise 0 or 1 from the low bit |
| `+0x88`, 32 bits | Compare to 1 only on the `+0x60 != 2` paths | qword at `+0x88` is 1 iff equal, otherwise 0 on those paths |
| `+0xe4`, 8 bits | Compare to 1 | byte at `+0xe4` is 1 iff equal, otherwise 0 |

When `+0x60` equals 2, instructions bypass initialization of the local values used for some other output fields, including the qword at `+0x88`; their resulting bytes are not specified here. Inactive payload and padding bytes are not defined by the tag table. The two 32-bit comparisons do not compare the full surrounding qword. No semantic names are assigned to these fields without additional evidence.

### Matched code and raw witnesses

The adapters' 154-byte bodies become equal after masking only the four-byte direct-call displacement at body offsets `[0x3c, 0x40)` and the four-byte indirect-call displacement at `[0x8d, 0x91)`. The collectors' 169-byte bodies become equal after masking `[0x4b, 0x4f)`, `[0x9d, 0xa1)` and `[0xa5, 0xa9)`. Raw bodies, raw differences and normalized hashes are retained, and the destinations of the direct and selected indirect transfers are decoded separately. The following context windows also match after masking exactly the four-byte call displacement in each row; the pinned calls resolve their actual targets separately:

| First host window | Sibling start | Length | Half-open masked offsets | Calls after decoding |
| --- | --- | ---: | --- | --- |
| `0x4d13b21` | `0x4d163b1` | `0x60` | `[0x21, 0x25)` | Distinct first-insertion entries `0x4308460` / `0x430abf0` |
| `0x4d13bb2` | `0x4d16442` | `0x95` | `[0x6a, 0x6e)` | Distinct adapters `0x4484510` / `0x44850d0` |
| `0x4d13efd` | `0x4d1678d` | `0xa2` | `[0x9e, 0xa2)` | Both call `0x4847b70` |

These are comparisons of bounded windows, not equality of the callers or distinct callees. All raw window bytes and differing offsets remain in `evidence.json`. The collector unwind calls target the PLT entry at `0x5660110`; the loader's final target is not verified.

## Implementation and comparison

Independent Rust implementation: not yet implemented. There is no Cargo lock, build, compiler/linker configuration, target execution, fixture, or compiled-code comparison for this packet. The captured raw bytes and the two explicitly masked within-target comparisons are not evidence of Rust equivalence. The insertion and merge bodies, the common processor, allocator/failure targets, helper/data closure, runtime relocation resolution, vtable closure and whole-ELF correspondence remain unmeasured. The field names and allocation interpretation are inferred from their use, not established source types.

## Results and limitations

| Selected measure | Result |
| --- | ---: |
| Independently indexed and decoded FDEs | 6 |
| Pinned context windows | 11 |
| Direct call sites / conditional branches | 15 / 37 |
| Indirect call sites / corresponding unique relative relocations | 7 / 3 |
| Selected instruction witnesses | 32 |
| Masked within-target body pairs / host-window pairs | 2 / 3 |
| Focused unit tests | 13 passed; 0 skipped |

The tests reject a bad target digest, a changed selected body, a changed caller window, unsupported or truncated call and branch encodings, missing/duplicate/wrong-type relocation records, NOBITS and ambiguous/out-of-range mappings, and incomplete masks. They also check the allocation threshold and aligned length conversion at zero and boundary values. They exercise static extraction and arithmetic controls only; they do not execute or compare the target. No progress gate is requested, and no denominator for overall function coverage or equivalence is implied.

Next question: which valid callback outcomes change the adapter byte, and which book-state changes have already happened when that failure route is taken?
