# RE-009: recover the node #94 OracleSnapshot pxs2 serialization path

This packet establishes that the examined ordinary `OracleSnapshot` serialization route writes its price vector as a sequence of three-entry rows, with compact `p`/`d` integer fields and a conditionally emitted `u` field, enabling a reconstruction to preserve row arity, field aliases, and the reader's failure routes.

- **Component ID:** RE-009, storage and state roots.
- **Target release and full SHA-256:** Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- **Source commit / reference commit:** repository `e5c9b6436876b2a4a39daef813171f9879317699`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as an unlicensed search lead, not copied.
- **Claim status:** static observations and bounded control-flow inference; full storage integration, type ownership and equivalence are unresolved.
- **Scope included and excluded:** the one-field snapshot wrapper, the `pxs2` vector, its fixed triple, entry map and selected integer/time writer helpers. Database keys, snapshot file selection, hashing, other fields, other serializer modes, and target execution are excluded.

## Reproduce

Run from the repository root with the pinned artifact materialized. The generator uses Python standard library and the repository's `elf_index.py` and `fde_extents.py`; it checks the input digest before parsing. The inspection environment was Linux x86-64, Python 3.12.3 and GNU objdump 2.42. Objdump is used only for the human-readable excerpt below; neither the generator nor tests invoke it or any other external program. No node binary is executed.

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_oracle_pxs2_94
A=$(mktemp -d)
B=$(mktemp -d)
PYTHONHASHSEED=1 TZ=UTC python3 tools/oracle_pxs2_94.py --out "$A"
PYTHONHASHSEED=999 TZ=Pacific/Honolulu python3 tools/oracle_pxs2_94.py --out "$B"
diff -ru "$A" "$B"
for f in "$A"/*; do cmp "$f" "research/work-items/RE-009-oracle-pxs2-94/${f##*/}"; done
(cd research/work-items/RE-009-oracle-pxs2-94 && sha256sum -c MANIFEST.sha256)
```

The retained `evidence.json` contains the input SHA-256, all selected FDE ranges, file offsets, body hashes, relative jump tables and selected relocation records. `calls.tsv`, `branches.tsv` and `windows.tsv` retain rel32 edges, conditional targets and raw instruction windows. Case tables are synthetic models of the indicated instruction paths, not node executions. The existing `foundation-byte-range-select-94` packet establishes the behavior of the external header marker selector; this packet uses that dependency without reanalyzing its function.

## Evidence

All addresses are linked ELF virtual addresses, not runtime-rebased addresses. File offsets are zero-based and independently resolved through file-backed ELF sections; `SHT_NOBITS` sections supply no bytes. Each range is taken from a decoded FDE, whose unwind extent is not by itself proof of a complete function boundary or complete CFG. The machine-readable files give exact exclusive endpoints and byte hashes. The following is a selected path, not a census of callers or serializer modes.

### Path and ownership

| Role | FDE start | Selected linkage |
| --- | --- | --- |
| One-field snapshot writer | `0x325f530` | Emits `pxs2`, calls the vector writer at `0x325f5b8`. |
| Snapshot reader | `0x2d39c90` | Map and sequence paths call the vector reader at `0x2d3a6fc` and `0x2d3a8cb`. |
| Vector writer / reader | `0x322fbd0` / `0x2d8dc60` | Writer advances by `0x60`; the reader delegates collection to `0x341a1a0`. |
| Triple writer / reader | `0x323c730` / `0x2aa4970` | Three calls to the entry writer / reader. |
| Entry writer / reader | `0x32608a0` / `0x2e33e50` | Emit or classify `u`, `p`, `d`; invoke value helpers. |
| Date / clock formatter | `0x151f240` / `0x15204a0` | Selected relocation addends of the `u` string writer. |
| Time text reader | `0x2a8d630` / `0x2a93110` / `0x3a0d6f0` | Nested reader, input dispatch, and text parsing gate on one selected route. |

The reader's sequence-length diagnostic uses the relocated descriptor at `0x56d8498`, whose data bytes and `R_X86_64_RELATIVE` addend identify the literal `struct OracleSnapshot with 1 element` at `0x578892`. The same reader matches `pxs2` and calls the shared vector reader. Separately, the vector writer passes the literal `OracleKindMap` at `0x59b552` to its triple writer. This ties the selected snapshot path to a binary type label; it does not prove its enclosing file name or database key.

For a human-readable check, the following is an abbreviated objdump rendering of bytes retained in `windows.tsv`:

```text
323c7ed: c6 04 30 93       mov BYTE PTR [rax+rsi],0x93
323c80b: e8 90 40 02 00    call 32608a0
323c816: 49 8d 77 20       lea rsi,[r15+0x20]
323c820: e8 7b 40 02 00    call 32608a0
323c82b: 49 83 c7 40       add r15,0x40
323c838: e8 63 40 02 00    call 32608a0
```

On the branch reaching this window, `0x93` is the fixed-array marker and the entry offsets are `0`, `0x20`, `0x40`. The vector writer computes and advances a `0x60`-byte stride. The ordinary named snapshot wrapper emits a one-field map and the positional wrapper a one-element array. Its vector can contain any number of these triples subject to the serializer's separate length and allocation conditions; `0x2aaa` in the reader is a cap on **initial allocation**, not an asserted maximum vector length.

### Entry fields and value encoding

The entry writer reads `p` at offset `0`, `d` at `8`, and a three-word representation for `u` at offsets `0x10`, `0x14`, and `0x18`. On the successful named-field route it emits `u` first when selected, then `p`, then `d`. The `p` and `d` calls both reach `0x359af90`: values below `128` are a single positive fixint byte; higher values use `cc`, `cd`, `ce`, or `cf` followed by 1, 2, 4, or 8 big-endian bytes. `unsigned-cases.tsv` contains boundary models. For example, the modeled compact named entry with `p=127`, `d=128` is `82a1707fa164cc80`; `compact-entry-cases.tsv` contains five such writer models, with no claim that synthetic values are valid chain state.

The `u` omission condition is more precise than a blanket claim that its three words are zero. The first indirect call at `0x32608bc` and the second at `0x3260933` use the same relocation slot, each with argument `0xaf93b`. A zero return takes a separate terminal indirect-call path; that callee is not analyzed here. The first nonzero return is compared with the first word while the other two words are checked for zero, choosing a field count of two or three. After the header, the second return is compared again to choose whether `u` is emitted. The model records the two returns independently: the equality of calls and the helper's full semantics are not assumed. Six abstract cases are in `entry-default-cases.tsv`; the cases with different helper returns describe branches, not a claim that those returns occur in the node.

When `u` is emitted, its nested writer at `0x31ebc50` calls a formatting helper for the first part, passes the byte `T` to a virtual formatter, calls a second formatting helper, and passes the resulting buffer to a string writer. A nonzero formatting result reaches the failure path containing `ud2`; a string-writer failure is propagated. The date and clock formatter addends are `0x151f240` and `0x15204a0`. On the bounded ordinary route, the former extracts the signed year by shifting its input word, indexes a 733-byte table using bits from that word, and writes two dash separators. The latter emits two colon separators, derives hour/minute/second, and branches on the subsecond word. Its two multiplication-and-rotation tests select descriptors with width values 3 or 6; the remaining nonzero case selects width 9. Values at or above one billion first subtract one billion and increment the displayed seconds. The table, instruction windows and descriptor bytes are retained. Interpreting those descriptors as zero-padded decimal widths is an inference about the called formatter; `time-model-cases.tsv` consequently records **modeled**, not observed, text. For example, a synthetic input follows the ordinary branches to `2024-02-29T12:34:56.123456`; another takes the incremented-second branch to `2024-12-31T23:59:60`.

On one reader route, `0x3c0c6a0` calls `0x2a8d630`, which calls `0x2a93110`; a bounded text-input path checks available length, invokes an input-checking helper, and calls `0x3a0d6f0`. That reader calls `0x1514b50`, then inspects two returned words: a zero first word or a nonzero second word takes error conversion, while a nonzero first word and zero second word reaches an indirect finalizer. A non-success finalizer result also reaches error conversion. `time-parse-route-cases.tsv` records all four abstract zero/nonzero combinations without assigning meanings to the words or claiming all combinations are reachable. The text grammar and other input-dispatch branches are not closed.

The time model covers nonnegative years below 10000, a table index below 733, seconds within a day, and a subsecond word below two billion. It does not validate whether arbitrary packed words are legitimate calendar values, and it excludes extended years, alternate formatting routes and full parser closure. The timezone and all runtime helper contracts remain unresolved. Selected dynamic relocation records are retained in `evidence.json`, including the two formatter slots and the entry's default-value slot; their presence does not prove runtime relocation or execution.

### Reader branches and negative controls

| Route | Observed control flow | Qualification |
| --- | --- | --- |
| Snapshot map `pxs2` | A set seen slot branches to the duplicate-field diagnostic; otherwise the vector reader is called. Missing `pxs2` reaches the missing-field diagnostic helper. | Unknown keys are delegated to a separate helper; its whole contract is not assumed. |
| Snapshot sequence | Length zero reaches the one-element diagnostic; after a successful child, length one takes the exact-length branch and extra elements take the excess branch. | Other input and child errors may exit earlier. |
| Triple fixarray | Lengths zero, one, and two reach the corresponding missing-element paths; length three takes the exact branch; greater lengths take the excess branch. | This table assumes each earlier child returned a successful, present result. |
| Entry map | `u` and `last_update_time` select tag 0; `p` and `px` tag 1; `d` and `daily_px` tag 2; everything else tag 3. | For tags 0–2, a nonzero seen slot selects the duplicate diagnostic; tag 3 calls the unknown-field helper. The raw value-to-slot representation remains unresolved. |
| Entry map finish | An absent `u` slot calls a default initializer; absent `p` and `d` slots reach their respective missing-field helpers, in that order. | The diagnostic helper can return a result; do not infer its complete error policy from the call alone. |
| Entry sequence | A nonempty sequence first goes through the time-value decoder, then the two price-value decoders; explicit missing and excess branches follow. | Child failures and alternate input-marker routes can exit before these checks. |

The tag table at `0x54e5e8` is read as signed little-endian offsets relative to its own VA. The length-dispatch table at `0x581ec4` and comparison immediates independently ground the aliases. `classifier-cases.tsv` includes every accepted alias, an empty key, a non-ASCII key and one-bit mutations of every alias byte; these are classifier **models**, not executed parser fixtures. `field-route-cases.tsv` covers the abstract seen-slot branches. The direct-call checks, branch opcode/target checks, corrupted digest, corrupted code byte, corrupted relocation, wrong call/branch opcode, out-of-range address and `.bss` controls are covered by the focused tests.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build scope, Cargo lockfile, compiler/linker flags, two-build result, target execution, byte-for-byte binary comparison and normalization masks: **not yet measured**. Helper and relocation closure are partial; in particular, the time parser, general formatting contracts, other serializer modes and allocation failure behavior remain outside the selected paths. No target-produced fixture or chain data was used.

## Results and limitations

The generator retains 20 selected FDE extents, 42 direct-call sites, 40 conditional branches, 55 byte windows, nine indirect-call observations, two relative jump tables and one relocated snapshot diagnostic descriptor. It emits 44 classifier cases, 16 triple-length cases, 11 unsigned boundary cases, five compact-entry examples, eight seen-slot cases, six default-decision cases, six bounded time models and four parser-gate cases. These are counts for this bounded packet only; they are not denominators for the node or evidence of runtime coverage. Twenty-five focused unit tests pass with no skips, including a comparison of the clock division reciprocals against integer division for every second in the bounded day. No milestone or full-scope progress gate is requested.

The next question is to close the remaining timestamp parser, formatter contracts and default initializer against the target, then validate snapshot round trips with separately authorized target-produced fixtures; neither storage-root ownership nor full MessagePack compatibility is established here.
