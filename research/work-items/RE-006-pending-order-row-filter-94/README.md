# RE-006: pending order-row filtering after a second insertion

This packet establishes that the pending-row step after a second insertion overwrites the matched order record's size bits or removes its row according to the first result and status byte, then stably compacts the vector and preserves the unprocessed suffix if a row destructor unwinds.

- Component ID: `orderbook`, RE-006 book transitions and insertion bookkeeping.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: independent repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference provides search leads only; no code is copied.
- Claim status: raw bytes, FDE and call-site records, relocation relationships, instruction operands, branch destinations and jump-table entries are static observations. Order-ID, status and size names use the prior book and order-status evidence and are inferences. Synthetic scenarios are consequences of the stated reading, not observations from target execution.
- Scope included and excluded: three newly examined FDEs: the complete filter, the removed-row destructor dispatch and the order-record destructor reached for the normal row variants. Two already documented insertion hosts and their adapter are bounded call-site context, not selected functions. Prior merge, slot writer, fill and later row-rewrite bodies; other destructor arms; allocator internals; and whole-transaction behavior are excluded.

## Reproduce

From the repository root on Linux x86-64, with Python 3.12.3 or compatible Python 3 and the authenticated artifact installed:

```sh
python3 tools/artifacts.py verify
python3 tools/order_row_filter94.py --out research/work-items/RE-006-pending-order-row-filter-94
python3 -m unittest tests.test_order_row_filter94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-pending-order-row-filter-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=0 TZ=UTC python3 tools/order_row_filter94.py --out work/order-row-filter-a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/order_row_filter94.py --out work/order-row-filter-b
diff -r work/order-row-filter-a work/order-row-filter-b
diff -r -x README.md -x MANIFEST.sha256 work/order-row-filter-a research/work-items/RE-006-pending-order-row-filter-94
```

The collector first checks the whole target SHA-256, then reads file-backed ELF sections and indexed FDEs with `tools/elf_index.py` and `tools/fde_extents.py`. It rejects NOBITS mappings, ambiguous ranges, unexpected instruction encodings, changed body hashes, branch targets and relocation relationships. It uses Python's standard library and launches no external program. GNU objdump 2.42 supplied human inspection of instruction starts; its output is not parsed or included in generated evidence. No node or visor executable is run. The output and hashes do not depend on the working directory's absolute name, hash seed or time zone.

## Evidence

All addresses are linked ELF virtual addresses; ranges are half-open. File offsets are read from the ELF section table and are included in `functions.json`. FDEs are unwind-described ranges, not proof of original source function boundaries. The three selected extents total 1,441 bytes:

| Role | FDE extent | Bytes | LSDA |
| --- | --- | ---: | --- |
| Pending-row filter | `0x3bc29a0..0x3bc2bba` | 538 | `0xae2a74` |
| Removed-row destructor dispatch | `0x3bba5a0..0x3bba7fe` | 606 | none |
| Order-record recursive destructor | `0x3bbc9d0..0x3bbcaf9` | 297 | `0xae2298` |

`functions.json` keeps every byte and its SHA-256 for each extent. `windows.tsv` retains fourteen readable-sized raw byte ranges; `branches.tsv` gives 39 selected branch opcodes and decoded destinations, and `calls.tsv` gives 15 selected direct and indirect transfers. These counts are selected evidence, not an instruction or whole-component coverage denominator. `operands.tsv` and `layout.tsv` derive the field offsets below from checked instruction bytes. No operand is normalized.

### Binding the filter to the insertion path

The existing two-insert packet records the host paths, their merge and the class gate. At `0x4d1475d` and `0x4d16fed`, the hosts make the same RIP-relative call through slot `0x57747b8`. Immediately before the call they pass a row-vector address, a saved qword, a flag derived from comparing the first result with `0x8000000000000000`, and a value in `xmm0`. `relocations.tsv` retains the raw ELF relative relocation and checks that its addend names the indexed FDE containing direct call site `0x3b7bd56`. That direct call reaches the selected filter. The adapter and both hosts are contextual boundaries, not selected or reanalysed FDEs. This establishes the static connection, subject to runtime relocation and patching; no runtime reachability claim follows.

At filter entry, the vector's pointer is at `+0x08`, its length at `+0x10`, and row stride is `0x268`. Its second argument holds pointers to a qword key, a flag byte and eight replacement bytes. A zero length returns immediately. An external input pointer aliasing the vector or a row is outside the model. Prior `RE-006-order-status-output-94` identifies the outer tag-3 rows as order-status rows and the record's `+0x68` field as size. Prior insertion evidence identifies the saved qword as an order ID on the studied route. Those names are inferences; the offsets and loads are direct observations.

### Row selection, writes and removal

The outer tag comparison reads **32 bits** and requires 3. For an outer tag whose full qword is 3, the next qword chooses these layouts:

| Inner word at `+0x08` | Record start | Compared key | Written eight bytes | Status byte |
| --- | ---: | ---: | ---: | ---: |
| 2 | `+0x38` | `+0xa8` | `+0xc0` | `+0x100` |
| 0, 1, 3 | `+0x30` | `+0xa0` | `+0xb8` | `+0x119` |
| 4 | not read | not read | unchanged | not read |

The machine's default arm also uses the second layout for inner words above 4. Validity and meaning of those values are unresolved. For either selected layout, a key mismatch leaves the row unchanged. On a key match:

| Input flag byte | Status byte | Result |
| --- | --- | --- |
| zero | any | Keep the row and overwrite the eight-byte field. |
| nonzero | zero | Call the row destructor and remove the row. |
| nonzero | nonzero | Keep the row and overwrite the eight-byte field. |

Prior `RE-006-order-status-output-94` identifies status byte 0 as `open`, and the two-insert evidence identifies the second result word at `+0x30` as an order ID. Taken together, these support the inference that a successful first result suppresses a matching second-order `open` row on this route while retaining nonzero-status rows. This packet does not independently establish the status-name table or every source of the key.

The tests include status bytes 0, 1, 2 and 255, and flag bytes 0, 1, 2 and 255; this is a byte-zero test, not equality with one or a low-bit test. The payload is copied with `movsd`, without arithmetic in this filter. Its exact bit pattern is preserved, including signed zero and NaN payloads. Previous `RE-006-queued-row-rewrite-94` studies a different, later rewrite driver that can replace an order record and remove a different status case. This packet establishes the preceding filter's separate assignment/removal rule and does not claim the other driver's functions.

Before the first removal, kept rows stay in place and matching writes happen in place. After a removal, the helper uses separate read and write cursors, calls through the ELF `memcpy` relocation for each retained `0x268`-byte row, and advances the write cursor only for a retained row. The source and destination ranges are disjoint for a well-formed vector because at least one full row separates them. It writes the new length after the scan; if no row is removed, it does not write the length. Order is stable. It does not clear the trailing bytes or reduce capacity, and no statement is made about stale rows after the new length.

The first test uses a dword tag while the destructor dispatch reads the full tag qword. The row-layout and resource-release claims therefore assume the full tag is 3, rather than generalizing from a synthetic value with high tag bits set.

### Removed-row cleanup and unwind

The row destructor maps its full qword tag through the eight-entry relative table at `0x5b6adc`, retained in `drop-table.tsv`. For a full tag of 3, inner word 2 reaches the selected record destructor with row `+0x38`; inner words 0, 1 and 3 reach it with row `+0x30`. Inner word 4 is not removed by this filter. The destructor's other tag arms are present in raw bytes and the table but are outside this packet's semantic scope.

The selected record destructor conditionally invokes the relocation-backed cleanup slot for nonzero size words at record `+0x00`, `+0x18` and `+0x48`, paired with pointers at `+0x08`, `+0x20` and `+0x50`. It traverses children at pointer `+0x38` with length `+0x40`, recursively calls itself on each `0xa8`-byte child in ascending order, and, when capacity `+0x30` is nonzero, calls the same cleanup slot with `capacity * 0xa8` bytes. The cleanup slot's target is recorded as an ELF relative relocation; deallocation is an inference from the argument shape and prior use, not a separately validated allocator contract. The traversal description assumes well-formed, non-aliased, finite records and representable sizes.

The two selected LSDAs have seven call-site records in `unwind.tsv`. The first destructor call is covered by the entry landing at `0x3bc2b7b`; the later destructor call is covered by the entry landing at `0x3bc2b73`. The latter increments the read index before the paths join. In either case the joined code moves the unprocessed suffix down using the ELF `memmove` relocation, writes length `kept_prefix + unprocessed_suffix`, and calls the unwind resume target. Rows before the failing destructor may already have been overwritten, dropped or moved; the failing row is excluded from the suffix. This is not a rollback claim, and the effects or completion of a throwing destructor are not established. The record destructor's recursive unwind entry is also retained, but action/type-table semantics and allocator behavior remain outside scope.

### Synthetic controls

`synthetic-cases.tsv` enumerates 126 combinations of inner word, key equality, flag and status. Inner words beyond the normal 0 through 4 are deliberately synthetic; the table shows instruction-level predicates, not validity of such a row. `synthetic-scenarios.tsv` covers empty vectors, no removal, first/middle/last and repeated removals, as well as injected first and later drop failures. Retained markers and SHA-256 values describe synthetic byte arrays only. `project_with_drop_failure` models the observed landing-pad data movement; it does not execute an exception or the target.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo lock, compiler/linker flags, source build, two-build comparison, target-executed fixture, normalized Rust-to-target comparison or whole-ELF match is claimed. The raw selected body bytes are retained without masks. The projections use independently authored Python, supplied row bytes and assumptions stated above; they are not a target differential test. Helper bodies beyond the selected destructor, runtime GOT resolution, arbitrary malformed layouts, recursive cleanup failure and complete relocation/vtable closure remain unmeasured.

The focused suite contains 14 tests with no skips. It checks the complete target digest and selected FDEs, altered body bytes, all 39 listed branch opcodes and displacements, all 15 listed transfer opcodes and displacements, duplicate/missing/partial relocations, invalid and NOBITS mappings, the two relevant LSDA landing pads, bit-preserving writes, key/tag/flag/status controls, repeated deletion order, and synthetic exception-tail preservation. The generated evidence was reproduced twice under different hash seeds and time zones with a Python-only executable path.

## Results and limitations

The packet retains three FDEs, 1,441 original code bytes, 13 operand encodings, two derived layout rows, 39 selected branches, 15 transfers, four relocation records, eight jump-table entries, seven LSDA call-site entries, 126 synthetic single-row cases and eight synthetic vector scenarios. No progress gate is requested. The observations do not establish complete insertion, cancellation or matching, transaction rollback, actual panic behavior, target ABI equivalence, concurrent behavior, or exact reconstruction.

Next question: determine how the second insertion's selected ID and replacement size are produced on every reachable host branch, including aliases and failures, before integrating this row filter with an independent Rust book transition.
