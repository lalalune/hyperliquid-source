# RE-017: Hyperliquidity state-root input and point reader in node #94

This packet identifies app-hash job 19 as the serializer of the Hyperliquidity holder, allowing a reconstruction to connect its existing block-step updates to the holder's guard, range and point serialization, subject to the object-identity and timing limits below.

- Component ID: abci, RE-017; related evidence from RE-006 and RE-009.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not source for an implementation.
- Claim status: observations are bytes, the decoded selected relative transfers and literal data; role and type names are inferences. Loading-to-worker object identity, scheduling, full wire encoding and component completion remain unresolved.
- Scope included and excluded: 27 previously unowned #94 FDE extents across the two writer lanes and the nested point reader. Earlier loader, block, app-hash builder and range-reader functions are context only. No loader GOT or old caller is newly owned. This does not cover all ABCI begin/action/end paths, the entire app hash, node #115 or visor.

## Reproduce

From the repository root, with Python 3.12 or a compatible Python 3 and the pinned artifact available:

```sh
python3 tools/abci_hyperliquidity_root.py --out research/work-items/RE-017-hyperliquidity-root-94
python3 -m unittest tests.test_abci_hyperliquidity_root
(cd research/work-items/RE-017-hyperliquidity-root-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=0 TZ=UTC python3 tools/abci_hyperliquidity_root.py --out work/re017-root-a
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/abci_hyperliquidity_root.py --out work/re017-root-b
diff -r work/re017-root-a work/re017-root-b
```

Development used Linux x86-64, CPython 3.12.3, and GNU objdump 2.42 for human inspection only. The tool checks the entire input SHA-256 before opening an output file. It uses Python's standard library, `tools/elf_index.py` and `tools/fde_extents.py`, reads file-backed ELF sections, excludes SHT_NOBITS, and checks FDE extents and body hashes. It decodes explicitly selected `e8` and conditional relative branches, LEA literals, two RELATIVE entries and supported LSDA call-site tables directly from bytes. It invokes no external program and does not execute the binary. The tables are generated; this README and its manifest are manually maintained. The two comparison directories above must be empty before use.

## Evidence

Addresses are linked ELF virtual addresses unless a column says file offset; FDE ends are exclusive. The unwind-described extents do not establish a complete function census. `functions.tsv` gives the 27 selected extents, file offsets, FDE addresses and full-body hashes; `extents.tsv` retains all 19,619 bytes in those extents without masking. `calls.tsv` and `branches.tsv` contain curated instruction starts, not exhaustive call or branch scans. `edges.tsv` separately checks 25 selected path handoffs, including five **prior context** handoffs; `capture-rows.tsv` extracts three prior builder captures and matching stack and table placements as context. `field-order.tsv` pairs eight names with their selected load instructions and source offsets; `decisions.tsv` labels 26 taken branches with both destinations. `windows.tsv` is raw hex for selected supporting instruction windows; `literals.tsv`, `diagnostic-data.tsv` and `tables.tsv` contain the direct data. `lsda-headers.tsv` retains the first eight bytes at each selected LSDA address. `lsda.tsv` decodes only the omit/omit/ULEB call-site format; it leaves action indices opaque and marks the point reader's different header unsupported. No LSDA action semantics are assumed.

### Entry into the input serializer

The established app-hash builder packet assigns a 16-byte closure row to job 19 of 41. The low builder captures a pointer at state `+0x38d0` (`0x27566b2`, `0x27566c1`) and installs its box and table at row offsets `+0x130` and `+0x138` (`0x2756d5b` to `0x2756d78`). The linked table `0x56bdc98` contains qwords `(0, 8, 8, 0)` in the file; its call slot `0x56bdcb0` has an ELF RELATIVE relocation to `0x26bb320`. The shared table `0x5744948` and slot `0x5744960` have the same file qwords and point to `0x42c0580`. The secondary shared builder captures its base `+0x38d0`; the primary builder captures base `+0x4350`, a difference of `0xa80` (`0x4d7d033`, `0x4d7efe3`). These are links to prior builder work, not a new claim over those bodies.

Both thunks call prior job bodies. Their selected handoffs call the newly studied writers: `0x28190a0 -> 0x26cd7f0` and `0x4ae5570 -> 0x42d6490`. The low body's `0x2819085` stores `0x01000400` at writer `+8`, making the byte at writer `+0xb` equal to 1 at that handoff. The shared body has the same selected configuration. After the low writer returns, the prior body compares its first result word with `0x8000000000000004`; non-equality branches to the error path. On equality it reloads the writer buffer capacity, pointer and length. The established job-body study identifies the subsequent buffer-to-hash update and 32-byte finalization; two 16-byte stores place that digest in the job output (`0x281918a`, `0x281918e`). The post-writer windows are handoff context, not new ownership of the hash body or its slots. The job builder and Keccak/output chain remain the scope of `research/work-items/RE-009-app-hash-builder-94`.

A human-readable excerpt of the low writer, with addresses as above:

```text
26cd810: cmp    BYTE PTR [rdx+0xb],0x0
26cd81e: mov    edx,0x2
26cd86c: lea    rsi,[rip+...]     ; spot_to_range, 13 bytes
26cd886: lea    rsi,[r15+0x10]
26cd892: call   25ecf10
26cd8aa: lea    rsi,[rip+...]     ; ensure_order_bucket_guard, 25 bytes
26cd8cf: call   2227b70
```

The outer writer calls a two-entry map-header helper for nonzero mode and a two-entry sequence-header helper for zero mode. It emits field names at mode exactly 1. A header or name helper returning something other than 2 is copied into an error-shaped result; children return the qword `0x8000000000000004` on their selected success paths and any other result is propagated. These are observed discriminants, not recovered Rust enum definitions.

### Writer path and state layout

`edges.tsv` records both lanes. The entries below are the new functions unless explicitly marked as a prior boundary.

| Step | Low lane | Shared lane | Observed role |
| --- | --- | --- | --- |
| Holder writer | `0x26cd7f0` | `0x42d6490` | `spot_to_range` from holder `+0x10`; guard from holder base |
| Tree wrapper | `0x25ecf10` | `0x4603dd0` | collects entries then passes them to a sequence writer |
| Tree traversal | `0x2562a50`, prior boundary | `0x48758b0` | produces 16-byte pairs of key and value pointers |
| Pair sequence | `0x1e42b50` | `0x44315a0` | iterates pointer pairs at stride 16 |
| Pair | `0x1df1990` | `0x43d1820` | selects scalar key and optional range paths |
| Scalar key adapters | `0x1e0d400`, `0x1e0e050` | `0x43f42c0`, `0x43f4400` | pass the pointed-to qword through a scalar helper; may flush a writer prefix first |
| Range | `0x26ccf30`, `0x26cd130` | `0x42d6210`, `0x42d5eb0` | write `order_sz`, then `points` |
| Point sequence | `0x1e38a60`, `0x1e488f0` | `0x440d2f0`, `0x442a780` | iterate point elements at stride 24 |
| Point | `0x26ccd60`; `0x26cca10` is a prior boundary | `0x42d5990`, `0x42d5da0` | optional `o`, then `p` |
| Guard | `0x2227b70`, prior boundary | `0x470d220` | `last_bucket` from holder `+8`, then `bucket_millis` from `+0` |

The shared collector reads its input count at `+0x40`, computes `count * 16`, and tests both multiplication overflow and the byte-size ceiling `0x7ffffffffffffff8` before allocation. A zero count uses pointer value 8 and count 0. At `0x4875950` it forms pointers `node + 0x168 + 8*i` and `node + 0x20*i`; subsequent traversal uses parent, index, count and child fields. The order is the collector's traversed order. Sorting on arbitrary malformed tree states has not been established. Allocation failure and invalid iterator paths enter separate indirect calls; landing-pad rows are preserved in `lsda.tsv` without asserting the callees' effects.

The pair writer has a direct store of `0x92` for a two-entry sequence and `0xc0` when the value's first qword is `0x8000000000000000`; these are consistent with MessagePack array and nil markers. Otherwise it calls a range writer. The direct range writer passes the qword at range `+0x18` after `order_sz`, then passes the range base to the point-sequence writer after `points`. The buffered version writes the same field labels as immediates. Helper semantics beyond these selected calls and buffer paths are boundaries.

For the point writers, the tag is a qword at `+0`, the optional `o` value is at `+8`, and `p` is at `+0x10`. The header count is the low 32 bits of `tag + 1`; the optional branch tests **only the tag's low byte**. On successful helper paths, tag 0 requests one field and skips `o`; tag 1 requests two fields and writes `o` then `p`. For a nonzero writer mode the `o` name is included, while the `p` name is included only when mode is exactly 1. The separate mode bytes are at `+0xb` for the direct adapter and `+0x1b` for the buffered adapter. A synthetic tag 256 would request 257 fields while taking the no-`o` branch. We have not established that noncanonical tags or modes can arise from valid state, or that all nested writer modes equal the outer mode.

### Reader handoff and failure branches

The snapshot range reader previously stops at its nested points boundary. At the prior handoff `0x18df5cb`, a direct call reaches `0x24dc4a0`; that new reader calls the new point reader `0x17234e0` at `0x24dc547`. In the selected sequence path it loads a 32-bit count, reserves `min(count, 0xaaaa)` slots of 24 bytes, checks allocation, and calls the point reader in a loop. A return byte other than 9 goes to the result-copy and conditional cleanup path; a word equal to 2 ends the loop; a full vector can call the growth slot. Thus `0xaaaa` is an **initial reservation cap**, not a demonstrated maximum accepted point count.

The point reader has several parsing paths. On the selected named-field path the one-byte key classifier maps `o` to selector 0, `p` to 1, and other lengths or bytes to 2. It calls an optional-field helper for `o` and a scalar helper for `p`. If `o` is absent its local sentinel 2 becomes 0; if `p` remains absent it calls a diagnostic helper using the `missing field` data and key `p`. A repeated `o` or `p` selects `duplicate field` data with the corresponding key and calls the same diagnostic helper. The helper can itself return different tags, including 9, so the observable branch is a diagnostic call rather than a proof that every such input is rejected. Other keys go to an unanalysed helper. The remaining reader formats and error helpers have not been fully resolved.

### Connection to prior state transitions

The established `RE-006-system-buy-order-94` block driver uses the same relative holder offset: `0x26fef73` passes state `+0x38d0`, and the flag-zero branch divides the clamped time by the first qword, updating state `+0x38d8` only if the quotient is larger (`0x26ff063` to `0x26ff076`). The established `RE-006-hyperliquidity-refresh-94` documents the flag-one refresh call and successful updates of a 24-byte point's tag and order id. Together with the new writer layout, this supports the inference that these guard and point changes can affect job 19's input **if** the transition and hash builder see the same holder after those changes. Neither object identity from the state loader nor actual ordering and intervening mutation have been established here.

## Implementation and comparison

Independent Rust implementation: not yet implemented. A full wire fixture, app-hash recomputation, execution against the target, normalized code comparison, call-target closure, data closure and whole-ELF equivalence are not yet implemented/measured. The unit tests exercise the static decoder, exact generated bytes, corruption checks and synthetic predicate cases; they are not target execution. They include all 256 one-byte classifier inputs, invalid key lengths, tag and mode boundaries, the reserve boundary, invalid branch targets, NOBITS and unmapped addresses, altered FDE/ELF bytes and unwind records, missing/duplicated/changed relocations, changed capture and row placements, field references, each labelled branch and checked call opcode and displacement, and malformed LSDA records.

## Results and limitations

`summary.json` records 27 selected FDEs containing 19,619 bytes, 294 selected conditional branches, 124 selected direct calls, 25 checked path edges, 42 byte windows, 8 field literals, 8 field-to-offset bindings, 26 labelled decisions, 4 diagnostic-data pins, 9 predicate pins, 2 table relocations, 3 prior builder-capture rows, 13 LSDA headers and 75 LSDA rows (including one unsupported-header marker). These denominators describe this selection only; they are not coverage of all functions or all failure paths. Selected tests are static controls. No runtime acceptance, canonical serialization of arbitrary inputs, serialized-byte digest or end-to-end loader-to-app-hash identity is claimed. The prior loader function, its GOT, the old range and guard readers, allocation/growth helpers and Keccak internals remain boundaries. No progress gate is requested; the abci component remains 0/4.

Next question: trace the parsed loader result through its ownership moves to the exact holder read by the block driver and job-19 builder, then validate the ordering of block updates and hash serialization without assuming object identity.
