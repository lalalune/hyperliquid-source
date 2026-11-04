# RE-017: carry a keyed block result into a state-root input

On selected node #115 paths, the state materializer shared with the Location-bearing loader feeds a compact task that updates a 20-byte-keyed record under distinct normal and penalty conditions; the root visitor then pairs that record's key and updated word with child descriptors.

- Component ID: `abci`; RE-017, connected to the RE-009 state-root question.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical state-link record `b0493b6e5f232e582daba48c6e29aaba53b6b867`. The reference's unlicensed source text was used only as a navigation lead and is not copied.
- Claim status: selected machine-code, descriptor and unwind observations; conditional dataflow and arithmetic interpretations; runtime identity and complete root semantics unresolved.
- Scope included and excluded: a materializer-return future, its contextual pointer handoff into a compact task, the compact-state item loop, its selected Location-bearing result handler, keyed probe/insertion, selected downstream result handling, and the corresponding root-map and value visitors. The already studied loader, engine, group visitor and scalar callback are boundary context, not newly owned FDEs or a complete component map.

## Reproduce

From the repository root with the authenticated node #115 artifact and the shared ELF/FDE readers present:

```sh
python3 tools/abci_keyed_result115.py --out research/work-items/RE-017-abci-keyed-result-115
python3 -m unittest tests.test_abci_keyed_result115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For independent regeneration, set `TMPDIR` to a writable temporary directory and use fresh subdirectories:

```sh
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_keyed_result115.py --out "$TMPDIR/re017-keyed-a"
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_keyed_result115.py --out "$TMPDIR/re017-keyed-b"
diff -r "$TMPDIR/re017-keyed-a" "$TMPDIR/re017-keyed-b"
diff -r -x README.md -x MANIFEST.sha256 "$TMPDIR/re017-keyed-a" research/work-items/RE-017-abci-keyed-result-115
(cd research/work-items/RE-017-abci-keyed-result-115 && sha256sum -c MANIFEST.sha256)
```

The optional historical comparison authenticates the retired capture separately and prints its release-specific anchors without changing generated files:

```sh
python3 tools/abci_keyed_result115.py --out "$TMPDIR/re017-old-check" --old-elf references/can1357-hl/bin/hl-node-mainnet-new
```

The collector checks the complete target digest before producing output. It uses Python's standard library and `tools/elf_index.py` and `tools/fde_extents.py`, excludes `SHT_NOBITS` from file mappings, and derives the emitted offsets, instruction bytes, relative transfers, relocation addends and call-site rows from ELF bytes. Selected instruction starts are fixed byte-pattern inputs, not a general x86 decoder. It and its tests invoke no external program and never run either captured executable. Analysis used Python 3.12.3 on Linux x86-64; GNU objdump 2.42 was used only for human inspection. No network, chain, keys or captured runtime state is used by reproduction.

## Evidence

Addresses below are linked ELF virtual addresses before rebasing; the generated tables also contain file offsets. `functions.tsv` reconciles each selected `.eh_frame` FDE with `.eh_frame_hdr` and preserves its complete described bytes and hash. FDE extents do not establish source-function boundaries, all callers, or complete control flow. `windows.tsv` separates contextual windows from the selected functions. `branches.tsv`, `calls.tsv`, `operands.tsv`, `references.tsv`, `descriptors.tsv`, `boundaries.tsv`, `locations.tsv`, `joins.tsv`, `unwind.tsv`, and `unwind-witnesses.tsv` contain raw bytes or relocation/LSDA coordinates. The decoded LSDA action numbers are retained without interpreting the action table. This is a bounded, completed static analysis of the selected path; it is not a whole-node scan.

### Materializer-result handoff

The existing `state.rs:123:37` caller `0x3c13520` and selected future `0x2adce40` call the same materializer slot `0x64e73a0`; its `R_X86_64_RELATIVE` relocation resolves to `0x3c13610`. The prior caller, its call site and the slot remain context, not new ownership. These are separate calls: sharing a callee does not establish that the Location caller executed on the future route or returned the same allocation.

| Selected stage | Byte-backed handoff |
| --- | --- |
| Materializer future `0x2adce40` | At `0x2add95b` the future calls the shared boundary and stores its returned pointer in future `+0x90`. On the pinned result arm, it reloads that slot, constructs sentinel `0x8000000000000001`, and returns the saved pointer in output `+0x8`. Other future arms and intervening callbacks remain outside this join. |
| Wrapper `0x2af45f0`, contextual | Its call at `0x2af4797` reaches the selected future. When the future's first word is the selected sentinel, the observed classifier takes the arm that reads the second output word and later stores it in wrapper output `+0x380`. The wrapper's first `0x308`-byte output copy does not itself include that pointer. |
| Parent `0x2b41b70`, contextual | After the wrapper's completed return and the `0x3b8`-byte copy, it loads the qword at the copy's `+0x380`, saves it at parent `+0x3a0`, and copies `0x350` bytes starting at parent `+0x80` into the task-constructor input. Thus the qword occupies input `+0x320`, within the copy. The direct call at `0x2b4261c` reaches the previously studied task constructor `0x2b3aba0`. |

The previously recorded constructor and compact-engine context carry that input slot toward the item loop and root capture under the stated scheduler and copy assumptions. The joins are conditional on the selected future-result and completed-return arms, ordinary slot bindings, normal helper returns and no intervening alias writes or replacement of the pointer. They do not prove runtime reachability or identity with the distinct pointer returned by the prior Location caller.

### Entry, result, and map

| Stage | Selected observation |
| --- | --- |
| Prior engine context | Existing PR #2181 identifies compact engine `0x2d23610`, its call to `0x22ed710`, and the later end selector. At `0x22ed7e5`, the latter calls the newly selected loop `0x2706500`. Its context carries the state-pointer slot from the prior caller; the call site and earlier FDE are contextual, not claimed as new. |
| Item loop `0x2706500` | Each selected item advances by `0x20` bytes. A slot call produces a gate byte. When it is nonzero, the loop calls `0x2c766e0` once; a returned 16-bit tag other than `0x1a2` clears the gate before the subsequent record pass. The loop passes the state-pointer slot to `0x231b9c0`, and handles zero or one returned row without sorting, rows 2 through 20 through one sorting boundary, and 21 or more through a different slot boundary. |
| Record pass `0x231b9c0` -> `0x2705280` | The allocator forwards the captured state-pointer slot into a loop over `0x90`-byte records. A nonzero gate reaches `0x22ec9b0`; a zero gate takes a separate path that constructs status `0xc6`. On the selected normal path, the loop projects a `0x48`-byte row and returns the three-word result through the allocator. The named status meanings and generic conversion helpers remain unresolved. |
| Tag and admission `0x22ec9b0` | The handler first compares a 16-bit input tag with `0x1a2`. Other tags take a payload-copy path ending in output tag `0x0f`. For tag `0x1a2`, it checks a 20-byte key against the zero, one and multiple-entry cases rooted at state `+0x970/+0x978/+0x980`. The one-entry comparison combines 16 bytes and a further 4 bytes; the multi-entry path uses `0x2b6e540` and `0x26fe6d0`. A separate 20-byte tree search and a state `+0xd88` lookup are fallback boundaries. If the latter returns zero after the preceding misses, output is tag `0x0f`, code `0x36`. |
| Dispatch `0x2c766e0` | Before its two slot-call boundaries it increments state `+0xb40` with unsigned saturation. If the returned 16-bit tag is `0x1a2`, it also saturating-increments `+0xb48`; otherwise it copies the returned `0x70`-byte payload. This helper is called both in the initial gate path and in the selected handler path, so the evidence does not collapse those invocations into one. |
| Map `0x26fe6d0` and `0x26f6bd0` | The probe uses 16-byte control groups, checks the candidate index against the row count, and compares all 20 key bytes at row `+0x48`. The insertion path uses `0x60`-byte rows, returns row `+0x8`, and can call growth or failure boundaries. The handler's map address is state `+0x968`; its subsequent store is at returned value `+0x8`, that is, row `+0x10`. |

The hash helper initializes four observed constants, supplies exactly 20 input bytes to `0x2b41610`, and performs selected rotate/add/xor rounds. A SipHash-family interpretation is plausible from the constants and rounds; exact algorithm identity, all helper behavior and a captured hash fixture are not established here.

### Ordered selected decisions and writes

The table describes only the pinned branch paths and assumes each reached helper returns normally unless a different result is stated. `amount` and `amount2` are separate returns from the same slot boundary; no equality is assumed.

| Condition | Selected effect |
| --- | --- |
| Input tag differs from `0x1a2` | Copy the selected input payload into an output with first byte `0x0f`; this arm of the handler does not perform the `+0x968` update. An earlier loop invocation may already have changed its counters. |
| Admitted key; dispatcher result differs from `0x1a2` | The dispatcher has already incremented `+0xb40`; the handler copies the returned payload to an output tagged `0x0f`. |
| Dispatcher result `0x1a2`; config dword at `+0` is 1 and its qword at `+8` is below the selected clock-derived value | Obtain `amount`, saturate unsigned `5 * amount`, find or insert the key, saturating-add the result to value `+0x8`, copy state bytes `+0x60..+0x6b` to value `+0x30..+0x3b`, and return tag `0x0f`, code `0xd0`. |
| No prior exit | Obtain `amount`, find or insert the key, saturating-add it to value `+0x8`, copy the same 12 state bytes to the value, and call `0x2c69220`. This update precedes the nested call and is not evidence of rollback if that call fails. |
| Nested result first byte `0x10` and nested 16-bit code `0xd0` | Obtain `amount2`, saturate unsigned `4 * amount2`, find or insert the original key and saturating-add that quantity to the same value offset, then continue result projection. The code checks overflow before the shift. |
| Nested result first byte `0x0f` and the selected flag byte is not 1 | Saturating-increment state `+0x50`, set state byte `+0x78` to 1, call an existing helper boundary, then clear the byte on normal return. The outer handler initially sets the passed flag byte to 1; reachability of this alternative after intervening calls, and effects if the call unwinds, are not established. |
| Optional observer pointer at state `+0x4278` is nonzero | A slot-return tag other than `0x1a2` reaches the independently decoded `state.rs:460:78` Location and a diagnostic call followed by `ud2` if it returns. The tag-`0x1a2` arm calls an indirect callback at table offset `+0x20` and conditionally releases its returned buffer. |

The clock comparison reads three dwords at state `+0x60`, `+0x64`, and `+0x68`; it constructs a signed value, replaces nonpositive values with zero, and uses an unsigned comparison against the config qword. Its calendar interpretation and allowed runtime inputs are not asserted. Both multiplication paths use unsigned overflow to select all ones; the subsequent additions independently select all ones on carry. Even if the two getter returns are equal, their writes are separated by other calls and may be changed through aliases. The static cases do not prove runtime reachability.

### State-root child handoff

PR #2181 records the end selector and root capture, including the pointer formed at `0x269a20b` for state `+0x968`. The same capture array is passed to the grouped descriptor at `0x644b2d0`. The previously referenced group callback loads capture index 4 at `0x3d2a05a` and pairs it with descriptor `0x6479420`; those two existing group/capture functions remain context. The descriptor's relative relocations identify the newly selected visitor `0x46a4900` and constructor `0x46a0fb0`.

On the selected visitor path, `0x46a4900` reads the row pointer at map `+0x8` and row count at `+0x10`. For each `0x60`-byte row it pairs row `+0x48` with the 20-byte key descriptor `0x648f6f8` and row `+0x8` with the value descriptor `0x6493458`. The latter resolves to visitor `0x4307310`; this visitor forms a child pointer at value `+0x8` and pairs it with the eight-byte scalar descriptor `0x6482968`. These offsets join the prior `row + 0x10` store to that scalar child. `joins.tsv` checks the equality from independently read operands and descriptor sizes.

The visitor tests the source count at map `+0x30` for overflow and for an allocation size above `0x7ffffffffffffff8`; it has distinct zero-size, allocation-failure and unwind cleanup paths. The value visitor checks its container and expects ten children. The exact serialization or hashing performed by the generic child callbacks is outside this packet. Thus the evidence reaches an input descriptor; it does not compute a state-root digest or prove that a runtime scheduler invokes every recorded callback.

For example, these human-readable excerpts correspond to pinned ELF windows; no tool parses disassembler text:

```text
22ecf12  48 03 68 08     add    rbp,QWORD PTR [rax+0x8]
22ecf25  48 89 48 08     mov    QWORD PTR [rax+0x8],rcx
46a4a10  49 8d 45 c0     lea    rax,[r13-0x40]
4307332  48 8d 47 08     lea    rax,[rdi+0x8]
```

### Historical lead and release boundary

The original RE-017 loader packet is node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its original loader Location is `0x56dfbf8`, `state.rs:107:37`; the separately authenticated #115 loader Location is `0x64767a8`, `state.rs:123:37`. Their selected result checks differ: #94 at `0x3273871` compares a register with 2, while #115 at `0x3c1353b` compares a different register with 1.

The historical navigation lead at #94 `0x2208580..0x2208e5c` references `state.rs:398:78` and compares its input with `0x186` at `0x2208597`. Independently, the selected #115 handler `0x22ec9b0..0x22ed1ec` references `state.rs:460:78` and compares its input with `0x1a2` at `0x22ec9c9`. The optional check validates both complete digests, the two #94 Location relocations and their instruction references, the two #115 Location records, and both pairs of comparison bytes. Similar structures and locations are navigation evidence, not proof that the releases have equivalent types, layouts or behavior. No historical address or observed value is relabelled as #115.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo manifest, lockfile, compiler and linker flags, fixture replay, two-build comparison, raw and normalized implementation comparisons, relocation masks, helper closure and whole-ELF comparison: **not yet implemented/measured**. Target bytes are observation, not code to transplant. The negative controls below exercise the collector and small arithmetic/byte models; they do not execute the node or establish behavioral equivalence.

## Results and limitations

`summary.json` reports 15 selected FDEs, 63 selected and 21 contextual byte windows, 56 selected conditional branches, 48 selected/context calls, 16 checked direct-call joins, 45 decoded operands, 7 RIP references, 5 descriptors, 1 materializer boundary relocation, 139 LSDA call-site rows, 38 covered-call witnesses and 24 checked layout, tag, descriptor-reference and callback joins. These are selected records, not coverage percentages. The focused suite passed 49 tests with zero skips, including changed target and historical hashes, every fixed window and transfer, actual encoded FDE/relocation/Location/LSDA corruption, fileless and overlapping mappings, malformed exception tables, the index-4 descriptor join, all descriptor-reference and selected callback destination joins, a damaged materializer relocation and future-tag/copy boundaries, all 5,100 single-byte key substitutions, saturated multiplication/addition, sort thresholds, root allocation bounds and a two-row root-offset control.

Pointer propagation from the materializer to the root is conditional on the selected future, prior engine and root paths, ordinary bindings, successful helper returns and no conflicting intervening alias writes. The distinct pointer returned by the Location caller has not been shown to be the pointer on the alternate materializer-future route. The key hash, the inner action's complete behavior, timestamp meaning, dynamic callback effects, all branch reachability, unwind actions, persistent snapshot effects, complete begin/action/end-block scope and final state-root digest remain unresolved. No component gate is advanced and no whole-node equivalence is claimed.

Next question: establish loader-to-compact-task pointer identity and trace the eight-byte scalar callback through the ordered root reduction, including mutations that may occur between the two selected visits.
