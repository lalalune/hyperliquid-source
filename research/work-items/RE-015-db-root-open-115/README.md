# RE-015: DB-root guard and per-key open path in node #115

Node #115 builds two keyed entry paths from a separately formatted root input, checks that input again during DB opening, and applies binary-observed options before publishing the collection.

- Component ID: `constants` (global configuration); task `RE-015`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference snapshot `999556f6e0a474b8312db96ec3149e1c44e97c23` is a lead, not copied implementation.
- Claim status: byte and relocation observations, with explicitly conditional control-flow inferences below; runtime contents, types, and external callees remain unresolved.
- Scope included and excluded: the selected allocation, byte-key loop, root guard, bounded search, options and open adapters on their identified paths; not all callers, other configuration components, vector-search internals, I/O outcomes, or exception cleanup.

## Reproduce

From the repository root with Python 3.12.3, the standard library, the existing `tools/elf_index.py` and `tools/fde_extents.py`, and the authenticated #115 capture:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_db_root_open_115.py --out work/re015-db-a
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re015_db_root_open_115.py --out work/re015-db-b
diff -r work/re015-db-a work/re015-db-b
python3 -m unittest tests.test_re015_db_root_open_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

The two output directories contain the 24 generated files; compare them with the same-named files in this work item. The generator checks the complete input SHA-256 before parsing, reads ELF/FDE data directly, and never executes the capture or invokes an external program. The tests and both generations also passed with a PATH containing only Python and without binutils. The analysis used GNU objdump 2.42 for human inspection only; no output file, count, address or test parses its text. Generation writes only its output directory. SHA-256 of the generator is `5021c735ccdcada8c7d1d665299230d5220ef3b1bec3dc617b770e465be99135` and of the test is `7df3d69211f53ea3b6eb645212e3e2c83f793bd421c779e40cdc29512ada9e90`.

For the optional historical comparison, supply the separate authenticated #94 capture; its digest is checked before comparison. This command prints the old and new coordinates but does not add files to the default output:

```sh
python3 tools/re015_db_root_open_115.py --out work/re015-db-history --compare-94 references/can1357-hl/bin/hl-node-mainnet-new
```

## Evidence

All addresses are linked ELF virtual addresses (VAs) unless explicitly called file offsets. Ends in `functions.tsv` and `windows.tsv` are exclusive. The 26 selected extents are decoded from FDEs, checked against the unwind index and whole-body hashes; `bodies.tsv` retains all 21,718 selected bytes. An FDE extent is not proof that all functions or all control-flow edges have been found. `branches.tsv`, `calls.tsv`, `references.tsv`, `relocations.tsv`, `plt-links.tsv` and `windows.tsv` retain the selected branch encodings, direct and indirect calls, RIP displacements, relocation records and complete raw windows. File offsets are separately labeled. The 93 branches are selected sites, not a complete control-flow census.

| Observed path | Coordinates and byte-grounded observation |
| --- | --- |
| Build the input and paths | On a selected upstream branch, `0x51d04b1` calls `0x57c4420`, then `0x51d04c0` calls `0x4e33ef0` with the same output object. The constructor formats the incoming root, prepares key bytes `0, 1`, calls `0x5168300` → `0x5b80150`, and publishes the resulting map alongside the original root fields. The row formatter receives that earlier formatted root, the key callback at relocated slot `0x64e2078`, and the complete `c0 01 / c0 00` entry at `0x43aa84`. The callback at `0x1696db0` submits `Exchange` for byte 0, `Rpc` for 1 and `EvmState` for other byte values to the shared output helper; valid source-level enum values remain unknown. |
| Preserve the formatted path | `0x5b80269` invokes relocated object constructor `0x16961b0` on each formatted row. In its non-rejection path, the constructor copies the formatted string triple into a new object; `0x4d0be50` places the row byte and object pointer into map slots later read by `0x57c6530`. For inputs of at most 24 bytes, an exact byte-substring `checkpoint` takes a diagnostic route at `0x169623f` instead; if its helper returns, it reaches `ud2` at `0x16966f3`. Longer search paths are not modeled. |
| Top-level root and fixed keys | `0x4e33ef0` formats its input using the same signed-min selector, global slot and root entry; it calls a separate root-check boundary at `0x4e33fdc`, whose nonzero result takes an error branch. At `0x4e33feb` through `0x4e34004` it sets the range to 0..2 and initializes two key bytes to `0, 1`. The same input pointer is passed at `0x4e3401d` through `0x5165970`, `0x5b77f30` and the loop to the per-entry guard; `input-flow.tsv` records the register and stack handoffs. These two bytes are local map keys, not established enum discriminants. |
| Allocate and iterate | `0x5b77f30` calls `0x543e5b0` at `0x5b77fcf`; the loop passes a byte to `0x57c6530` at `0x543e63e`. After a normal return it publishes a byte and pointer at `0x543e6f8`/`0x543e6fc`, advances the count and writes the final count at `0x543e716`. Empty and allocation-failure branches are retained. |
| Locate entry | The selected routine compares byte keys and routes an empty or exhausted lookup to the `no entry found for key` bytes at `0x9360f2`; the matching reference is incremented at `0x57c65c9`. It calls the guard at `0x57c65df`. |
| Select root format | At `0x5a007eb`/`0x5a007ee`, only input first word `0x8000000000000000` falls through to the global slot `0x64e0918`, whose relative relocation addend is `0x64f06c0`; it uses that object's `+0x18` field and the complete 27-byte entry at `0x443e39`: `c0 18`, `/hyperliquid_data/db_hub`, `00`. Other first-word bit patterns take the input-format entry `c0 00` at `0x43b857`. These are machine-word observations, not a claim that every bit pattern is a valid value of the original type. |
| Test root | The guard passes `Exchange` (8 bytes at `0x4595c0`) and `Rpc` (3 bytes at `0x47b428`) to a shared formatting-output slot, then calls `0x59dbff0` at `0x5a00902` and `0x5a00988`. A nonzero search result goes to the `db_home contains db_bundle in path` entry at `0x44dbf5`. Formatting and output failures have distinct incoming branches. If the respective error helpers return, these error routes reach `ud2` at `0x5a00a95`; unwind behavior is not closed. |
| Compute size | At `0x57c6606` the low bit selects either the default `0x4000 << 20 = 0x400000000` or the supplied unsigned value shifted by 30, with saturation to `0xffffffffffffffff` at the `2^34` boundary. Both normal and saturated values go to the relocated builder `0x5d35250`, which forwards the input to `0x5d3db50` and the latter calls `0x5d3d550`. Saturation is an argument, not an immediate rejection. |
| Build and attach options | `0x5d34b20` initializes option A field `+0x58` to `0x1000`; `0x57c66cb` calls `0x5d34c40` with `0x8000` on the same object. Setters `0x5d34c50` and `0x5d34c60` store `1` at option B `+0x0` and `0x8000000` at `+0x4a8`. `0x5d35ae0` transfers the size-builder pair to A `+0x38/+0x40`; `0x5d356e0` calls a copy boundary and writes its result and a new control object at B `+0x548/+0x550`. Null and replacement branches are recorded. Field names and exact native types are not established. |
| Choose a path and open | The entry loads a pointer/length pair from the matched reference at `0x57c6787`/`0x57c678c`, passes that pair through conversion and to the directory boundary at `0x57c6978`, then calls `0x5828940` at `0x57c69b4`. A directory error, non-sentinel open result, and null returned box branch separately at `0x57c6981`, `0x57c69cc`, and `0x57c69d5`. |
| Native status and result | Adapter `0x5828940` initializes an error pointer to zero and calls the relocated wrapper `0x5d33cb0`; the wrapper calls the open-engine boundary `0x5e65530`. A zero status byte proceeds to allocation of an eight-byte box containing the returned word. A nonzero byte calls `0x5d2e0e0`, whose ordinary return writes the result of `strdup` to the error pointer and returns 1, leading the wrapper to return zero. The adapter follows a separate path if that pointer is nonzero; if it is zero it writes the signed-min marker and wrapper result. The caller also checks the box pointer. PLT relocations for `strdup`, `free`, and the allocator are independently decoded. |
| Collect and publish | If both fixed entries return normally, `0x5165970` observes count 2 and takes its below-21 handler at `0x5165a86`; count 0, count 1 and the at-least-21 boundary have separately recorded branches. It passes the collection to a construction boundary at `0x5165a25` and writes its output. On the selected per-entry success path, `0x57c6aac` through `0x57c6ae0` write result fields through offset `+0x50`; the outer loop then publishes its byte/pointer row. The table does not establish the behavior of the opaque engine, filesystem, allocator, or all failure cleanups. |

A human-readable excerpt, with raw encodings independently retained in the generated windows:

```text
5a007eb  cmp    rax, QWORD PTR [rdi]
5a007ee  jno    5a00837
5a0081e  lea    rdx, [rip + displacement]  # 443e39
57c6606  and    r14b, 1
57c663f  shl    rdi, 20
57c6643  call   QWORD PTR [rip + displacement]  # slot 64eab30
57c6ba8  mov    rdi, 0xffffffffffffffff
57c6baf  call   QWORD PTR [rip + displacement]  # slot 64eab30
```

For the traced upstream branch, the later pair is loaded from an object whose path string was built from an earlier formatting of the same root input and a key-specific formatting argument. The guard formats the root input again; neither equality of the two runtime formatting results nor the exact rendered path is established, especially across shared helpers and global state. No concrete path was opened in this analysis, and the global field's runtime value is unknown.

### Branch and model boundaries

`constructor-keys.tsv` and `parent-keys.tsv` give the two fixed key bytes; `key-label-cases.tsv` records the callback's machine-byte branches; `path-guard-cases.tsv` covers the bounded 24-byte search and the unmodeled longer boundary; `input-flow.tsv` records nine handoffs; `collection-cases.tsv` models six count boundaries. `root-cases.tsv` contains the signed-min word and four neighbors/control values; `size-cases.tsv` contains 14 flag/value boundary cases; `guard-cases.tsv` records the precedence of five supplied Boolean outcomes. `native-cases.tsv` records five normal-return cases, treating the status and duplication outcome as inputs; it does not simulate allocation failures or external calls. These rows are models of decoded branches, not executions of the node.

For the two literal byte sequences, `0x59dbff0` takes the equal-length comparison when lengths match and returns false when the needle is longer. With a strictly longer haystack shorter than `needle length + 15`, and for the two literals whose first and last bytes differ, its scalar loop calls relocated `bcmp` for each candidate; this supports ordinary case-sensitive byte-substring semantics for that bounded input domain. `bounded-search-probes.tsv` contains 96 positive, negative, short and boundary model rows. The vector branch at equality with `needle length + 15` is deliberately not modeled. Applying the literal model to the guard further assumes that the shared formatting-output helper emits the supplied label bytes unchanged; this packet does not re-establish that shared helper's full behavior.

### Historical leads and release separation

The optional comparison checks the separate #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` before reading it. The complete `/cham` entry is #94 `0x1fc0ec` and #115 `0x44ab69`; `/static_config` is #94 `0x1ef5f5` and #115 `0x4401ef`; the DB-root format entry is #94 `0x1f3db9` and #115 `0x443e39`. These are separate byte-validated coordinates, not relocated addresses inferred from #94. The #94 references at `0x164f840` and `0x164fbae` are checked only against #94. Existing #115 work owns the corresponding configuration-path questions, so this packet does not claim them as new functions.

The `NvTestnet` pointer/length descriptor is at #94 `0x5668488` and #115 `0x63f8998`, with length 9 in each capture. Its indices are 32 and 33 relative to the previously reported respective table bases; this check does not establish a complete discriminant table. The #94 selector bytes at `0x15861dd` include an additional `0x8000000000000001` comparison leading to the #94 `/hyperliquid_data/no_db_hub` entry at `0x1ea808`. The #115 guard instead routes that word to its ordinary input-format branch, and the exact `/no_db_hub` suffix occurs zero times in the full #115 file. This is a bounded byte-level comparison, not proof that such a path cannot be built dynamically or that the two routines have identical original source identities.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker flags, two-build result, binary comparison, masks, dynamic execution and end-to-end filesystem comparison: **not yet measured**. `size-cases.tsv`, `guard-cases.tsv`, `native-cases.tsv`, and `bounded-search-probes.tsv` are static models, not differential tests of a candidate reconstruction. The existing shared ELF and FDE parsers supply section, unwind, CIE and FDE decoding; file-backed mapping explicitly excludes SHT_NOBITS. Selected direct displacements, dynamic relocations, PLT links, bytes, and branch targets are independently checked by this packet's tool. No source code from the reference was copied.

## Results and limitations

The generator produced 24 files from 26 selected FDE extents (21,718 bytes), 93 conditional branch sites, 28 direct and 21 indirect call sites, 22 RIP references, 15 data entries, 17 dynamic relocations, 3 PLT links, 78 raw windows, 4 option values and 4 binding-field stores. These counts describe the selected evidence only. The focused suite passed 34 tests with zero skips, including corrupted identity, instruction, branch, string terminator, relocation, symbol, PLT jump, option value and field-offset controls, invalid ranges and NOBITS mapping. The size model was checked for 5 flags across 262 values each; the bounded search model was compared with independent byte membership, including altered samples and rejection at the vector threshold. Two generations under different hash seeds and time zones were byte-identical. Artifact verification, catalogue check, and inventory reproduction passed.

The real global value, equality of separately formatted roots, shared formatter's complete semantics, the longer `checkpoint` and vector search paths, full options types, external engine behavior, all error unwinds, call-target closure and live filesystem effects remain unknown. No milestone or component progress gate is requested. Next question: close the shared formatter and global-state dependencies to determine when the constructor's formatted root and the guard's independently formatted root must be equal.
