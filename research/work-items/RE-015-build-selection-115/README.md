# RE-015: configuration-rooted build selection through command state

Node #115 maps the callback's machine-byte input through a four-way repeating display selection, then selects a `run-client` path before checking the nonzero build-kind byte and carries it through argument construction and process-result state; a reconstruction must preserve these boundaries and failure handoffs.

- Component ID: `constants`; task `RE-015`, using RE-001 unwind and relocation evidence.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical inferred-reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` as a lead only. No inferred source code was copied.
- Claim status: observations are selected target bytes, FDE/index associations, relocations, instructions and branch destinations; names and source-level roles are inferences. Runtime inputs, complete native adapter behavior, and component ownership outside this path remain unresolved.
- Scope included and excluded: one callback-to-command path, its build-kind selection, selected ASCII argument handling, first process-state transition, and selected native success/failure routes. This does not cover all callback registrations, all selector callers, all process options, complete service lifetime, every unwind path, or the full component.

## Reproduce

From the repository root, use Python 3.12.3 or compatible Python 3, the standard library, the repository's shared `tools/elf_index.py` and `tools/fde_extents.py`, and the authenticated #115 capture. The tool verifies the complete input digest before reading ELF structures or emitting anything. It never executes a captured binary and makes no network, chain, key, or target-driven filesystem calls. GNU objdump 2.42 was used only for human inspection; generated files and tests do not invoke it or parse its output.

```sh
python3 tools/re015_build_selection_115.py --out research/work-items/RE-015-build-selection-115
python3 -m unittest tests.test_re015_build_selection_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

The producer SHA-256 is `68f612f0eb900903a48b6393e83991dff95fd51bbf7c244cc54f6de3b94fa0b4`; the focused test SHA-256 is `f2f7368d18e4ee32af5f15c6d7f048b63aa3a64cf3ab1ca10de37b95246d4f27`. The manifest lists the output and README hashes. The producer writes exactly the 20 generated files listed below. `README.md` and `MANIFEST.sha256` are separately maintained. The following generates two independent sets; substitute two different writable, repository-root-relative directories for the placeholders.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_build_selection_115.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re015_build_selection_115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

A separate authenticated #94 capture is optional; it is not required for the default producer or tests. If available in the reference snapshot, this command prints the independently decoded historical comparison while still writing the usual #115 files:

```sh
python3 tools/re015_build_selection_115.py --out <tmp-dir-one> --compare-94 references/can1357-hl/bin/hl-node-mainnet-new
```

All addresses below are linked ELF virtual addresses (VAs) unless labelled as file offsets. The selected `.text` bytes have file offset VA minus `0x1000`; the selected `.rodata` bytes have file offset equal to VA. Relocation rows separately contain the relocation record's file offset and the relocated slot's file offset. Ranges are half-open. Each chosen FDE was decoded with the shared parser and matched against its unwind-index entry; an FDE range is not by itself proof of a complete function census or complete control flow.

| Generated evidence | Contents |
| --- | --- |
| `summary.json`, `functions.json`, `bodies.tsv` | Digest, selected counts, 19 FDE/index bindings, complete raw bytes and unmasked SHA-256 hashes for those extents. |
| `transfers.tsv`, `references.tsv`, `relocations.json` | Selected direct calls and RIP-relative operands, 39 decoded relocation records, and the dynamic symbol for imported slots. |
| `branches.tsv`, `windows.tsv` | 74 selected conditional instruction encodings and destinations, and 61 selected raw windows. |
| `literals.tsv`, `context-anchors.json` | Exact complete selected templates and literals, the global slot and field, and the contextual #115 `NvTestnet` descriptor. |
| `name-dispatch.json`, `name-byte-cases.tsv` | Four selected packed-word, jump-arm, and displayed-text bindings and a 256-input machine-byte shift model. |
| `mode-cases.tsv`, `mode-exhaustive.json`, `equality-probes.tsv` | A selected machine-byte decision model, exhaustive byte-pair counts, and length/single-bit predicate probes. |
| `prelude-cases.tsv`, `ascii-arguments.tsv`, `short-nul-cases.tsv`, `state-cases.tsv`, `native-cases.tsv` | Bounded TLS-gate, ASCII, short NUL-scan and explicitly conditional state/native-result models; these are not target executions. |

## Evidence

### Selected path and input binding

| Stage | Selected FDE range | Byte-backed observation |
| --- | --- | --- |
| Callback | `0x15b8cd0..0x15b8e35` | Reads a byte at input `+0x28`; after a separate prelude returns, passes it at `0x15b8d05` through a RELATIVE slot to `0x155f8d0`. The slot at `0x64004e8` also relocates to this callback; its registration context is not recovered. |
| Prelude | `0x155f9e0..0x155fa02`, `0x5c908b0..0x5c90b47` | A 32-byte copy crosses two RELATIVE slots. The callee checks a thread-local byte, performs a selected pointer swap and dispatches zero or more 16-byte entries before the callback can proceed. |
| Entry and name display | `0x155f8d0..0x155f9d2`, `0x1551630..0x15516b1` | The entry packs four words, formats a selected displayed name with the complete entry at `0x448b95`, and supplies `run-client` with mode bytes 2 and 1 to the command builder. |
| Select and prepare | `0x1564870..0x1564b2b`, `0x1564b30..0x1565355` | The selector reads the RELATIVE global slot, adds `0x18` to its object pointer on selected paths, and returns a three-word value plus byte `+0x18`. The builder consumes that byte, constructs an argument vector, and writes an output object. |
| Trim and collect | `0x150caf0..0x150cd87`, `0x1531b10..0x1531e02`, `0x1532b70..0x1532ed5` | The builder passes a formatted byte sequence to a trim-like routine and initializes a one-byte `0x20` search; the iterator and collector copy the resulting slices into 24-byte entries. Only the ASCII model below is claimed. |
| Initial dispatch | `0x1565f40..0x15677fe`, selected initial loop | The entry copies `0xb0` bytes into a single-element collection. The loop checks each element's `+0x80` word against 2 and calls `0x1565460` with the second argument zero. Other loop iterations and scheduling are not closed. |
| Start and process boundary | `0x1565460..0x1565e45`, `0x1565ec0..0x1565f38` | The start routine formats a log suffix from the same global field, reaches a process adapter, handles its result tag, copies returned state or routes to an error helper. |
| Command conversion | `0x5c94cb0..0x5c95025`, `0x5c94bb0..0x5c94ca2`, `0x141e960..0x141eada`, `0x141e170..0x141e251` | The path and argument adapters pass byte slices through a shared NUL scanner and terminator, record a conversion-error flag, and populate the native command. |
| Native process adapters | `0x5c84a40..0x5c870b9`, `0x5c870c0..0x5c874cd` | Selected branches reach imported `fork`, `pidfd_spawnp`, `posix_spawnp`, or the fork-child `execvp` path. Their selection is conditional; no call is actually made during this research. |

The callback first copies its input's first 32 bytes and calls slot `0x64e1310 -> 0x155f9e0`; that wrapper copies the same width and calls slot `0x64e1188 -> 0x5c908b0`. The latter loads a byte at offset `+8` from a selected thread-local base and compares it with 1 and then 2. Its conditional routes are:

| Selected thread-local byte | Observed route before the build entry |
| ---: | --- |
| 1 | Skip the initialization call and continue to the thread-local pointer swap. |
| 2 | Call the error boundary at `0x5c908f7`; if that call returns, execute `ud2`. |
| Other byte | Call `0x5ca0d20` through a RELATIVE slot, write byte 1 to the selected thread-local location, and continue to the pointer swap, conditional on a normal return. |

After the swap, the code processes the previous pointer through another helper and conditionally decrements its reference count. It reads a count and pointer from the copied object, scales the count by 16, and on the nonempty path calls a function pointer at each selected entry's second word plus `0x18`; a zero count bypasses that loop. Conditional deallocation and unwind-resume tails are recorded as raw selected branches and calls. The actual thread-local value, element identities, indirect callees and their effects are unresolved; only normal return from this prelude reaches the subsequent build entry. The five rows in `prelude-cases.tsv` are a bounded machine-byte branch model and do not imply that every byte is a valid runtime state.

The entry loads `0x0002000300040006` at `0x155f8df`, selects a 16-bit word using its input, and passes the word to the display callback via relocated slot `0x64e10f8 -> 0x1551630`. The callback dispatches through 32-bit relative entries at `0x466d28`. For the selected input domain 0 through 3, the tool decodes the following table directly from those bytes:

| Input byte | Word | Display text | Display arm VA |
| ---: | ---: | --- | --- |
| 0 | 6 | `Local` | `0x155166b` |
| 1 | 4 | `XyzSandbox` | `0x1551679` |
| 2 | 3 | `XyzTestnet` | `0x1551695` |
| 3 | 2 | `Xyz` | `0x155165d` |

The entry first shifts the low input byte left by four within `cl`, then uses `cl` as the count of a 64-bit right shift. On x86-64, the latter uses only the low six count bits, so the machine-byte result repeats every four input values: 4 has intermediate count byte 64 but effective count 0, 16 wraps its intermediate byte to 0, and 255 has intermediate byte 240 and effective count 48. `name-byte-cases.tsv` models all 256 byte values against the decoded packed word and display arms. This is an instruction-level consequence, not proof that any value outside 0 through 3 is a valid source-level input, and it is not the separately recorded `NvTestnet` discriminant.

The display callback's selected arms tail-call an output slot with a pointer and length. Interpreting the complete compact templates as formatted text relies on the previously documented Rust formatting representation; these bytes do not alone prove every property of the shared formatter.

### Build-kind and program precedence

The selector tests the bitwise OR of the two low input bytes first. If both are zero it follows the local copy branch. Otherwise, it checks length 10 and compares all ten program bytes with `run-client`: an eight-byte XOR plus a two-byte XOR are ORed before the equality branch. The `run-client` equality branch precedes the comparisons with kind bytes 1 and 2.

| Condition, in execution order | Selected action | Result byte at `+0x18` |
| --- | --- | ---: |
| kind and flag both zero | Copy the supplied program bytes, subject to allocation/length branches. | 0 |
| At least one mode byte nonzero and exact ten-byte `run-client` | Format the selected global field with the full `c0 10 ... 00` client entry at `0x4366ce`. | 0 |
| Other program, kind 1 | Format `debug` and the program through the full build entry at `0x449a91`. | 1 |
| Other program, kind 2 | Format `release` and the program through the same build entry. | 1 |
| Other program, remaining nonzero combinations | Reach the diagnostic entry at `0x440ed2` and its error-call boundary. | not established |

The selected #115 references start at `0x1564985` for the build entry and `0x1564a2a` for the client entry, rather than at their interior text bytes. The first global-field load uses `0x156494e`; the corresponding path's guard precedes `+0x18`. The exact client branch takes its own guard and field access. The full entry encodings and displacements are retained in `literals.tsv` and `references.tsv`.

This ordering has a concrete boundary consequence: a nonzero byte pair with an otherwise unsupported kind still takes the client branch when the program bytes match exactly. For example, the algebraic machine-byte model routes `(kind=3, flag=0, program=run-client)` to the client template, while changing any one of the 80 program bits routes that same byte pair to the mode-error boundary. No claim is made that such a kind is a valid value of an original Rust type. A zero pair with the same program takes local copy first. The 131,072 total cases in `mode-exhaustive.json` are model evaluations of two specified program strings, not dynamic tests of 131,072 node inputs.

For the concrete entry above, kind 2 and flag 1 are forwarded at `0x1564bfa`, and the exact `run-client` match yields result byte 0. The builder tests that byte at `0x1564da7`; byte 0 branches past the script-argument insertion. On the tag-1 branch, the 21 bytes `--running-from-script` are inserted at the front of the 24-byte-entry collection before selected extra entries are copied. This is a condition on the selector's result, not a claim about every possible caller or mode representation.

### Argument collection and object state

The entry's `0x448b95` template contains the literal `--api-url ` followed by an argument marker. The builder formats another complete entry at `0x448bb1`, containing an argument marker followed by ` zip-and-upload`. After a normal formatter return, the resulting bytes reach the trim-like helper at `0x1564d3c`. The subsequent iterator is initialized with the one-byte value `0x20`; `0x1531b10` searches for the selected delimiter and `0x1532b70` copies the ranges into 24-byte records. The selected ASCII checks in the trim helper cover bytes 9 through 13 and 32 at the two edges.

In the explicitly bounded ASCII model, edge whitespace is trimmed, then splitting occurs at each space byte. A repeated interior space produces an empty entry, and an interior tab remains within an entry. The four selected displayed names contain no spaces, so the model maps their normally formatted strings to three entries: the option, displayed name, and `zip-and-upload`. The model does not establish the complete Unicode table, arbitrary malformed UTF-8 behavior, allocator behavior, or external command parsing.

At `0x15650c4`, the builder writes 2 to output offset `+0x80`; it also writes zero to `+0x78` and initializes a byte at `+0xa8`. The entry allocates and copies `0xb0` bytes, then passes a one-element pointer/count collection to the dispatcher. On its selected first iteration, `0x1565f75` checks `+0x80 == 2`; a different value branches to the diagnostic boundary. The matching path calls the start routine with argument byte 0. These are field offsets and writes, not a recovered Rust struct definition.

The start routine may first reset the `+0x78` counter if the compared time field changes; it updates the associated time fields before the process adapter call. After a non-error process result it copies 28 distinct bytes into state starting at `+0x80`, using two overlapping 16-byte stores. It increments the counter only when the decremented mode byte is below 2, saturating at `0xffffffffffffffff`; the initial dispatch's mode 0 becomes 255 and skips this increment. On the result-tag-1 branch it instead reaches `0x1565ec0`; the earlier time-field changes need not be rolled back. `state-cases.tsv` models these selected conditions with external results supplied as inputs.

### Native command conversion and short NUL boundaries

The start routine supplies the selected program pointer and length to `0x5c94cb0`, and supplies each collected argument pointer and length through slot `0x64e0ee8 -> 0x5c94bb0`. Both call the byte-slice converter at `0x141e960` through slot `0x64df718`. For input lengths at most 15, the selected scalar loop compares each original byte with zero. With no zero, its selected normal path calls `0x141e170`, which writes a zero after the copied bytes, and returns the signed-minimum sentinel in the first result word. A found zero instead returns a non-sentinel first word and the first matched offset. Lengths of 16 or more use additional scanning paths which are preserved as raw bytes but not modeled here.

The path constructor uses the converter result to fill native command offset `+0x80`; the child adapter later loads that field for its `execvp` argument. The argument adapter inserts each normally converted pointer into an array and restores a zero pointer after the last entry. If the selected converter reports a found zero, the path constructor or argument adapter selects the literal `<string-with-nul>` and records byte 1 at native command offset `+0xc0`. With the constructor's observed zero values at native offsets `+0x70` and `+0x78`, the adapter checks `+0xc0` at `0x5c84baa` and returns result tag 1 before its native process calls. This is a conditional error-path observation, not a statement about the actual runtime input. `short-nul-cases.tsv` contains all 136 modeled empty/no-zero and single-zero cases through length 15; the focused controls reject length 16 as outside this model.

### Native effects and failure branches

The selected process adapter checks option fields before choosing among paths; those checks and all runtime values are not fully recovered. The following statements are conditional machine-code observations, not evidence that a process or file was created during analysis:

| Selected condition | Byte-backed route |
| --- | --- |
| Socket-pair call returns `-1` | `0x5c85eb3 -> 0x5c860a2` reads the error-location import and constructs output tag 1. |
| Fork call returns `-1` | `0x5c85f0b -> 0x5c860ec` reads the error-location import and constructs output tag 1. |
| Fork returns zero | `0x5c85f16 -> 0x5c86b24` enters the child path, which calls the child adapter; after its intervening checks, a selected path calls the imported `execvp`. If execution returns, the child adapter reads the error location. |
| `pidfd_spawnp` returns 38 | `0x5c86863` stores byte 2 in a separate global; after normal cleanup the selected branch returns to the socket-pair/fork path. Other nonzero statuses take the error route. |
| `posix_spawnp` returns nonzero | The selected cleanup path reaches output tag 1. A zero status enters the success cleanup, whose subsequent value-dependent branches remain significant. |
| Process adapter returns tag 1 | `0x1565aab -> 0x1565d95 -> 0x1565ec0`; the error helper calls the diagnostic boundary and has an `ud2` if it returns. |

The successful selected process-result path constructs output tag 0 and later reaches the state copy. Dynamic symbol names, binding/type/section fields and their exact `R_X86_64_GLOB_DAT` entries are decoded from `.dynsym`, `.dynstr` and `.rela.dyn`. The `pidfd_spawnp` symbol is weak and undefined in the ELF, and its slot is checked for zero before the selected call. These are static bindings, not observations of a host system. The helper bodies, child setup branches, global synchronization, process scheduling, open flags and other failures remain incomplete.

A short human inspection excerpt, with the authoritative bytes and targets in the generated records:

```text
1564888  mov eax, r8d; or al, cl
156488d  je 15648de
15648b0  je 1564a02
15648bf  cmp cl, 1
15648c7  cmp eax, 2
1564da7  test r15b, r15b
1564dba  je 1564ff2
1565f75  cmp dword ptr [rdi+0x80], 2
1565f92  call 1565460
1565aab  je 1565d95
```

### Historical leads and release separation

The #94 leads are recorded in the parent revision `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4` under the work-item directories `RE-015-format-prefix-correction-94`, `RE-015-rip-xref-tail` (its packet is named `EVIDENCE.md`), and `RE-015-xref-instruction-starts`. They were removed from the active tree during the #115-only migration. The #94 capture is `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The optional comparison authenticates it separately and reads each coordinate independently. The #94 selector FDE starts at `0x13cd410`; the #115 selector starts at `0x1564870`. Their selected first 54 bytes are equal, but the rest is not asserted equal or normalized.

| Full entry | #94 entry / selected reference VA | #115 entry / selected reference VA |
| --- | --- | --- |
| Build suffix | `0x1fae07` / `0x13cd525` | `0x449a91` / `0x1564985` |
| Client suffix | `0x1e4c77` / `0x13cd5be` | `0x4366ce` / `0x1564a2a` |
| `cham` context | `0x1fc0ec` / `0x164f840` | `0x44ab69`, contextual data only |
| Static-config context | `0x1ef5f5` / `0x164fbae` | `0x4401ef`, contextual data only |

The optional comparison also validates the `NvTestnet` pointer/length pair at #94 slot `0x5668488`, text `0x2180ff`, index 32; the separately decoded #115 slot `0x63f8998` points to `0x464716`, index 33. Both slices have length 9. Selected descriptor controls give old/new indices 0/0 for `Ec`, 31/32 for `SoloSandbox`, 33/34 for `NvTestnet2`, and 75/78 for `EbHlPerp`. The separate bound diagnostics report 76 for #94 at `0x21823f` and 79 for #115 at `0x464893`. These are context and release-drift controls, not a new 76-entry table, a reanalysis of the already-owned configuration initializer, or evidence that this build-kind byte is an `AwsName` discriminant.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker flags, two-build result, compiled-code comparison, normalized masks, dynamic differential tests, complete helper/data closure, and whole-ELF comparison: **not yet measured**. The historical prefix comparison is raw and unmasked; it is not equivalence for either full body. The reference is a lead and is not a correctness oracle.

The 36 focused tests include input shift, thread-local comparison and indirect-call corruption controls, short zero-byte position and terminator corruption controls, wrong current and historical digests, changed instruction and branch bytes, wrong or duplicate relocations, changed imported symbols, altered display leaves and literals, section-boundary/NOBITS/ambiguous mapping rejection, all single-bit mutations of the program predicate, and explicit argument/state/native-result boundary controls. The default producer and tests use no external programs. Models are conditional arithmetic over the decoded operands; none invokes or emulates the node.

## Results and limitations

The producer records 19 selected FDE extents comprising 28,114 bytes, 54 selected transfers, 39 relocations, 21 selected RIP references, 74 selected branches, 61 windows, 16 literal slices, five prelude cases, four name rows, 256 callback-byte cases, 1,024 representative mode rows, 85 equality probes, 13 ASCII argument cases, 64 state cases, 14 native-result cases and 136 bounded short NUL cases. These are selected-set counts, not coverage denominators. The focused suite passed 36 tests with zero skips. Two generations under different hash seeds and time zones matched byte for byte; artifact verification, imported-reference verification, packet verification, catalogue consistency and inventory reproduction passed.

The prelude's indirect callees and input provenance, shared formatting internals, actual global contents, non-ASCII trimming, complete filesystem and native process adapters, concurrent state transitions, post-start scheduling, unwind closure, Rust reconstruction and whole-node equivalence remain open. No component gate is requested. Next question: identify how callers construct and validate the callback's input byte and close the process adapter's remaining option-dependent branches against #115 bytes.
