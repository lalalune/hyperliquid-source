# RE-010: Trace the builder-approval dispatch and state paths

Node #115 stages two distinct builder-approval tags in decoded objects, routes matching tags through separate entry functions to one shared gate and writer, and applies different input limits before the common zero-removal or nonzero-update transition.

- Component ID: `action-dispatch` (RE-010).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; investigative reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no license and is used as a lead only.
- Claim status: static observation for the selected bytes, FDEs, branches, calls, relocations and literals; action associations and data-structure names are inferences as stated below. Runtime behavior, wire-to-dispatch transport and complete helper behavior are unresolved.
- Scope included and excluded: a selected three-field decoder container, two decoder arms and their boxed output, a selected execution caller, two direct dispatch arms, their handler-local validation, the common gate, selected normal writer operations and failure paths. The external input-to-ordinal adapter, actual decoder-to-dispatch transport, all other action arms, general preflight gates, balance-summary internals, the full map helper closure, dynamic interposition, captured-binary execution and a Rust implementation are outside this packet.

## Reproduce

From the repository root with the authenticated target and Python 3.10 or later:

```sh
python3 tools/node115_builder_approval.py --out research/work-items/RE-010-builder-approval-115
python3 -m unittest tests.test_node115_builder_approval
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

With `TMPDIR` set to a writable temporary directory, compare two independent generations:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/node115_builder_approval.py --out "$TMPDIR/builder-a"
PYTHONHASHSEED=999 TZ=Pacific/Honolulu python3 tools/node115_builder_approval.py --out "$TMPDIR/builder-b"
diff -r "$TMPDIR/builder-a" "$TMPDIR/builder-b"
```

The tool checks the complete input digest before parsing. It uses `tools/elf_index.py` and `tools/fde_extents.py` for ELF sections, the unwind index and CIE/FDE records; it reads RELA entries and the selected opcode patterns directly. It accepts only file-backed ranges, excluding `SHT_NOBITS`, and never invokes a disassembler or another process. `functions.tsv` retains full, unmasked FDE bytes and hashes; `windows.tsv` retains the selected, independently pinned instruction windows. `MANIFEST.sha256` hashes the packet files other than itself. Analysis used Python 3.12.3 and GNU objdump 2.42 on Linux x86-64. Objdump was used only for human inspection, never as input to the generator or tests. No node or visor execution, network, private keys or chain state was used; signature verification reads the pinned public key.

## Evidence

Addresses are linked ELF virtual addresses, not runtime-rebased addresses. `functions.tsv`, `windows.tsv`, `dispatch.tsv`, `decoder.tsv`, `container.tsv`, `calls.tsv`, `imports.tsv`, `branches.tsv` and `statuses.tsv` record corresponding file offsets where applicable. Ranges below are half-open FDE extents. The indexed FDE, direct call target and entry/return bytes support the described callable entries; an FDE alone does not establish original source ownership or rule out cold fragments. The selected arm addresses lie *inside* the dispatcher FDE and are not independent functions.

| Role | Selected #115 FDE range | Selected connection |
| --- | --- | --- |
| Action dispatcher | `0x54a3a00..0x54a4468` | Two interior jump-table arms call distinct handlers. |
| Action name formatter | `0x2bd0ef0..0x2bd34e1` | Same two ordinals reach literal-bearing formatter arms. |
| Action decoder | `0x2b84370..0x2b86ebb` | Selected ordinal arms call distinct payload helpers and stage the corresponding tag in a boxed object. |
| Decoder container | `0x20bc850..0x20bdcdc` | A selected three-field sequence retains the decoded box pointer and two 20-byte fields. |
| Execution caller | `0x55f4d60..0x55f52d0` | A selected preflight result reaches the dispatcher directly or with a surrounding counter and flag update. |
| User handler | `0x5533140..0x5533a0a` | Checks the length, calls the percentage adapter, then calls the shared gate. |
| System handler | `0x5520ca0..0x55214d0` | Checks an unsigned input word, then calls the shared gate. |
| Percentage adapter | `0x421e240..0x421e4dd` | Tests suffix, delegates decimal work, and bounds the returned word. |
| Shared approval gate | `0x55f43a0..0x55f457f` | Skips balance check for zero; otherwise checks the builder-like key and summary. |
| Writer | `0x3c1a510..0x3c1ae41` | Gets a row, selects removal or the count-gated update, and dispatches map operations. |
| Row probe / row entry | `0x3ee6280..0x3ee63bc` / `0x4717c50..0x4717d2c` | Selected hash probe and entry-handling paths precede the writer's quantity decision. |
| Outer-row insertion | `0x3ec8b70..0x3ec8f88` | The selected miss path appends a row when capacity is available; vector growth has a separate failure path. |
| Compact insert / ring shift | `0x4549b40..0x4549c3e` / `0x456fb70..0x456fde3` | Insert increments a count and copies a 32-byte record; a shift path uses `memmove`. |
| Tree insert / remove | `0x3710950..0x3710a77` / `0x3901f10..0x3902098` | Empty-tree insert stores the key and word; found-key remove calls a helper and decrements a count. |
| Status formatter | `0x46ef710..0x46f312f` | Selected result words index literal-bearing arms. |

### Two dispatch arms and actual entries

The dispatcher sequence at `0x54a3a6d` subtracts `0x86`, substitutes index `0x14` when the input is below that bias, and indexes a signed-relative table based at `0x92688c`. The selected formatter at `0x2bd0ef7` uses the same bias with a separate table at `0x6098bc`. The calculation below is for the two selected ordinals; no table size, high-tag bounds behavior, or mapping of other ordinals is asserted.

| Ordinal and derived tag | Dispatch table slot and interior arm | Direct call and separate FDE entry | Formatter association |
| --- | --- | --- | --- |
| 54 / `0xbc` | `0x926964` -> `0x54a4276` | `0x54a4286` -> `0x5533140` | `ApproveBuilderFee`, `approveBuilderFee` |
| 70 / `0xcc` | `0x9269a4` -> `0x54a3b07` | `0x54a3b17` -> `0x5520ca0` | `SystemApproveBuilderFee`, `SystemApproveBuilderFeeAction` |

The selected name association is supported by the formatter and by a third switch in the target decoder, which separately refers to the corresponding action type literals and writes the same tags into its output. The exact raw name-to-ordinal adapter and the runtime transfer of that output to this dispatcher remain untraced. The literal pointers and lengths are retained in `dispatch.tsv` and `decoder.tsv`. Both arms move the action pointer by eight bytes before calling their handler. The two named `handlers/54_approve_builder_fee.rs` and `handlers/70_system_approve_builder_fee.rs` files in the investigative reference are agent-created splits. They are not original #115 function boundaries: this target has two handler FDEs, a further shared gate FDE and a writer FDE.

### Decoder to boxed tag

The FDE at `0x2b84370` calls an envelope helper at `0x2b843c5`. On the selected non-error continuation it uses a returned ordinal byte to index the signed-relative table at `0x607198`. Ordinal 54 selects `0x2b864e7`, which refers to `ApproveBuilderFeeAction` and calls payload helper `0x207f3d0`. Its observed `neg`/overflow failure takes `0x2b86979` and stages a different discriminator; the selected non-overflow continuation stages `0xbc` at `0x2b86556`. Ordinal 70 selects `0x2b845db`, which refers to `SystemApproveBuilderFeeAction` and calls payload helper `0x2066ab0`. A zero byte in its result takes the selected continuation at `0x2b86701`, with `0xcc` staged at `0x2b84630`; a nonzero result takes the separate error materialization path. The exact content grammar and payload-helper contracts are not recovered.

For both selected successful continuations, `0x2b86d6b` stores the staged tag as the first word of the object at stack offset `0x1d8`. The decoder requests `0xf0` bytes, copies `0xf0` bytes from that object into the allocated region via a static `memcpy` import, and returns its pointer at output `+0x8` with result byte `0x09`. A null allocation takes a separate failure call followed by `ud2`; unwind cleanup is also present. The dispatcher independently loads a tag from the beginning of its fourth-argument object. **If** the decoded box is passed unchanged as that object and the earlier gates succeed, its tag selects the corresponding measured arm. The intervening ownership and transport are not established, so this is a layout connection rather than an observed end-to-end execution.

### Container and execution caller

The decoder also has a selected caller FDE at `0x20bc850`. For content kind `0x14`, it visits three fields: the first two helper calls must each return result byte `0x09`, and the third must be present before `0x20bd142` calls the action decoder. If that decoder returns `0x09`, the caller takes its box pointer from result `+0x8`, stores it at container output `+0x0`, and copies two separately decoded 20-byte fields to output offsets `+0x8` and `+0x1c`. After its selected cleanup call, exactly three fields take the return at `0x20bd7bc`. Missing fields and non-`0x09` results have separate error branches, recorded in `branches.tsv`; extra fields follow another path. These offsets are a measured container layout, not a claim about the real-world identity of either key.

Separately, FDE `0x55f4d60` preserves an action-like pointer received in its fourth argument and on the selected preflight continuation passes it to the dispatcher at `0x55f50b4` or `0x55f5281`. When the earlier helper's result byte is `0x0f`, the first byte of a separate mode object chooses the two calls. Mode byte `1` takes the first call. Another mode takes the second path: it increments state word `+0x50` with saturation at `u64::MAX`, sets state byte `+0x78` to `1`, calls the dispatcher, and clears that byte after a normal return. A result byte other than `0x0f` or `0x10` takes a result-copy path; the `0x10` case includes an untraced special subcase. The flag's behavior on unwind is not established. In particular, a later action rejection does not by itself prove that the caller made no surrounding state changes.

The container output and execution caller are independently established endpoints, not a proven transfer between them. `container.tsv` records the pointer/key offsets and counter/flag operands, and `caller-vectors.tsv` contains only a synthetic model of the selected result-byte and normal-return branches.

### Input and failure decisions

Both handlers perform selected 20-byte key comparisons before calling two earlier gates. A match on either of the two documented comparison paths reaches word `0x120` and outer byte `0x0f`; its #115 status formatter text is `Can only send reduce-only orders.` The two gate calls can each propagate another non-`0x1a2` result before the action-specific checks. Their full semantics are not analyzed here, and a bypass of the approval writer does not prove that an earlier gate had no side effects.

After these preflight paths, the user handler reads a length from its payload `+0x10`. Lengths at least `0x65` reach `0x158`; shorter inputs go to the adapter using the pointer at payload `+0x8`. The adapter initializes failure word `0x13b`, rejects length zero or a final byte other than `0x25` (`%`), and delegates the preceding bytes to other routines. Its later path supplies an operand `1000` to another helper and tests the conversion result. In the selected final numeric path, an unsigned word at or above `0x7fffffffffffffff` is rejected; the smaller word is returned with `0x1a2`. The packet does not claim complete accepted text syntax, rounding, or that a particular text reaches every representable word.

The system handler takes its word from payload `+0` and a 20-byte key from payload `+0x8`. It rejects the unsigned word when it is at least `0x0ccccccccccccccc`, producing `0x154`, before the shared gate. The user handler instead obtains the word from the adapter and takes the 20-byte key from payload `+0x40`; its selected successful call to the same gate has no system-limit check. The different thresholds are an instruction-level observation, conditional on the user decimal helpers successfully producing a word, not a proof of an externally constructible input or a runtime discrepancy.

The original 20-byte third argument is saved by each handler and passed as the gate's third argument. The builder-like 20-byte payload field is passed as its fourth argument. In the gate, the fourth argument is copied into the lookup at `0x55f4412`; the saved third argument is forwarded to the writer. This distinction corrects the tempting interpretation that the balance lookup necessarily uses the caller key. The real-world identity and unit of the returned summary word remain inferences; the error text supports the builder/balance interpretation but does not establish its denomination.

| Decision in the selected action path | Observed result / continuation |
| --- | --- |
| A documented preflight key comparison is equal | `0x120`, outer `0x0f`; approval gate bypassed. |
| Earlier gate returns a word other than `0x1a2` | Propagate that gate's result; approval gate bypassed. |
| User text length is at least 101 | `0x158`, outer `0x0f`; decimal adapter bypassed. |
| User text is empty, lacks `%`, or the selected adapter conversion fails | `0x13b`, outer `0x0f`; shared approval gate bypassed. |
| System word is at least `0x0ccccccccccccccc` | `0x154`, outer `0x0f`; shared approval gate bypassed. |
| Word is zero | Skip the root and signed-summary checks and call the writer's zero path. |
| Word is nonzero and the root count at state `+0x7d0` is zero | The gate prepares `0x156`, calls a panic-like target, and reaches `ud2`; this is not a normal returned `0x156`. |
| Word is nonzero and the signed summary word is at most `99999999` | `0x138`; the approval writer is bypassed. |
| Word is nonzero, earlier checks pass and the selected row count exceeds 10 | `0x13c`, including for a key that would otherwise be replaced. |
| Word is nonzero, earlier checks pass and count is at most 10 | Selected compact and tree paths update an existing key or insert a key/word pair; normal success is `0x1a2`. |
| Word is zero and the writer completes normally | Remove the key if found, or return success if absent; normal success is `0x1a2`. |

The gate's signed comparison is `jg` after `cmp ... ,0x5f5e0ff`; equality fails and `100000000` passes the comparison. The calls and branches, including their raw opcodes and taken destinations, are in `calls.tsv` and `branches.tsv`. The static RELATIVE relocation for the writer slot `0x64e7e90` names `0x3c1a510`; the status table independently connects the error words above to target literals in `statuses.tsv`. This does not prove runtime loader bindings in the presence of interposition.

Selected human-readable instruction excerpts, also preserved as raw bytes in the generated windows:

```text
2b86556  41 bc bc 00 00 00          mov r12d,0xbc
2b84630  41 bc cc 00 00 00          mov r12d,0xcc
55f43b7  4d 85 c0                   test r8,r8
55f43ba  0f 84 b1 00 00 00          je 0x55f4471
55f4456  48 81 7c 24 20 ff e0 f5 05 cmp qword [rsp+0x20],0x5f5e0ff
55f4468  7f 07                      jg 0x55f4471
3c1a60b  48 83 f8 0a                cmp rax,0xa
3c1a60f  0f 87 71 07 00 00          ja 0x3c1ad86
55f5270  41 c6 46 78 01             mov byte [r14+0x78],1
55f5286  41 c6 46 78 00             mov byte [r14+0x78],0
```

### Selected mutation and cleanup paths

The writer calls the row probe at `0x3c1a59b` and the entry helper at `0x3c1a5e5` before it tests the word for zero at `0x3c1a5f4` and before the nonzero count check. The probe compares a 20-byte field in rows of stride `0x100`. On the selected probe miss, the writer supplies a nonzero entry discriminator, and the entry helper calls `0x3ec8b70`; the hit path supplies zero and skips that insertion call. In the insertion FDE, a selected path with spare vector capacity increments the hash-table count and stores a slot index, copies `0xe0` bytes of the initialized row body, appends the hash and 20-byte key, copies a `0x100`-byte record to the indexed row array, and increments the vector length. These stores precede the writer's zero test. Thus, on this normal path, an outer row is inserted even for a zero input; this is a local state observation, not a claim about transaction rollback or persistence.

When the vector length equals capacity, branch `0x3ec8ced` takes a separate growth path. A failed first attempted growth can reach a smaller retry; failure of that retry reaches `0x3ec8f46`, an indirect failure call followed by `ud2`. Hash-table growth, nonlocal failure cleanup and whether earlier writes are rolled back remain unresolved. The count, copies, selected miss/hit branch and growth branches are retained as raw bytes and direct ELF-derived operands; the imported copy slots statically name `memcpy`.

For the selected row, the map begins at `+0x80`, and the tracked count is loaded from `+0x98`. The nonzero branch returns `0x13c` when count is greater than 10 *before* the subsequent inner-key lookup, so an attempted overwrite also encounters the guard. In the compact representation, a found entry writes the supplied word at entry `+0x18` (`0x3c1ab7b`); an absent entry is handed to `0x4549b40`, whose selected normal path increments count and copies a 32-byte record. In the tree representation, the selected search uses a 20-byte `memcmp`; an empty-root insertion requests `0x140` bytes, writes a 20-byte key and an eight-byte value, checks the local node bound of 11, and increments the tree count. Existing-tree splits and all map invariants are not recovered.

For zero, the tree path calls `0x3901f10`. A selected equal-key path calls `0x35b5a50` and then decrements the tree count; the empty or exhausted-search paths return without that decrement. The compact path treats a missing lookup as success; a selected found-key path calls the ring-shift helper and decrements the tracked count. The tree-to-compact predicate checks the sentinel and count below 32 after a zero-path tree removal. The reverse compact-to-tree condition includes count at least 64. Given a stable, consistent count, the earlier nonzero `>10` check excludes that latter path from the selected ordinary nonzero operation; other writers or malformed state can still produce representations outside that assumption. The two imported slots statically name `memcmp` and `memmove`; the packet does not assume runtime interposition is impossible.

Normal selected returns use inner word `0x1a2` and outer byte `0x0e`; errors propagate with outer byte `0x0f`. Allocator, bounds, unwind and nonempty-tree repair continuations exist and are not modeled as normal action failures. No rollback, persistence, or complete semantics for a malformed container are claimed.

### Historical lead and release separation

The retired packets `research/work-items/RE-010-exchange-handlers/README.md` and `research/work-items/fees-approve-builder-94/README.md` at repository commit `3324e50333042b391312515e542279ca21f63dc8` concern node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. They report #94 dispatcher `0x2759240`, user arm `0x275a048` calling `0x1e60a90`, system arm `0x2759360` calling `0x1e64620`, shared gate `0x2758330`, and writer `0x37459e0`. These are #94 coordinates and historical claims, not #115 boundaries. For #115 the table entries, names, calls, FDE records, status strings, checks and writes above are independently read from the authenticated #115 ELF. The old packet's success `0x186` and selected failure words, including `0x127`, `0x12a` and `0x12b`, are not reused as #115 values. The different callers and builds are not claimed to be byte- or behavior-equivalent.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Source-build hashes, compiler/linker settings, raw and relocation-normalized source comparisons, whole-ELF equivalence, complete helper/data closure and runtime behavior: **not yet measured**. All retained windows and bodies are raw and unmasked. The generator records 18 selected indexed FDEs, 70 windows, 32 direct calls, eight direct jumps, ten RELATIVE indirect calls, five imported call sites, 67 conditional branches and seven status-to-text mappings. These counts describe this selected evidence, not whole-component coverage.

The generated vectors contain 18 system predicate scenarios, five conditional user-word scenarios, seven caller scenarios and eight text-prefix scenarios. They are synthetic models of the selected static predicates, not execution or emulation of the node; the user-word scenarios assume the decimal helper produced the specified word. Missing-row scenarios assume the measured spare-vector-capacity path and successful hash-table operations; `outer_row_inserted_before_value_check` records the selected local insertion, not durable state. These vectors do not establish rollback, real market state, or the complete parser grammar.

## Results and limitations

The focused unittest module passed 49 tests with no skips, including wrong digest, modified window bytes, invalid FDE/index relationships, corrupt decoder tags and switch targets, corrupt status targets, malformed relocation and instruction forms, invalid address ranges, `SHT_NOBITS` exclusion, numeric/count boundaries, and the selected outer-row growth and allocation failure branches. Two generator runs with different hash seeds and time zones were byte-identical; generation and the focused test module also passed with binutils absent from `PATH`. Artifact/signature verification and catalogue consistency passed separately. No component gate is requested; `action-dispatch` remains 0/4.

Remaining questions include the actual wire-decoder-to-dispatch handoff, full preflight behavior and caller flag cleanup on unwind, the summary helper's exact inputs and units, decimal parsing and rounding, outer hash-table growth and allocation-failure cleanup, nonempty tree splits and repair, cleanup and rollback, and runtime relocation bindings. The next concrete question is to trace a successful user decimal-helper result into the gate with independent #115 examples and establish rollback after outer-row growth failure before implementing these paths in Rust.
