# RE-021: revision-9 read-call handler and borrowed precompile lookup

Raw revision bytes 9 and 10 select a separate read-call handler that installs the mode-2 borrowed precompile registry and probes a full 20-byte key before local gas and checkpoint handling, making this route reconstructible when its frame key and prerequisite conditions are known.

- Component ID: `evm`, RE-021 continuation of the unresolved lookup in `RE-021-blake2b-compress-94`; RE-021 is not a new row in the official task table.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead, with no reference code copied.
- Claim status: byte sequences, FDE records, encoded branch destinations and RELA entries are observations. Function names, handler structures, account/journal roles and normal-return connectivity are inferences. The builder-input-to-frame-key transformation, live registry contents and seed values, wider helper effects, and full EVM execution are unresolved.
- Scope included and excluded: one revision-9/10 read adapter, callback constructors, registry handoff, selected account/value operations, borrowed lookup and local result branches. Prior standard registry, dispatch, BLAKE2b, rollback, allocation and database helpers are cited boundaries, not newly owned bodies. Node #115, visor, captured execution, networking and chain actions are excluded.

## Reproduce

From the repository root with the authenticated artifacts present and Python 3.12:

```sh
python3 tools/evm_read_precompile94.py --out research/work-items/RE-021-evm-read-revision9-94
python3 -m unittest tests.test_evm_read_precompile94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For a deterministic regeneration check, replace each placeholder with a distinct empty temporary directory:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/evm_read_precompile94.py --out <tmp-dir-a>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/evm_read_precompile94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

Python 3.12.3 and GNU objdump 2.42 were available for this analysis. Objdump was used only to read instructions, never to construct a generated count, table or address list. The generator and tests use the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; neither launches external tools nor executes target bytes. They authenticate the complete artifact before ELF parsing, exclude SHT_NOBITS from file-backed address reads, and use actual FDE intervals. A deliberately restricted x86 byte-shape walker is adapted from the MIT RE-021 runtime work; the bounded exception call-site parser is adapted from the MIT installation work. They are not general-purpose disassemblers or exception interpreters. Generation writes only the thirteen evidence files; this README and the manifest are authored separately.

## Evidence

All addresses below are linked ELF virtual addresses. Ranges are half-open. `functions.tsv` supplies the file offsets, FDE/CIE/LSDA coordinates, lengths and hashes for each of the twelve selected bodies; `unwind-records.json` retains their original FDE and CIE records. `instructions.tsv` retains each linearly decoded byte shape and original bytes, while `control-flow.tsv` records direct and indirect control shapes. `semantic-windows.tsv` retains the bytes of the bounded observations below. A linear walk and an FDE interval do not prove reachability, all instruction semantics, or complete function coverage. Exception call-site ranges and landing-pad offsets appear in `exception-sites.tsv`, with their encoded prefixes in `exception-prefixes.json`; action chains and catch-type semantics are not decoded.

### Revision, callback and registry handoff

| Step | Evidence | Observation and bounded interpretation |
| --- | --- | --- |
| Builder | `0x2446ac0..0x2447970`; calls at `0x2446cbb` and `0x24472c2` | Passes the revision byte to `0x2461390`, prepares a context and handler, checks preparation results, and calls `0x25134e0`. At `0x244706a..0x244708c` it writes byte 1 at environment `+0x294` and copies the 20 bytes addressed by its incoming RDX argument to environment `+0x295`. |
| Revision constructor | `0x2461390..0x2464bc3`; relative table at `0x3e28b8` | Inputs 9 and 10 both branch to `0x2461a4f`; normal construction calls `0x2790e20` at `0x2461aa4`, calls `0x2798a10` at `0x2461c68`, and stores canonical byte 9 at `0x2461c6d`. The common tail copies those blocks into the handler. |
| Preexecution factory | `0x2790e20..0x2790fd6`; `0x2463494..0x24634c4` | The first returned callback pair contains vtable `0x56becc0`; its slot `+0x28`, RELA at `0x56bece8`, resolves to the already researched `0x276e2d0`. Its output lands at handler `+0x48/+0x50`, hence engine `+0x158/+0x160`. |
| Execution callback | `0x2798a10..0x2798f75`; `0x2463515..0x246352f` | The third callback pair uses vtable `0x56c1270`; the common tail copies it to handler `+0xe8+0x20/+0x28`, hence engine `+0x218/+0x220`. Its `+0x28` slot relocates at `0x56c1298` to `0x276d490`. |
| Postexecution callbacks | `0x2461c32..0x2461c60`, `0x24634ea..0x2463515`, `0x244f550..0x244f567`, `0x244f570..0x244f6b3` | Handler offsets `+0xc8/+0xd0` and `+0xd8/+0xe0` receive vtables `0x56a6ff8` and `0x56a7028`. Their `+0x28` relocations resolve to `0x244f550` and `0x244f570`. The first passes the result pointer and length `0x90` to the `memcpy` GOT slot; the second operates on the context and resets its byte at `+0xb8` to 5 before further cleanup/reset helpers. |
| Registry publication | `0x25134e0..0x2515499`, especially `0x2513533..0x2513605` | Following a tag-5 preparation result, the executor invokes the preexecution slot, calls `0x25b6b20`, extends the set at context `+0x80` through external helper `0x26b8980`, and copies the five-word factory value to context `+0xe8`. |
| Address-set handoff | `0x25b6b20..0x25b6c96`; borrowed arm `0x25b6c25..0x25b6c3d` | A zero first word selects a borrowed registry. The helper passes its associated set at borrowed object `+0x28` to a clone helper and copies one additional word. The other arm has its own iteration path. |
| Frame callback | `0x2513698..0x2513708`, `0x276d490..0x276d507` | After additional tag checks, the executor requires environment variant 1, calls the external frame constructor through slot `0x5774588` (RELA `0x4e91cb0`), checks its result for null, and invokes execution vtable `+0x28`; `0x276d490` calls `0x2789db0` at `0x276d4a0` and later releases its input. |
| State and lookup | `0x2786dd0..0x278745a`, `0x2788500..0x278870f`, `0x2789db0..0x278b402` | Account/code hydration precedes the checkpoint, value handling and registry lookup described below. The backing database and allocator methods remain external boundaries. |

The revision table is generated directly from twenty signed relative entries. Following the normal fall-through code to the first canonical-byte store gives the groups below; the tool rejects an intervening unconditional or indirect jump, and the generated table retains every entry and its raw four bytes. Allocation failures and exception paths can prevent any normal store. No historical fork names are assigned.

`allocation-checks.tsv` separately matches each immediate argument, indirect call, `test` and zero-branch in this case and its two callback constructors. The revision-9 case has six such checks, the preexecution constructor four, and the execution constructor eleven; each passes 16 as the immediate argument. For example, the null branch at `0x2790e3f` goes to `0x2790f38`. These are allocation-shaped observations; their cleanup and terminal effects are not presumed from the branch target alone.

| Raw input byte | Canonical store byte |
| --- | ---: |
| 0, 1 | 0 |
| 2, 3 | 2 |
| 4 | 4 |
| 5 | 5 |
| 6 | 6 |
| 7, 8 | 8 |
| 9, 10 | 9 |
| 11 | 11 |
| 12, 13, 14 | 12 |
| 15 | 15 |
| 16 | 16 |
| 17 | 17 |
| 18 | 18 |
| 19 | 19 |
| 20 through 255 | 255 on the default normal path |

### Account and code input boundary

At `0x2786dfb`, `0x2786dd0` calls external helper `0x27c4370` with context `+0x30` and a 20-byte key. If the first returned word is zero, it uses the returned pointer, tests bit `0x10` in its byte at offset `-8` and clears that bit if set. On the other branch it passes the same key to backing helper `0x37d0fb0` with a database object offset by `0x20`; subsequent insertion uses a `0xd0`-byte stride in the context's account-shaped table. Before returning tag 5 with a pointer and flag, this path calls `0x27c53f0` with context `+0x80` and the key. The selected branch at `0x2787342..0x278739b` appends a tag-0 record containing the 20-byte key and returns flag 1; the other branch returns flag 0. The cache and journal roles are inferred from these byte operations, not an assertion that the external helpers are fully known.

`0x2788500` adds a distinct code-input boundary:

| Predicate | Observed action |
| --- | --- |
| Account-loader tag is not 5 | Copy its result to the output and return. |
| Account field's 32-bit tag is not 4 | Keep the existing field and return the account pointer and flag with tag 5. |
| Field tag is 4 and account bytes `+0x68..+0x87` match the two file-backed 16-byte constants | Call `0x26b0730`, store a tag-1 field and return tag 5. |
| Field tag is 4 and the 32 bytes differ | Pass the bytes to external code helper `0x37d13c0` using the database object at `+0x928`. If its returned first dword is 4, call `0x324a070` for a fallback; otherwise copy the returned 64 bytes into the field. |

`code-hash-constants.tsv` retains the exact compared chunks, from VAs `0x206160` and `0x204be0`, and their file offsets. Concatenated in comparison order they are `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`, matching the conventional Keccak-256 digest of empty bytes. Calling the field an empty-code hash is an inference; the local comparison and branch are observed. No behavior of the backing helpers is inferred beyond the values this caller tests.

### State, lookup and local failure branches

The call frame uses its 20-byte field at `+0x60` as the account hydration and lookup key. The depth word at context `+0xa8` is compared with `0x400`. A normal hydration result has byte tag 5; account result tag 3 additionally reads a 20-byte field at account `+0x28` and invokes the account loader. On the proceeding branch, `0x2789eb3..0x2789f1f` increments depth and appends an empty journal frame. For input value tag 0, the four limbs at frame `+0x08..+0x27` are tested for zero. On the nonzero route, the body loads account state, conditionally records tag 2 and sets flag bit 4, performs four-limb debit and credit, and appends a tag-3 record containing two 20-byte fields and four limbs. The tags and offsets are observed; the account, balance and journal names are inferred.

The scheme byte at frame `+0x9e` equal to 6 bypasses precompile lookup. Otherwise, a zero context word at `+0xe8` selects the borrowed registry pointer at `+0xf0`; a nonzero word selects a separate owned-map branch. In the borrowed arm at `0x278a75b..0x278a879`, a zero item count misses; otherwise the code hashes four overlapping little-endian words of the 20-byte key with process and map words, compares a seven-bit fingerprint against 16 controls, and checks all 20 key bytes before taking a hit. A control equal to `0xff` ends an unsuccessful probe; the successive group advances are 16, 32, 48 and so on, masked by the table mask. The hit at `0x278a92f` passes the resulting value to the shared dispatcher through slot `0x5774e30`, whose RELA addend is `0x4ea2df0`. A miss branches to the ordinary account/code route at `0x2789f44`. The process seed is not a file-backed constant and no real bucket position is inferred.

At that fallback, `0x2789f79` reloads account/code by the same 20-byte key. A non-5 loader tag goes to the outer-error path at `0x278a6d1`. If the subsequent code field has tag 4, `0x2789fcd` calls the default-code helper; other tags go to the code-variant jump table at `0x278a71c`. The remainder of ordinary bytecode execution is outside this packet's interpretation.

| Condition | Local observation |
| --- | --- |
| Builder or executor preparation does not produce tag 5 | The corresponding error/result path is taken instead of the next normal stage; see `0x2447196..0x24472af` and `0x2513533`, `0x2513634`, `0x2513690`. |
| Frame-constructor return is null | `0x25136cf` branches to `0x25150f3`; its allocation and terminal effects are outside the bounded interpretation. |
| Depth is greater than `0x400` | Returns local status byte `0x11` before the checkpoint. |
| Initial account/code load or the tag-3 secondary account load returns a non-5 tag | Copies the returned error and takes the outer result path before checkpoint creation. |
| Nonzero value, debit underflows | Sets status `0x12` and invokes the checkpoint rollback boundary at `0x278a8e3`. |
| Nonzero value, credit overflows | Sets status `0x5f` and invokes that same rollback boundary. |
| Borrowed precompile result word 0 nonzero and word 4 cost at most input gas | Subtracts cost, sets status `0x02`, and decrements depth. |
| Word 0 nonzero and cost exceeds input gas | Releases the returned value, sets status `0x53`, and calls the rollback boundary. |
| Word 0 zero, low bit of word 1 set | Returns the outer error form with byte tag 4 and bypasses this function's local rollback branch. |
| Word 0 zero, low bit of word 1 clear, word 2 is `0x8000000000000000` | Sets status `0x53` and calls the rollback boundary. |
| Other ordinary error word 2 | Sets status `0x60` and calls the rollback boundary. |

The debit/credit rollback calls at `0x278a8e3` and the ordinary result rollback call at `0x278afa9` target `0x2787af0`, whose body belongs to earlier work; these observations do not by themselves establish whole-transaction atomicity. Error handling after the checkpoint can take other paths too, so the table is not a claim that every failure follows the listed rollback edge.

For the outer-error form returned by the selected frame callback, the executor compares its first word with 4 at `0x2513730`. Equality reaches `0x2513959`, copies the payload and returns the sentinel `0x8000000000000002` through `0x251375f`; non-equality enters another path at `0x251396a`. The builder calls the postexecution copy and context reset callbacks before examining the result. `copy-symbol-relocation.tsv` records the symbol-bearing GOT relocation and dynamic symbol bytes for `memcpy`; under normal symbol resolution, `0x244f550` copies all `0x90` result bytes unchanged. If cleanup returns normally without altering that separate result buffer, the builder sees the same sentinel and the cleanup branches at `0x244736e..0x244759c` write byte 0 to its output at `0x24475a0`. External cleanup effects, aliasing and non-sentinel result semantics remain open.

### Connection to the earlier address-09 evidence

Prior PR #1373 identifies `0x276e2d0` as producing a borrowed mode-2 registry whose constructor-derived entries include the tag-0 value for address 09; it also identifies shared dispatcher `0x4ea2df0` and its tag-0 indirect call. The existing [compression packet](../RE-021-blake2b-compress-94/README.md) binds that value's callback to `0x4e9d2a0` and the BLAKE2b compression implementation. This packet supplies a distinct revision-9/10 caller and inline lookup body, without selecting those previously owned functions.

The combined path to that callback is conditional: the factory and preceding helpers must return normally, the borrowed registry and hash-table invariants must hold, the frame's 20-byte lookup key must be address 09, scheme 6 must not bypass lookup, and earlier account/value guards must permit lookup. The bytes selected here show the builder's incoming address copied to the environment and the subsequent frame field used for lookup, but do not trace the intervening transformation by external `0x4e91cb0`. Consequently they do **not** prove that a particular builder argument becomes the address-09 frame key or that a live node selects this route. Prior constructor-derived membership is not a captured memory dump.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker flags, independent rebuilds, normalized comparisons, helper/data closure, behavioral comparison and whole-ELF equivalence are **not yet implemented/measured**. No normalization masks or executable-byte transplantation are used.

The focused Python suite models the recovered lookup and result predicates using explicitly synthetic inputs; it does not execute captured instructions. It checks all 160 single-bit alterations of the 20-byte key, group wrap and empty/deleted controls, a hash calculation with arbitrary seeds, and gas equality/overflow, fatal-bit and ordinary-error boundaries. Corruption controls cover the full target digest, both ends of every selected semantic window, FDE lengths and index membership, NOBITS/ambiguous/out-of-range reads, relocation type/addend and the copy symbol, switch-table bytes, unsupported/truncated byte shapes, a changed allocation null test or invalid branch destination, both code-hash constant chunks, and the exception-table header. Generated files are also compared byte-for-byte against a fresh in-process extraction.

Validation in the stated environment: 23 focused tests passed with zero skips under an empty PATH; two independent CLI generations under different hash seeds and timezones were identical under `diff -r`. Artifact verification and `tools/catalogue.py --check` passed. The full repository suite, hosted CI, containers and captured node execution were not run.

## Results and limitations

`summary.json` reports 12 selected FDE intervals, 36,841 selected bytes, 6,914 linearly decoded byte shapes, 1,539 control records, 66 semantic windows, 20 revision table entries plus one default range, 21 allocation null checks, 2 code-hash chunks, 7 relative and 1 symbol-bearing relocation, and 386 exception call-site rows. These are counts for this selected corpus, not denominators for the node or component. Helper calls, alternate dynamic callbacks, exceptional action chains, runtime seeds, live state, all call variants and complete transaction behavior remain open.

The existing EVM progress gate remains 0/4. The first COMPONENTS task covers private fork boundaries and state-transition inputs more broadly than this bounded route; this packet does not satisfy that full gate or claim a complete node reconstruction. The selected FDE starts were checked against the checked-out research evidence and the supplied open/merged PR inventory; the available local `origin/main` snapshot is the stated source commit. No live public refresh was performed because networking is outside this run's authorization.

Next question: without reclaiming another contributor's functions, establish the caller-produced frame key and its address-09 provenance across the opaque frame-construction boundary, then validate the remaining database and call-result boundaries against target-grounded fixtures.
