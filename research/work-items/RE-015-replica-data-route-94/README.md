# RE-015: configuration-rooted replica command data route

This packet distinguishes the sentinel-selected and configured `replica_cmds` path templates, then maps a matching-layout pending-record route through its name gate, field emission and guarded buffer drain, so these reconstruction choices no longer have to be collapsed into one generic path.

- Component ID: `constants` (RE-015), with downstream node data and serialization boundaries.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23`. The latter is an unlicensed source of search clues only; no reference code is incorporated.
- Claim status: observations are digest-bound byte windows, FDEs, relocations and call sites below; the descriptive role names, formatted renderings and matching-instance relationship are inferences; runtime scheduling and effects are unresolved.
- Scope included and excluded: twelve selected FDE extents, the bounded call-site excerpts needed to connect them to previously indexed functions, local byte predicates and exceptional branches. The pre-existing function bodies, formatter implementation, complete component, node #115, visor and target execution are excluded. No component gate is requested.

## Reproduce

From the repository root, with the identified artifact present, Python 3.12.3 on Linux x86-64 was used for:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/config_replica_route94.py --out work/replica-route-check-a
PYTHONHASHSEED=947 TZ=America/New_York python3 tools/config_replica_route94.py --out work/replica-route-check-b
diff -r work/replica-route-check-a work/replica-route-check-b
for f in work/replica-route-check-a/*; do cmp "$f" "research/work-items/RE-015-replica-data-route-94/${f##*/}"; done
(cd research/work-items/RE-015-replica-data-route-94 && sha256sum -c MANIFEST.sha256)
python3 -m unittest tests.test_config_replica_route94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

The generator checks the full input size and SHA-256 before parsing. It imports the repository ELF and FDE parsers, rejects non-file-backed or ambiguous virtual ranges, rejects duplicate or missing selected unwind-index starts, verifies each selected FDE and body digest, and reads selected instruction and data bytes directly. It makes no external program calls and never executes the captured binary. The two generation runs and the focused tests also passed with a PATH containing only Python. The formatting-token interpretation is the compatibility interpretation described in `research/work-items/RE-015-format-prefix-correction-94/README.md`, not a newly established implementation of the shared formatter. Output hashes are in `MANIFEST.sha256`.

## Evidence

All code coordinates below are linked ELF virtual addresses (VAs); the corresponding file offsets and complete selected bytes are in the generated tables. An FDE supplies an unwind range, not proof of a source-level function boundary. `instructions.tsv` is a closed byte-pattern length and transfer decode of the selected ranges, not a claim that every byte in an FDE is independently established as executable or that any unselected region was decoded.

The original `/static_config` and `/cham` template references and the `NvTestnet` fallback are already investigated in `research/work-items/constants/README.md` and the RE-015 prefix and instruction-start corrections. This packet selects neither those FDEs nor the existing name-table census. The prior packet identifies the configuration byte at object offset `+0x48` and the second string at `+0x18`; this packet independently observes the consumers below. The table slot `0x5668488` has an `R_X86_64_RELATIVE` addend of `0x2180ff`, length 9, and is slot 32 relative to `0x5668288`. Its bytes spell `NvTestnet`. The earlier fallback evidence identifies that slot index with the default byte. That connection is relied upon as prior evidence, not re-proved by a new name parser here.

### Selected FDE map

| Inferred role | FDE start | FDE end | Directly observed role in this packet |
| --- | --- | --- | --- |
| Replica entry | `0x474bd90` | `0x474bf96` | Branches on an input flag and mode, supplies the 12-byte key, calls the constructor. |
| Path and liner constructor | `0x4b307c0` | `0x4b30c2b` | Chooses a base template, formats a child path, invokes an existing initializer, copies output fields. |
| String adapter | `0x4b6ef00` | `0x4b6ef14` | Loads a string-like pointer and length and tail-calls a shared formatter. |
| Indirect string adapter | `0x45b0200` | `0x45b0217` | Loads a string-like object through an additional pointer and tail-calls the formatter. |
| Parent finalizer | `0x1d3aa70` | `0x1d3ad06` | Calls the pending-record drain on the parent and then releases parent fields. |
| Pending-record drain | `0x4760b00` | `0x4760cc9` | Clears a sentinel-bearing word, conditionally samples and passes a record to an existing function. |
| Sample helper | `0x4525250` | `0x4525453` | Samples values, updates an atomic word, and returns one word and two binary64 values. |
| Record writer | `0x45ba470` | `0x45ba67b` | Emits field calls and a newline before forwarding to an existing writer. |
| Block field writer | `0x4a85160` | `0x4a852e0` | Emits punctuation and delegates the field value. |
| Response field writer | `0x4a80e80` | `0x4a8105a` | Emits punctuation and either `null` or calls the external value helper. |
| Liner cleanup | `0x4b20250` | `0x4b2030d` | Tests sentinels, drains an embedded buffer, frees state and calls `close`. |
| Buffer drain | `0x4b71f10` | `0x4b72029` | Handles the write loop, interruption, partial progress and compaction. |

`functions.tsv` contains each actual FDE, CIE, LSDA, file offset, length and SHA-256. `transfers.tsv` preserves the transfer bytes and resolved encoded operands. Eight selected FDEs reference LSDA tables; their 53 protected call-site entries, landing pads and uninterpreted action indices are in `lsda-headers.tsv` and `lsda-sites.tsv`.

### Entry and path choice

At `0x474bdaf`, a zero input flag supplies the first-word sentinel `0x8000000000000000`; a nonzero flag reaches the time-format path with the 18-byte pattern `%Y-%m-%dT%H:%M:%SZ`. A nonzero formatting result goes to the existing failure helper and `ud2` at `0x474bf1a`. A successful path calls `0x4b307c0` at `0x474bec6` with the `replica_cmds` slice at `0x6fb7c5`. At the unsigned mode-byte boundary, 0 and 1 call the existing `0x4b2fda0`, and the same predicate is forwarded in the low byte of the sixth argument. `mode-cases.tsv` shows all 256 mode bytes for representative zero and nonzero flags; it does not assert that every value occurs at runtime. The existing mode helper receives a pointer to the value and is not reconstructed here, so the initial flag alone does not prove which first word reaches the constructor when the mode is 0 or 1.

The constructor compares the input's first word against the sentinel via signed-overflow flags at `0x4b307ec`:

| Observed input word / branch | Template VA | Complete template bytes | Arguments assembled at the call site |
| --- | --- | --- | --- |
| Sentinel | `0x1e79d4` | `0b2f746d702f6c6f63616c5fc0065f6c696e657200` | The key slice. |
| Any other word | `0x1fc527` | `c0062f646174612fc0012fc000` | Configuration object `+0x18`, the key slice, and the input string-like value. |

The configured branch obtains the configuration address through relocation slot `0x576e928` to `0x577b288`, checks the initialization word at `+0x50`, and passes the string-like field at `+0x18` through the selected adapter. The existing component evidence labels this field `cham_dir`; the observation here is its offset and argument position. The local branch calls the existing predicate at `0x144a070` through slot `0x576e9a0`. If it returns nonzero, the code calls `0x13c9a30` with the 10-byte operation text `remove_dir`; a nonzero return is followed by a vtable call. The helper body, actual filesystem operation and results are outside this packet.

Both branches meet at `0x4b3090d`. A separate 22-byte pattern `%Y-%m-%dT%H:%M:%S%.3fZ` and a time-validation helper precede the complete child template at `0x1f04e5`, bytes `c0012fc0012fc000`. The three descriptors refer to the selected base, the validated result and an earlier time-like sample; their full format implementations are not analyzed. A zero validation result reaches a 43-byte local-time-range diagnostic and `ud2` at `0x4b30b95`. Otherwise, the selected code calls the previously investigated liner initializer `0x13d1720` via `0x576eac0` and copies fields through output offset `+0x70`. Synthetic rendering examples and the exact data slices are in `templates.json`, `data-slices.tsv` and `summary.json`.

### Handoff, sample and name gate

The earlier-indexed caller contains a checked indirect call at `0x226edfb`: slot `0x5773b28` relocates to `0x474bd90`, with the output at stack offset `0x111a0`. Eight subsequent moves at `0x226f15d`–`0x226f1dd` transfer 120 bytes into a parent whose base is stack offset `0x1760`, at parent-relative offset `0x540`. The caller initializes parent `+0x5b8` to `0x8000000000000000` at `0x226f2b7`, then passes that parent and size `0x698` to a register-indirect call. The checked excerpts and five decoded call edges are in `boundary-excerpts.tsv` and `boundary-edges.tsv`; the eight matching offsets are in `handoff.json`. These excerpts are not a new analysis of the previously owned caller FDE `0x226c2d0`.

The selected consumer at `0x4760b00` stores the sentinel into its input at `+0x5b8` before checking the old first word. If the old word is the sentinel it returns; otherwise it copies the record, calls `0x4525250` with the 12-byte `crash_height` slice and later calls the existing `0x4b30260` at `0x4760c11`, passing parent `+0x540`. Normal and unwind paths both call the record cleanup helper. The two uses of `+0x540` and the intervening copies support a common layout, but do not establish runtime object identity, registration, scheduling or that a particular initialized instance reaches this consumer.

The separate selected parent finalizer at `0x1d3aa70` calls `0x4760b00` through relocated slot `0x5773038` at `0x1d3aa7c`, preserving the same parent argument. If that call returns normally, the wrapper conditionally decrements shared fields, later reads the parent field at `+0x540`, releases its allocation when nonzero, and calls a cleanup helper on `+0x558`. Its later `+0x5b8` check skips the vector-like release when that field still holds the sentinel. The LSDA records and the exceptional code beginning at `0x1d3ac63` show a separate path through the `+0x540` and `+0x5b8` cleanup helpers. These observations support a finalization ordering for this selected wrapper, while its caller and the identity of any initialized parent are still unresolved.

The sample helper uses three calls to `0x4ee3800`, two calls to `0x4ee3730`, an atomic compare-exchange adding `0x10` to a word at input `+0x568`, and an atomic exchange-add of `-0x10`; contested states use existing helpers. A nonzero incoming option calls the existing helper at `0x13c9e20` with integer `50`. It stores one word and two binary64 values in its output; the units and the external helpers' complete semantics are not established.

The consumer adds those binary64 values and compares the result with the binary64 constant `3.0` at `0x20aab8`. Only ordered values strictly greater than 3.0 enter the configuration-name check; less, equal and unordered values bypass it. The byte at configuration `+0x48` must be at most 31 and have its bit set in `0x803c6000`, admitting exactly 13, 14, 18, 19, 20, 21 and 31. Thus the prior default byte 32 bypasses this local gate; this says nothing about other uses of that name. If the additional once word is nonzero, another existing helper is called before the branches rejoin. Before the handoff, the returned first word is incremented with saturation at the maximum unsigned 64-bit value. `name-cases.tsv`, `duration-cases.tsv` and `counter-cases.tsv` are explicit synthetic evaluations of these byte-checked local predicates, not observations from running the node.

### Field output and cleanup

A previously indexed intermediate FDE contains a sentinel-guarded direct call at `0x4b306eb` to `0x45ba470`. A distinct call at `0x4b30694` reaches `0x4b20250` while replacing state; the two call-site excerpts do not establish the intermediate function's complete control flow. The record writer allocates an initial buffer with requested size `0x80`, writes `{`, and calls selected field helpers with `abci_block` (10 bytes) and `resps` (5 bytes). Those helpers conditionally write a comma, quotes and a colon around the name before delegating its value. In the second helper only, input byte `2` selects the literal bytes `null`; every other byte reaches existing helper `0x459d810`. On the selected success path the outer writer may add `}`, appends `0x0a`, and calls existing writer `0x13d12a0`. On field error it releases its temporary buffer and calls `0x45be9d0`; allocation and unwind paths have separate helpers. The complete values and downstream writer semantics remain boundaries.

Cleanup at `0x4b20250` checks the outer and embedded sentinels. For a present embedded buffer it calls `0x4b71f10`, frees the buffer when its stored allocation field is nonzero, and calls the relocated `close` symbol. The drain returns immediately when its active byte at `+0x18` is nonzero or length at `+0x10` is zero. Otherwise it calls the relocated `write`, retries a `-1` result only when the relocated errno accessor returns 4, and stops on zero or any other error. After partial progress, it shifts the remaining bytes with relocated `memmove` and updates the stored length. The guard byte is cleared after each returned call. Bounds-failure and unwind blocks are also retained in the selected range. `buffer-cases.tsv` models supplied results only; it performs no system calls and does not predict actual I/O.

`cfg.tsv` records 23 bounded reachability propositions over decoded selected-FDE instructions. It assumes each call returns normally, considers both conditional edges feasible and stops at indirect jumps, returns and traps; it does not model exceptions or prove feasibility. `contracts.tsv`, `data-refs.tsv`, `relocations.tsv` and the raw byte columns provide the direct observations behind the branch descriptions.

## Implementation and comparison

Independent Rust reconstruction: not yet implemented. Build scope, Cargo lock, compiler/linker settings, two-build comparison, normalized masks, call-target/data/relocation closure and whole-ELF comparison: not yet implemented or measured. No runtime fixture, captured-node test or external I/O is claimed. The synthetic tables and focused tests exercise boundary decisions and reject corrupted input, but cannot establish target equivalence.

## Results and limitations

The bounded dataset contains 12 selected FDEs and 5,177 FDE bytes, 1,211 decoded instruction-length records, 274 transfer records, 36 checked byte contracts, 7 boundary excerpts, 5 boundary call edges, 26 checked relocations, 10 data slices, 3 complete template byte sequences and 23 CFG propositions. The 23 focused tests passed with no skips, including altered image hashes, selected bytes, duplicate unwind starts, an LSDA header, a relocation expectation, instruction and address bounds, all name and response bytes, threshold and saturation boundaries, and partial-write controls. Two differently seeded and time-zoned generator runs produced identical bytes with no binutils on PATH. These are the only denominators claimed; they are not a node-wide function census.

The caller and intermediate FDEs are prior-work boundaries, their indirect runtime state and the identity of the producer and consumer instances are unresolved, and no selected-path behavior was dynamically observed. The full RE-015 component remains incomplete and its 0/4 gates remain unchanged. Next question: can the registration and state-transfer chain between the initialized parent and the `0x4760b00` consumer be bound without taking ownership of an already-covered FDE or assuming runtime execution?
