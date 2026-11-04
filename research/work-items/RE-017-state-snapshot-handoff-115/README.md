# RE-017: trace the owner snapshot result through state serialization

This packet identifies a previously unowned owner-to-snapshot path, shows how serialized and copied state form the returned record, and maps the owner's subsequent protected bucket and counter updates.

- Component ID: `abci`; bounded RE-017 loader-adjacent work related to RE-009 state and snapshots.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is an unlicensed navigation clue only, and no reference code is copied.
- Claim status: target bytes, relocations, selected transfers and exception-table ranges are observations. The object meanings and data-flow relations below are conditional static inferences, not observed runtime executions.
- Scope included and excluded: an owner entry and two adapters, its direct and scheduled snapshot paths, callback replacement, selected guarded serialization, copied regions, owner bucket/counter updates, return, selected failures and unwind edges. The earlier loader, clone, scheduler internals, helper internals, process entry, other serializers, full block execution and state-root computation remain boundaries.

## Reproduce

Run from the repository root with `artifacts/node/115/hl-node`, `tools/elf_index.py`, and `tools/fde_extents.py` present. The generator checks the full input digest before creating output, imports the shared ELF and FDE/ULEB parsers, reads ELF bytes directly, and invokes no external program. It does not execute either binary. The following two relative output directories must be initially empty:

```sh
python3 tools/abci_snapshot_handoff115.py --out research/work-items/RE-017-state-snapshot-handoff-115
python3 -m unittest tests.test_abci_snapshot_handoff115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=7 TZ=Etc/UTC python3 tools/abci_snapshot_handoff115.py --out .re017-snapshot-a
PYTHONHASHSEED=984 TZ=Pacific/Honolulu python3 tools/abci_snapshot_handoff115.py --out .re017-snapshot-b
diff -r .re017-snapshot-a .re017-snapshot-b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-state-snapshot-handoff-115 .re017-snapshot-a
(cd research/work-items/RE-017-state-snapshot-handoff-115 && sha256sum -c MANIFEST.sha256)
```

The optional historical control below requires the separately authenticated #94 artifact. It performs additional checks before generating the same #115 files and is not required by the default command:

```sh
python3 tools/abci_snapshot_handoff115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out .re017-snapshot-historical
diff -r .re017-snapshot-a .re017-snapshot-historical
```

The local run used Python 3.12.3 on Linux x86-64. GNU objdump 2.42 was used only for human inspection; neither the generator nor tests invokes it. The two regenerations and focused tests were also run with a PATH containing Python but no binutils. Generation has no network, target execution, key or chain side effects. The manifest covers this README and all generated evidence files.

## Evidence

Coordinates below are linked ELF virtual addresses before runtime rebasing. Tables also preserve file offsets, original bytes and selected FDE, CIE and LSDA coordinates. `functions.json` contains the complete selected unwind-range bytes and their individual hashes, but an FDE range is not a source-level function-boundary proof or a whole-node function census. `transfers.tsv` decodes only selected fixed instruction forms; a slot is an address of an indirect binding, not its observed runtime value. The relative relocations and imported `memcpy` symbol are context anchors only and do not claim ownership of shared GOT entries.

### Route and object handoff

| Selected FDE start | Observed role on the selected route |
| --- | --- |
| `0x5648a30` | Passes its owner input through two adapters, retains the five-word snapshot result, updates owner guard/bucket/counter fields and returns the retained result. |
| `0x4e47ca0`, `0x4f279d0` | Selected guarded and trace adapter paths construct and forward a tuple containing that owner pointer to `0x4fc2330`. |
| `0x4fc2330` | Reads an owner pointer from its input, forms owner `+0x6b0` as the context argument and calls `0x59ebeb0` at two distinct sites. It later returns five words after a protected region and helper boundaries. |
| `0x59ebeb0` | With a non-null TLS pointer, compares a TLS-derived address with its second input; the equal path builds the snapshot directly, and the unequal path calls the scheduler adapter. A null TLS pointer takes a separate helper boundary. |
| `0x59ea8a0` | Captures the context, supplies callback address `0x5669160` to an opaque scheduler boundary, and reads the captured result after its local status decision. |
| `0x5669160` | Clears and checks the captured context, calls the builder, replaces five captured result words and exchanges the status word with 3. The builder's selected LSDA landing rejoins replacement. |
| `0x5444fa0` | Calls the guarded wrapper, copies three state regions, assembles a `0xb0`-byte record and returns its pointer together with four other words. |
| `0x4e48ee0` | Chooses a direct or TLS-instrumented guarded call to `0x4e36140`, with diagnostic/cleanup paths also present. |
| `0x4e36140` | Reads state `+0x28`, passes state `+0x1108` and the word to an indirect helper, and calls `0x4e4b860` on the selected direct and instrumented paths. |
| `0x4e4b860`, `0x5480950` | Build a buffer, invoke the state encoder, check its result tag, and forward the resulting three-word buffer on the selected successful route. |

At `0x5648a30`, the incoming `rsi` owner is saved twice in a tuple and passed to `0x4e47ca0`. On the selected path where its check returns zero and its output flag is zero, that adapter passes owner `+0x130` and the tuple to `0x4f279d0`. If the mode byte at that adjusted pointer `+0x20` (owner `+0x150`) is zero, the latter directly calls `0x4fc2330` with the tuple. The other recorded trace-adapter call follows an instrumentation path whose helpers are not fully resolved.

At each inner owner call, `rdx` is formed as owner `+0x6b0`; both the direct builder and callback builder address context `+0x450`. Thus the selected path dereferences owner `+0xb00`, conditional on normal argument passing and no conflicting alias writes. Prior #115 loader-handoff and context-result packets describe a constructor that places a loader-fed expanded-object pointer at this same owner-body offset. If the input here points to that constructed owner, this path reaches that pointer. Equal offsets alone do not prove the two independently studied paths operated on the same runtime object, and the expanded pointer is not asserted to be identical to the original loader pointer.

The owner uses an atomic guard at `+0x6a8`. The fast acquisition attempts to add 16 only when bit 3 is clear and the unsigned old word is below `0xfffffffffffffff0`; a failed compare-exchange or a failed precondition enters an opaque boundary. Release uses atomic addition of -16. Its wake boundary is selected when `(old_word & 0xfffffffffffffff2) == 0x12`; an unwind path performs a corresponding release. This proves selected guard-word mutations, not a particular lock implementation or a block-state transition.

### Owner updates after snapshot construction

After the adapter returns normally, `0x5648a30` attempts an atomic byte compare-exchange from 0 to 1 at owner `+0xb50`. A failed comparison calls a separate boundary and continues without a local retry; its acquisition behavior is an assumption. The code forms a nonnegative numerator from earlier helper output, loads an unsigned divisor at owner `+0xb58`, and uses 32-bit division only when both operands fit in 32 bits, otherwise 64-bit division. A zero divisor would raise the processor's divide-error exception if that instruction executes; no recovery or runtime reachability is asserted.

For a nonzero divisor, let `q` be the unsigned quotient and `b` the prior word at owner `+0xb60`. If `q > b`, the selected path stores `q` at `+0xb60` and later resets owner `+0xb68` to zero. If `q <= b`, it skips that reset. Both paths later load `+0xb68` and increment it with saturation at the largest unsigned 64-bit value, then attempt to change the guard byte from 1 to 0; a failed comparison calls a separate boundary. Thus, assuming normal helper returns and no intervening writes to these words, a rollover path ends with counter 1 and a non-rollover path ends with `min(old_counter + 1, 2^64 - 1)`. After guard release the function copies the saved five-word result to its output. The division inputs' domain meaning, the helper side effects, and whether this owner is a loader-fed instance remain unresolved; these guard and bookkeeping writes are not proof of a block-state transition.

The rollover branch sets an auxiliary length word to 31. Its later negative-length branch calls a failure boundary and reaches `ud2` if that call returns; a null allocation joins the same failure boundary with alignment argument 1. The negative and zero length branches are not reached from the selected 31-byte setup if the staging word remains unchanged. If an owner-guard boundary unwinds, its recorded landing reaches a cleanup call for the saved snapshot result and then an unwind-resume boundary. This does not establish the behavior of the allocation, copy or cleanup helpers.

### Serialization and record composition

The guarded aggregate's first 24 output bytes come from the buffer result returned by `0x4e4b860`. Its next 24 bytes come from the indirect helper's result area; the final word is the explicitly saved state `+0x28` value. These statements require the shown calls to return normally. The helper slot and its relative relocation are recorded as an anchor, with runtime binding and helper semantics unresolved.

The builder then reads state `+0x28` again and calls through the slot whose dynamic symbol is `memcpy`. Assuming the symbol binds to the expected copy behavior, valid non-overlapping objects and no intervening conflicting writes, it places these source spans into a contiguous allocated region:

| State-relative source range, end exclusive | Destination-relative range, end exclusive |
| --- | --- |
| `0x1200..0x1a10` | `0x0000..0x0810` |
| `0x1b08..0x2318` | `0x0810..0x1020` |
| `0x2410..0x2c20` | `0x1020..0x1830` |

`copy-segments.tsv` derives the three ranges from the selected instruction operands. The builder also uses the beginning of the first copied span as the staging area for the `0xb0`-byte record. `record-layout.tsv` derives the following offsets from its store displacements and checked copy length:

| Record-relative range | Selected source or overwrite |
| --- | --- |
| `0x00..0x10` | Two words set to 1. |
| `0x10..0x28` | The three-word serialization result. |
| `0x28..0x30` | Immediate `0x8000000000000003`. |
| `0x30..0x38` | The allocation holding the three concatenated regions. |
| `0x38..0xa8` | If no intervening helper or alias changes the staging buffer, these bytes remain from state `0x1238..0x12a8` in the first copy. |
| `0xa8..0xb0` | The builder's later state `+0x28` read. |

The aggregate and builder read the state word at different sites and times. They are equal only if it remains unchanged between those reads; no atomic snapshot across the copies is established. The record-pointer result plus the aggregate's remaining four words form the five-word callback result on the normal builder return. The direct dispatcher contains the corresponding selected copy and record-assembly windows.

`0x4e4b860` initializes writer bytes with immediate `0x01000400`, calls `0x5480950`, and accepts the first result word only if it equals `0x8000000000000004`. The initial writer byte checked at `+0xb` is therefore 1. The named-mode prefix passes count 1 to one header helper, then, on selected success and mode checks, passes `exchange` with length 8, count 59 to another header helper, and `locus` with length 5; a later exact mode check gates `ctx` with length 3. Helper calls can change the writer mode, and their encodings are outside this packet. These literals and counts do not establish a complete wire schema, a state root, or successful durable storage.

### Selected decisions, failure and unwind paths

| Condition | Statically observed effect |
| --- | --- |
| Top-level guard acquisition or release compare-exchange fails | Calls the corresponding opaque guard boundary; the acquire-side code continues without repeating the compare-exchange locally. |
| Owner divisor is zero / quotient exceeds the saved bucket / quotient does not exceed it | The selected divide raises a processor exception if executed / stores the quotient and resets the counter before its later increment / preserves the bucket and increments the previous counter. The count increment saturates, under the stated no-intervening-write condition. |
| Rollover auxiliary allocation returns null | Joins the size failure boundary and reaches `ud2` if that boundary returns. The selected unchanged setup uses a 31-byte length; the separate negative-length failure is unreachable under that condition. |
| Owner selector at `+0x128` equals `0x3b9aca00` | The selected first dispatch site is used; the other selected path uses the second dispatch site. Both pass the same owner-relative context and both copy the five-word result through local staging on their respective normal paths. |
| Dispatcher TLS is absent / present with unequal comparison / present with equal comparison | Calls the missing-TLS helper / scheduler adapter / direct guarded builder, respectively. The scheduler's actual callback invocation is not established by passing a code pointer. |
| Callback input context is null, or its TLS pointer is null | Calls a diagnostic boundary and reaches `ud2` if the relevant calls return. The context slot was cleared before the null test. |
| Guard or aggregate check returns its selected nonzero result | Enters a diagnostic boundary. Other TLS branches and helper internals remain opaque; selected direct and TLS paths both contain a serializer call. |
| State encoder result differs from the accepted tag | The wrapper conditionally passes its buffer to a release-like boundary, supplies `state.rs:161:83` and the recorded unwrap diagnostic to a failure helper, and reaches `ud2` if it returns. |
| Either selected allocation returns null | The builder calls a size-specific failure boundary for `0x1830` or `0xb0`, then reaches `ud2` if that boundary returns. |
| Callback replaces an old result | For old word `w` at callback `+0x10`, let `M = 2^63` and `n = 1` when `w <= M`, otherwise `n = w - M - 1`. `n = 0` skips old-result cleanup, `n = 1` takes an atomic-reference-count branch, and larger values take a vtable-based branch. This arithmetic alone does not make arbitrary words valid objects. |
| Callback publishes | Five result words are stored before an atomic exchange sets callback `+0x38` to 3; old status 2 calls a wake-like boundary. The scheduler tests its corresponding stack status. If it is not 3, it calls a wait-like boundary and then proceeds to result classification without re-reading that status. |
| Scheduler classifies the result word | The same `n` arithmetic selects direct forwarding for `n = 1`, an opaque helper for `n = 2`, and a diagnostic path for other values. The helper may affect the returned register values; its behavior and the validity of forged tags are not inferred. |

`unwind.tsv` and `unwind-links.tsv` decode only the call-site ranges and landing coordinates, not personality or action-table semantics. Both owner dispatch calls are covered by a range landing at `0x4fc28f7`, where the selected instructions release the guard before the unwind-resume boundary. The serializer's encoder call is covered by a range landing at `0x4e4bbcb`, which conditionally passes the buffer to a release-like boundary before unwind resume. The callback's builder call is covered by a range with action value 3 and landing `0x56693a8`; if that landing is entered and its helper returns, the instructions rejoin old-result replacement with the second output word set to `0x8000000000000003`. If the scheduler later sees that word, its arithmetic selects the helper case. This is a static conditional handoff, not proof that a particular exception is caught or that a runtime callback was scheduled. The scheduler's own selected call-site landing performs cleanup and resumes unwinding.

### Historical clue and independent #115 observations

The retired #94 artifact is bound to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its checked call at `0x3272785` uses slot `0x57755a8`, whose relative relocation names `0x3273810`; the checked reference at `0x3273856` points to Location `0x56dfbf8`, with line 107 and column 37. The optional historical check authenticates and reads those original bytes. Separately, the authenticated #115 ELF has loader Location `0x64767a8` at line 123, column 37 and this packet's serialization-failure Location `0x649d9f8` at line 161, column 83, both resolving to `l1/src/abci/state.rs`. These facts do not transfer addresses, object layouts or behavior between releases.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile and compiler/linker comparison: not yet applicable. Raw or normalized binary matching, masks, helper/vtable closure, dynamic binding closure and whole-ELF equivalence: not yet measured. The recorded bytes are research evidence, not transplanted implementation code. No node or visor was executed.

## Results and limitations

`summary.json` describes 12 selected FDE ranges, 52 validated byte windows, 84 selected transfers, 71 operands, 3 relative relocation anchors, 1 dynamic-symbol anchor, 2 Locations, 4 literals, 3 copy segments, 9 record-layout rows, 120 LSDA rows and 36 selected call/LSDA links. These are packet-local counts, not coverage or completeness denominators. The focused suite passed 23 tests with zero skips, including corrupted digests and windows, changed transfers and operands, missing/duplicate FDEs and relocations, damaged dynamic-symbol names and bounds, fileless and out-of-range sections, corrupt LSDA records and Locations, callback tag neighbors, guard acquisition/wakeup boundaries, both divide widths, zero divisors and counter saturation. The tests do not execute target instructions.

No component gate or binary-equivalence claim is requested. In particular, reaching this entry from the loader-fed owner, actual callback scheduling, helper behavior, aliasing and concurrent writes, full encoder structure, persistent output, begin/action/end-block behavior and state-root inputs remain unproved. Next question: trace the top-level entry's caller and prove whether it receives the same captured owner instance produced by the loader-fed constructor, including the relevant lifetime and synchronization conditions.
