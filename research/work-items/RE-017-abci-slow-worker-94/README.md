# RE-017: slow ABCI worker construction, protected result replacement and completion

This packet traces two slow ABCI worker constructor arguments through the thread payload to distinct loop inputs and shows how a selected 40-byte loop result replaces a protected record, including creation failure and unwind continuations.

- Component ID: `abci`, RE-017.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. The lead supplies only questions, not implementation text.
- Claim status: static observations below are distinct from the inferences and unresolved identities. No component gate is requested.
- Scope included and excluded: ten previously unclaimed FDE extents, selected branch, transfer, layout, relocation and exception records, and a few explicitly marked instructions in the previously inventoried startup and receive-loop FDEs as boundary context. The original state-loader GOT and call site, the existing receive loop, the prior driver and its earlier task machinery are not re-owned. #115 and visor are separate targets.

## Reproduce

From the repository root on Linux x86-64, with Python 3.12.3 and the standard library:

```sh
python3 tools/abci_slow_worker94.py --out research/work-items/RE-017-abci-slow-worker-94
python3 -m unittest tests.test_abci_slow_worker94 -v
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_slow_worker94.py --out "$TMPDIR/abci-slow-worker-a"
PYTHONHASHSEED=91 TZ=Asia/Seoul python3 tools/abci_slow_worker94.py --out "$TMPDIR/abci-slow-worker-b"
diff -r "$TMPDIR/abci-slow-worker-a" "$TMPDIR/abci-slow-worker-b"
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-abci-slow-worker-94 "$TMPDIR/abci-slow-worker-a"
```

The output directories must initially be absent or empty. `MANIFEST.sha256` records hashes of all work-item files other than itself. The producer checks the full input digest before parsing, uses the shared ELF/FDE and variable-length integer readers, and accepts only uniquely file-backed allocated sections; NOBITS sections are excluded. It interprets selected fixed x86-64 byte patterns and ELF relocation/exception bytes, and never launches external programs or the target. Human inspection used GNU objdump 2.42; neither output counts nor addresses are parsed from it. No host path, timestamp, hash iteration order, binary execution, network or secrets enter the output.

## Evidence

All addresses below are ELF link-time virtual addresses, not runtime addresses. File offsets, exact bytes and full FDE hashes are in the generated TSVs. The ten FDE ranges come from actual CIE/FDE records, with an exact body hash for each; a range is not a whole-program coverage denominator. Each selected instruction has a pinned encoding. The byte windows cover those ten extents, but the branch table is selected rather than a claim of exhaustive control-flow decoding.

### Boundary and newly mapped functions

The [state inventory](../abci-state-inventory-94/inventory.json) records `0x22ae8a0` calling the previously inventoried `0x2275a10`; the [node inventory](../node-inventory-94/RESULT.md) records the latter calling the startup FDE `0x226c2d0`. The [original state link](../RE-017-abci-state-link-94/README.md) and [round-clock packet](../staking-round-clock-94/README.md) own the deeper Location-bearing loader chain. Separately, the same `0x2275a10` FDE contains the boundary instruction `0x2277292`, whose RIP-relative slot `0x5773b60` has a type-8, symbol-zero relocation to the newly studied `0x474abe0`. This is a possible static route, with intervening conditions and dynamic task scheduling unresolved. Its existence does not prove that the exact original loader executes or that its return is the worker input.

| Newly studied FDE | Selected role established by bytes |
| --- | --- |
| `0x474abe0..0x474b13b` | Uses the length-bound literals `slow abci block` and `node slow abci_state driver`; calls `0x43320f0` and tests the first output word. |
| `0x43320f0..0x4332768` | Requests a 168-byte payload and a 24-byte envelope, installs the worker table, calls the thread adapter, and constructs success or failure output. |
| `0x4ee4ab0..0x4ee4cab` | Configures thread attributes and calls imported `pthread_create` with entry `0x4ee48b0`. |
| `0x4ee48b0..0x4ee4aad` | Takes envelope words at offsets 8 and 16, releases the envelope, and calls the table word at offset 24 with the payload. |
| `0x433a350..0x433a5e1` | Invokes the prior receive-loop boundary `0x432e4d0` and writes the completion words. |
| `0x4340ae0..0x4340b53` | The table's drop entry; calls two cleanup boundaries and conditionally releases the completion reference. |
| `0x474a0f0..0x474a4e7` | Is called from the prior loop; two selected paths call the same protected dispatcher and copy its first 40 output bytes. |
| `0x4528a00..0x4528d25` | Acquires a guard at input base `+0x568` before choosing one of three TLS-dependent call paths, then releases it. |
| `0x4527ab0..0x4527d3e` | Acquires a guard at its input base `+0x568`, replaces the record at `+0x570`, and handles selected cleanup and unwind paths. |
| `0x4eeb8a0..0x4eeb8bd` | The thread builder's selected counter-failure helper. |

At `0x4332405`, the builder takes table `0x571cb68`. Its captured words are `0, 168, 8, 0`; relocations fill the first and fourth words with `0x4340ae0` and `0x433a350`, respectively. The builder puts the control pointer, payload pointer and table pointer in the 24-byte envelope. The thread entry loads envelope `+8` and `+16`, then calls table `+24`. The 168-byte payload and table's size/alignment words agree, but identifying the original Rust trait is an inference.

The selected previous receive loop is a boundary, not a newly claimed FDE. The [channel packet](../channel-locations-94/README.md) already describes its blocking receive and no-item return. New boundary instruction `0x432e67c` calls `0x474a0f0`. The wrapper's ordinary and TLS paths both call `0x4528a00`; they copy the first 40 output bytes to the caller. If the loop's comparison at `0x432e681` does not take the branch to `0x432e729`, the loop copies those 40 bytes and passes them at `0x432e6e0` to `0x4527ab0`. `protected-layout.tsv` records every load and store used for this copy. The loop obtains the dispatch base from its `+0x70` field and the replacement base from its `+0x78` field, each followed by a 16-byte adjustment. Those are distinct pointer loads: equality or object identity is not established.

`origin-layout.tsv` and `origin-operands.tsv` trace these two words further upstream. Under the selected normal allocation and copy path, `0x474abe0` saves its second and third arguments from `rsi` and `rdx` at stack offsets `+0x110` and `+0x118`. It copies that pair to the 128-byte record at offsets `+0x70` and `+0x78` and passes the record pointer as a stack argument to `0x43320f0`. The builder's six saved registers, return address and frame allocation account for its stack-argument displacement; its copies put those words at payload offsets `+0x98` and `+0xa0`. The relocated `memcpy` slot and the byte-pinned 168-byte copy bind the payload. The callback copies payload `+0x28..+0xa8` to its loop argument, so the two original argument words reach loop `+0x70` and `+0x78`, respectively. This follows the x86-64 calling convention and successful calls; it is not evidence that the words are equal or are the original loader's result.

### Selected branch and failure table

`decisions.tsv` contains the exact guard and adjacent conditional branch, file offsets, fall-through and computed destination for all 21 selected decisions. The following rows give their bounded interpretation.

| Guard or branch | Taken path | Other continuation |
| --- | --- | --- |
| `0x43323c8`, `0x433241f` | Null payload or envelope allocation reaches separate failure blocks `0x43325a5` or `0x43325b7`. | Continue preparing the respective allocation. |
| `0x43323f0`, `0x4ee48c7` | A nonpositive result after a locked increment reaches `0x43325e4` or `0x4ee4a2c`; the latter is `ud2`. | Continue the reference handoff. |
| `0x4ee4ad2` | Nonzero attribute-init result reaches `0x4ee4bda`. | Select the stack-size candidate. |
| `0x4ee4b12`, `0x4ee4b1a`, `0x4ee4b44` | A zero stack-size result reaches thread creation. A nonzero first result equal to 22 takes the `sysconf(30)` and alignment-mask retry; a different value takes `0x4ee4c24`. | A failed retry takes the separate cleanup route at `0x4ee4b46`. |
| `0x4ee4b93`, `0x4ee4bc7` | Zero `pthread_create` status selects the returned handle; a nonzero attribute-destroy result reaches `0x4ee4c45`. | Nonzero create status is shifted left 32 bits and ORed with 2 before attribute destroy. |
| `0x4332444`, `0x474af2e` | Adapter low bit clear selects builder success; a zero first builder output word selects `0x474b003`. | The failure arm stores a zero first word and the adapter payload; the caller uses the 22-byte `failed to spawn thread` literal and reaches `ud2` if its failure helper returns. |
| `0x4528a47`, `0x4527af3` | A failed atomic comparison for the respective `+0x568` guard goes through a separate helper. | On equality, execution continues directly. Both sites attempt to replace zero with 8. |
| `0x4527b4d` | With zero in the compare register, signed overflow selects `0x4527b80`; this happens for the 64-bit minimum signed word. | Other words take the old-record cleanup checks before reaching the copy. |
| `0x4528b4c`, `0x4527ba8` | A failed atomic release comparison goes to a helper. | The uncontended path continues after releasing. |
| `0x433a4a5`, `0x433a5d0` | Select whether the previous completion value needs its conditional cleanup before replacement. | Join at the completion stores when the guard permits. |

On the selected `pthread_create` paths, if the intermediate cleanup and attribute destroy return normally, the adapter returns `(rax, rdx) = (0, handle)` for status zero and `(1, (status << 32) | 2)` for a nonzero 32-bit status. This claim is limited to those paths; an attribute failure has separate handling. The default stack-size candidate is 16384 when the dynamic candidate is absent. The retry sequence is the recorded 64-bit add, subtract-one and bitwise-AND with the negated `sysconf` result; its behavior is not generalized to arbitrary page values or overflow.

### Protected replacement and unwind

For `0x4527ab0`, let B be its second argument and I its third. The function attempts a zero-to-eight atomic change at `B+0x568`. Its ordinary copy stores `I[0..16]`, `I[16..32]` and `I[32..40]` at `B+0x570`, `B+0x580` and `B+0x590`. An action-zero LSDA row covering the old-reference release call `0x4527b63` has landing `0x4527ca8`. If that landing is selected and its remaining helper returns, the exception continuation makes the same three stores, attempts the guard release and resumes unwinding. This is a conditional observation about replacement during cleanup, not a claim of transaction rollback or ledger-state mutation.

For `0x4528a00`, the TLS load and comparisons select `0x4677fd0`, `0x46a7ee0`, or `0x46b8350`. All are boundaries here. The three selected call ranges in `processing-lsda.tsv` have landing `0x4528cb8`, whose code attempts the atomic guard release before the unwind-resume boundary. The ordinary and alternate wrapper calls have separate LSDA coverage; only the latter has the selected local landing `0x474a45c`. No assumption is made that every exception takes a particular landing pad.

The callback's LSDA has a row covering `0x433a493..0x433a499` with landing `0x433a586`, action index 7, action bytes `0100`, type filter 1, next action 0, and a zero four-byte type entry. If the personality selects that landing and subsequent helpers return, the conversion helper's `rax` and `rdx` become the completion's `+0x20` and `+0x28` words. The normal return sets the former to zero and preserves the word originally read from payload `+0`. Both selected paths store 1 at completion `+0x18`, then decrement its reference count; cleanup of an existing completion is conditional. These words are observed, not named as a Rust `Result` or a ledger state.

### Inferences and unknowns

The literals and calling convention are consistent with a slow ABCI worker, and the atomic protocol resembles a lock protecting a result record. The reconstruction can preserve the shown sizes, byte offsets and conditional control flow without assigning source-level types. The shared record may be a status or measurement rather than application state. The loaded value's provenance, equality of the two loop bases, scheduling feasibility, full loop behavior and the called processing functions' state effects remain unknown.

## Implementation and comparison

Not yet implemented. There is no independent Rust component, Cargo lock, two-build comparison, normalized mask, helper closure or whole-ELF comparison in this packet. The `pthread_result` helper is a synthetic model of the pinned return-word arithmetic under its stated normal-cleanup precondition; it is not execution of the target. The tests use private copy-on-write mappings for corruption controls.

## Results and limitations

`summary.json` reports 10 selected FDE extents and 10 byte windows, 111 selected conditional branches or jumps, 21 adjacent guarded decisions, 31 selected references, 11 general immediate operands, 13 relocations, four worker-table words, 34 thread-layout sites, 56 protected-layout sites, 23 origin-layout sites and 17 origin operands, three length-bound literals, and 47 LSDA call-site rows across four selected tables. These counts describe the selected packet only; they are not component, function, branch or behavior coverage percentages.

The focused suite passes 26 tests with zero skips, including one opcode-byte and one displacement-byte mutation at every selected branch; each guard, reference and layout instruction is independently corrupted; digest, FDE, relocation, duplicate-slot, symbol, literal, exception-table and file-range controls are also exercised. The signed-minimum and thread-result boundary cases and constructor-argument copy model are synthetic checks of pinned predicates and offsets. Two isolated, differently seeded and time-zoned regenerations compare byte-for-byte, including under a Python-only PATH. Artifact verification and catalogue consistency pass; no repository-wide test suite, execution, network or hosted CI was run.

This is a bounded static path, not a complete ABCI implementation. In particular begin/action/end-block effects, state-root inputs, actual worker scheduling, the exact loader result identity, helper semantics, and binary equivalence remain open. The `abci` gate stays at 0/4. Next question: establish whether the two loop bases alias and trace the original loader result into the payload without re-owning the existing loader or scheduler bodies.
