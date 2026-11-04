# RE-010: the node 115 claim-rewards dispatch and state path

Node #115's `claimRewards` name maps to ordinal 5 and internal tag `0x8b`; a decoded outer action preserves the child pointer at the offset used by the nested dispatcher, and the selected handler moves qualifying quantities using a metadata-derived floor.

- Component ID: `action-dispatch` (RE-010), with the selected accounting and event callees needed to follow this action.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; investigative reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The latter is an unlicensed lead, not implementation source.
- Claim status: static observations for the recorded bytes, selected decoder route, call operands, relocations and storage instructions; the decoder-to-dispatch object handoff, container names and quantity meanings are inferences as identified below. No target execution or source equivalence is claimed.
- Scope included and excluded: one content-name-to-boxed-action route, the top dispatch and its selected wrapper, a separate parent-to-dispatch route that reaches the same handler, normal reward-row decisions and writes, selected balance and account updates, and event-collector branches. The handoff between the decoded box and dispatch, complete wrapper and parent preflight, general container balancing, other action arms, dynamic loader interposition, allocation failures and rollback are not completely recovered.

## Reproduce

From the repository root, with Python 3.10 or newer, the authenticated node artifact and a writable `TMPDIR`:

```sh
python3 tools/re010_claim_rewards_115.py --out research/work-items/RE-010-claim-rewards-path-115
python3 -m unittest tests.test_re010_claim_rewards_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-010-claim-rewards-path-115 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/re010_claim_rewards_115.py --out "$TMPDIR/re010-claim-a"
PYTHONHASHSEED=987 TZ=Pacific/Honolulu python3 tools/re010_claim_rewards_115.py --out "$TMPDIR/re010-claim-b"
diff -r "$TMPDIR/re010-claim-a" "$TMPDIR/re010-claim-b"
```

Use distinct empty directories for the two temporary outputs. The extractor first verifies the full artifact digest, imports the repository's ELF and FDE readers, and reads instructions, section contents, jump displacements, RELA records and dynamic symbol names directly. It checks complete selected FDE hashes and emits the twelve generated evidence files. No normalization masks are applied. It calls no external program and never executes the captured node. Manual investigative excerpts were checked with GNU objdump 2.42 on Linux x86-64; neither the generator nor the tests parse its output. The focused checks here used Python 3.12.3.

## Evidence

Addresses are linked ELF virtual addresses; offsets in the generated tables are zero-based file offsets. All ranges are half-open. `functions.tsv` contains each selected FDE's raw bytes, hash, FDE/CIE/LSDA coordinates and unwind index. An FDE is an unwind range, not by itself a complete original source function. Direct calls, the selected switch destinations, entry instructions and returns support the callable entries below; they do not identify original Rust files or all split cold paths. The 33 selected ranges are not a coverage denominator.

| Selected role | Node #115 range or site | Observation |
| --- | --- | --- |
| Top dispatcher | `0x54a2f90..0x54a39f8` | Tag `0x8b` selects interior arm `0x54a3584`, which calls the selected wrapper at `0x550ac60`. |
| Top selected wrapper | `0x550ac60..0x550b422` | After identity selection and two shared gates, the original 20-byte argument is passed to the handler at `0x54e3030`. |
| Parent | `0x551cb40..0x551d429` | Saves a 20-byte third argument, follows a child pointer at the fourth argument's `+0x18`, checks preflight results and calls the selected dispatcher. |
| Selector | `0x4e0fd10..0x4e10079` | Ordinal 5 targets `0x4e0fd5d`; that arm writes zero at output `+0x8` and `+0x18` and result word `0x1a2`. The intervening word is not established by this arm. |
| Dispatcher | `0x55faa80..0x55fbb49` | Tag `0x8b` selects interior arm `0x55fb3de`; its direct call at `0x55fb3e7` targets the separate entry `0x54e3030`. |
| Name/ordinal emitters | `0x4d81e00..0x4d843f2`, `0x3714e60..0x3715c43` | The first selected arm references `claimRewards`, `ClaimRewards` and `ClaimRewardsAction`; the second stores ordinal 5 twice. |
| Name matcher and content adapter | `0x4d67530..0x4d6861e`, `0x57aebd0..0x57aecda` | The selected length-12 branch compares all `claimRewards` bytes and writes result bytes `0x09, 0x05`; content tag 13 selects a path that calls it. |
| Envelope and action decoder | `0x56900d0..0x56916b1`, `0x4d3f940..0x4d42472` | The selected normal envelope carries ordinal 5 into the decoder's table; its selected arm checks the `ClaimRewardsAction` payload and stages tag `0x8b` in a boxed object. |
| Container decoder | `0x5707dd0..0x5708fbd` | One three-element content path calls the action decoder and places its returned box pointer into the result. |
| Outer content decoder | `0x56f81d0..0x56f9abf` | A separate three-element path retains that box pointer at output `+0x18`, before the outer action is boxed. |
| Handler and writer | `0x54e3030..0x54e3736`, `0x3c17fc0..0x3c18252` | A relocated slot links the handler to the separately indexed writer; the handler processes returned `(key, quantity)` pairs. |
| Lookup and iterator | `0x4717930..0x4717a03`, `0x4506370..0x45065c0` | The lookup compares 20-byte keys; the iterator has compact and tree paths and returns a key pointer and a value pointer. |
| Scales and quotient | `0x3c49360..0x3c49433`, `0x4217e60..0x4217f8b`, `0x63efec0..0x63eff7e` | Selected metadata bytes feed powers of ten and an unsigned wide quotient. |
| Balance and side map | `0x3bfa910..0x3bfac09`, `0x3c003c0..0x3c007fd` | The zero-direction branch invokes a keyed side map and saturating-adds the returned amount to a selected word. |
| Event collector and sink | `0x51fb310..0x51fb49a`, `0x51ca4e0..0x51ca7c4` | The collector may discard the constructed event; one sink mode appends a `0xf8`-byte record and increments its count. |

### Selected dispatch and parent

`selected-switches.tsv` records one entry from each of five independently read signed-relative tables. The top dispatcher's selected table entry is `0x926730`; the ordinal emitter's is `0x79c1d0`, the name emitter's is `0x9146c8`, the selector's is `0x915b48`, and the nested dispatcher's is `0x927c8c`. Both selected formatters and both dispatchers subtract `0x86` before selecting their arm; the ordinal emitter also stores 5. Inputs below `0x86` select index `0x14` in the pinned sequences; no upper range check is established by those sequences, and no conclusion is made for arbitrary out-of-range tags.

`selected-name-match.tsv` and `selected-decode-route.tsv` record a further path from a content name to the internal tag. For the selected content tag 13, the adapter calls the name matcher with a byte pointer and length. The matcher's length table selects its 12-byte arm; after checking an earlier candidate it compares `claimRewards` in an eight-byte and a four-byte piece. Equal bytes select `0x4d684f2`, which stores the little-endian word `0x0509`. On the selected normal envelope path, the caller accepts first byte `0x09`, saves the second byte, and eventually stores ordinal 5 at output `+0x8`. The action decoder reads that byte and its ordinal-5 table entry `0x9136cc` selects `0x4d410a3`, which references `ClaimRewardsAction` and calls the payload decoder `0x573dd90`. When that helper returns `0x09`, the action decoder stages tag `0x8b`, allocates and copies the boxed object, and returns its pointer. A selected empty content-kind `0x15` with zero length reaches the payload helper's `0x09` return; nonempty and malformed content can take other paths. A non-`0x09` payload result follows the separate branch at `0x4d410c3`.

The containing decoder `0x5707dd0` provides a further observed handoff. On content kind `0x14`, with exactly three elements, the first two selected field decoders must return `0x09` and the third element must be present. It calls the action decoder at `0x5708608`; on its `0x09` result, it loads the returned box pointer from the decoder output at `+0x8` and stores that pointer at the containing result's `+0x0` at `0x570864f`. It also copies the two prior 20-byte field results into the container. A three-element count then takes the normal return at `0x5708b59`, after a cleanup call; missing fields and non-`0x09` results take different branches. This function alone does not establish the next consumer.

There is a further static layout connection on the nested route. The outer content decoder `0x56f81d0` calls `0x5707dd0` at `0x56f937c`; on the selected nonzero result and exact three-field return, it stores that child box pointer at its own output `+0x18`. The outer action decoder arm `0x4d41bd0` calls that content decoder and stages tag `0xba`; its register moves and boxed copy preserve the pointer at outer box `+0x20`. The top dispatcher's ordinal-52 table slot `0x9267ec` selects arm `0x54a384d` for tag `0xba`. That arm passes outer box `+0x8` to parent `0x551cb40`, which loads its child at argument `+0x18`: the same outer box `+0x20`. `nested-handoff.tsv` records both outer switch slots and these offsets. If this decoded outer box is supplied unchanged to the top dispatcher and the selected gates succeed, its child pointer follows the parent to the nested `0x8b` arm and the handler. The actual transfer of the outer decoded box to the dispatcher is not yet traced.

The name and decoder results therefore support the action association, and the selected nested layout matches across these target instructions. Treating decoded objects as the actual dispatched objects still depends on the untraced outer ownership and transport; the packet does not assume this happened at runtime.

The top dispatcher reads its fourth argument's leading tag and its `0x8b` arm calls `0x550ac60` at `0x54a358d`. The wrapper saves the original 20-byte third argument, performs identity selection and invokes two preflight gates. Each gate's non-`0x1a2` result has a separate failure branch. On the selected success path, the wrapper calls `0x54e3030` at `0x550b25c` with the saved original pointer. The handler's `0x1a2` return becomes outer kind `0x0e`; other handler results become outer kind `0x0f`. One earlier identity failure writes inner `0x120` and outer `0x0f`. The shared gate bodies are not selected evidence in this packet, and their full semantics remain open.

The parent saves its third-argument pointer and later passes that pointer in `r9`, the child pointer in `r8`, and the state pointer in `rsi` at `0x551d1e4`. The selected dispatcher forwards the original 20-byte pointer and state to the handler. Before that call, the parent can take an early `0x120`/outer `0x0f` path from two equality checks, or propagate non-`0x1a2` results from the selector or either gate. The selected selector arm returns `0x1a2`; the general gate implementations and all earlier identity-selection branches are outside this packet. The parent therefore does not prove that every possible caller of this action reaches the writer.

Both binary arms are inside their respective dispatcher FDEs, whereas the top wrapper, handler and writer are independently called FDE entries. The agent-created `handlers/05_claim_rewards.rs` is a historical lead and is not evidence that this collection of operations was one original source function.

### Writer decisions and mutations

The handler passes a state subobject at `+0x1348`, the 20-byte input, and a metadata subobject at `+0x90` to the writer. The writer calls the user lookup on its first subobject at `+0xb0`. Let `V` be the value pointer returned by the iterator, `U` the unsigned word at `V+0x8`, and `C` the word at `V+0x10`. The words are observed; interpreting `U` as unclaimed quantity and `C` as claimed quantity follows the action name and their update direction.

| Decision, in observed order | Normal-return observation |
| --- | --- |
| The 20-byte-key lookup returns null | Return inner word `0xaa`; no reward-row iteration. |
| Iterator ends with no nonzero `U` | Return `0xaa` if no pair was appended. |
| `U == 0` | Skip that row before calculating a floor. |
| `U != 0`, conversion does not fit in a word or `U` is below the floor | Remember `0xab` and continue; that row's two words are unchanged. |
| `U != 0`, conversion fits and `U >= floor` | Store zero at `V+0x8`, add `U` to `C` with unsigned saturation at `u64::MAX`, then append the original key and `U`. Equality qualifies, including a zero floor for a nonzero `U`. |
| At least one pair was appended | Return `0x1a2` with the vector, even if other rows were skipped. |
| No pair was appended but at least one nonzero row was processed | Return `0xab`. |

The `0xaa`, `0xab` and `0x1a2` values are directly extracted numeric words; the descriptive names in this table are not claims about wire encodings or exact error text. `0x3c18147` clears `U` before the saturating addition, and `0x3c18173` invokes vector growth only after the row write. The overflow recorder runs before the saturated replacement on the carry branch. Thus this packet does not assume atomic rollback if an allocation, recorder or a later row fails. The writer processes the complete returned iterator before the handler starts its per-pair balance and event loop, on normal return.

The selected instructions, also in `windows.tsv`, include:

```text
3c18135  49 39 d6             cmp r14, rdx
3c18138  0f 93 c1             setae cl
3c1813b  20 c1                and cl, al
3c1813d  66 41 bd ab 00       mov r13w, 0xab
3c18145  75 a9                jne 0x3c180f0
3c18147  49 c7 44 24 08 ...   mov qword [r12+0x8], 0
```

The qualifying predicate combines an unsigned comparison with the conversion's success flag. For valid metadata, let `w0` be byte `+0x49` of the first metadata record, and `s` and `w` bytes `+0x48` and `+0x49` of the selected record, whose stride is `0x158`. The `0x3c49360` helper forms `10^(w0-s)`, and `0x4217e60` is called with numerator `100000000`, scale `10^(w-s)`, and rounding flag zero. The resulting selected floor is

```text
floor(100000000 * 10^(w-s) / 10^(w0-s))
```

The quotient uses a wide multiply and the relocated helper at `0x63efec0`. A nonzero high quotient word makes the conversion flag false. Invalid token indices, negative byte subtraction and powers that do not fit the observed 64-bit ladder lead to separate panic paths; they are not normal `0xaa` or `0xab` returns. No live token metadata or price is assumed. The 20 sampled binary64 table values in `sampled-f64-powers.tsv` are a bounded observation only; they do not prove the table's end or that every possible metadata byte is a valid index.

### Downstream effects and failures

For each returned pair, the handler passes the same 20-byte input, key, amount, a zero direction flag and a price-like word to `0x3bfa910`. Under normal helper returns its zero-direction branch first calls the side-map routine, then saturating-adds the amount to a selected balance word. The side map compares a 20-byte key using a dynamic `memcmp` relocation. A sentinel representation with count below 32 enters a conversion path; in compact representation a missing key with count above 63 enters the other conversion path. The selected absent-asset path calls `0x370e120`; its empty-root branch requests `0x68` bytes, stores the key, checks a local bound of 11 and increments the container count. Existing-tree splits and all allocation/unwind effects are not fully traced.

The handler's separate value arithmetic uses `amount / 100` for key zero. For a nonzero key it first consults the selected mark-like helper. A zero result yields value zero. Otherwise the selected conversion computes `floor(amount * mark / (100 * 10^(w-s)))` for valid metadata; a quotient at or above `0x28f5c28f5c28f5c`, or one with a nonzero high word, makes its success flag false and the handler selects zero. Key 1 bypasses the `10^16` cap; for other nonzero keys the cap is bypassed only when the metadata name has length 4 and its bytes are exactly `HYPE`. These labels for key and mark are inferences from the dataflow, not independently verified market semantics.

The selected account entry receives `floor(value / 10000)` at word `+0x10` with signed saturation at `i64::MAX`. Afterwards the handler builds an event-shaped object and calls the collector. At `0x51fb367`, the collector subtracts its word at `+0x798` from zero: if that word is `0x8000000000000000`, signed overflow sends control through cleanup without calling the sink. Otherwise it calls `0x51ca4e0`. In that sink's vector mode, `0x51ca541` copies `0xf8` bytes through a dynamically imported `memcpy` slot and increments the count at sink `+0xc0`; two other sink modes have separate paths and are not fully characterized. A call to the collector therefore is not proof that an event was retained.

The handler also has explicit metadata-bounds and allocation-failure branches. The writer's checked conversions and tree iterator have their own failure paths, and the side map and collector contain unwind cleanup. The raw windows and selected direct edges record those sites; the packet does not claim rollback, successful downstream persistence, or complete behavior under malformed in-memory objects. Dynamic import names and RELATIVE addends describe the ELF's static records; runtime interposition is not measured.

### Historical lead and release separation

At repository commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4`, the retired `research/work-items/RE-010-exchange-handlers/README.md` and `research/work-items/fees-claim-rewards-94/README.md` describe node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. They report tag `0x79`, dispatcher `0x2759240`, arm `0x2759c55`, handler `0x2710e30`, writer `0x3743930`, and normal words `0xa6`, `0xa7` and `0x186`. Those are historical #94 VAs and results, not #115 coordinates. This packet independently reads the #115 tables, calls, FDEs, comparisons and stores from the authenticated #115 ELF; it does not rerun the retired artifact or assert cross-release byte or semantic equivalence.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker settings, two-build reproduction, raw and normalized source comparison, call/data/relocation closure and whole-ELF comparison: **not yet measured**. Every retained body and window is raw and unmasked. The selected static record contains 33 indexed FDEs, 111 instruction-aligned windows, 129 direct edges, 11 selected RELATIVE call relocations, three selected dynamic import calls, five dispatch-related switch entries, the two additional selected decoder-table entries, and two selected outer-action table entries. These are selected evidence counts, not total function coverage.

The focused tests include a small synthetic model for the reported normal branches, decimal arithmetic, saturation, representation thresholds and collector sentinel. The model is checked against explicit expected values and pinned instruction bytes; it does not execute, emulate, or differentially test the captured node.

## Results and limitations

The focused unittest module passes 72 tests without skips, including wrong digest, a changed copy-on-write FDE start, corrupted switch, name, tag, literal and handoff bytes, unsupported/truncated branches, out-of-range and non-file-backed mappings, missing/duplicate/wrong-type relocations, invalid dynamic symbols, and arithmetic boundary controls. Separate generation runs with different hash seeds and time zones are compared byte for byte, including with binutils absent from `PATH`. Artifact signature verification and catalogue consistency are separate checks. No node, visor, chain, network or private key is used. No progress gate is requested.

The result remains partial: the external wire-to-content boundary and actual outer-box transport into the top dispatcher, full wrapper and parent preflight and their shared gates, complete balance-side-map and tree rebalancing, other event sink modes, metadata ownership, allocator failures, unwinding, rollback, dynamic interposition and the complete helper closure remain open. The selected name route is not a complete tag-to-wire proof. Next, trace the outer decoded box into the top dispatcher and prove the remaining map and event failure semantics before independently implementing and comparing this path.
