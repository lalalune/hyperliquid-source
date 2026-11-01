# RE-021: post-call gas settlement and state output after precompile dispatch

This packet shows how the already mapped BLAKE2b outcomes become transaction results: status `0x02` retains frame gas/refund, statuses `0x53` and `0x60` clear both and become distinct halt reasons, and the post-call callbacks credit accounts before returning the drained state map; reconstruction can now distinguish local precompile failure handling from later gas settlement and output ownership.

- Component ID: `evm`; RE-021 continues the unresolved connection in the existing BLAKE2b packet, not a new official TASKS row.
- Target release and full SHA-256: node #94, Linux x86-64, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference implementation text was not copied.
- Claim status: observation for authenticated bytes, FDE ranges, relocations, fixed instruction shapes, table entries and exception intervals; inference for Rust container names, caller/beneficiary roles and composition with the earlier provider path; unresolved for live handler selection, external helper behavior and native execution equivalence.
- Scope included and excluded: five post-call callback surfaces, their selected account/state/output callees and cleanup branches. The owned constructor, provider, lookup, rollback, wrapper and compression bodies are dependencies, not selected or counted again. This is a static extension, not full-component recovery. No #115, visor, target execution or emulation.

## Reproduce

Run from the repository root with the authenticated artifact present. Python 3.12.3 was used. The extractor imports only the standard library and the repository's `elf_index.sections` and `fde_extents.eh_frame_records`/`uleb` readers. It checks the full binary digest before parsing and never starts another program.

```sh
python3 tools/postcall_settlement94.py --out research/work-items/RE-021-postcall-settlement-94
python3 -m unittest tests.test_postcall_settlement94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/postcall_settlement94.py --out <tmp-dir-a>
PYTHONHASHSEED=991 TZ=Pacific/Honolulu python3 tools/postcall_settlement94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

Every JSON and TSV file beside this README is generated. README and MANIFEST are packaging files. MANIFEST covers all other files in this evidence folder. Neither the extractor nor tests depend on binutils; both CLI regenerations and the focused suite were also run with an empty PATH. GNU objdump 2.42 was used only for human reading during research. Its text is not parsed or included in generated evidence. There are no timestamps, random outputs or host paths in the generated records.

## Evidence

All addresses are original ELF virtual addresses before load bias. `functions.tsv` gives explicit file offsets, actual FDE/CIE coordinates, LSDA pointers, exclusive ends and whole-interval hashes. `function-bytes.json` and `unwind-records.json` retain original bytes. No next-index-start estimate supplies a function size. SHT_NOBITS sections are excluded from file-byte mappings.

The restricted instruction reader admits only the hash-pinned selected bodies and rejects unsupported shapes. Local direct branches and the selected table destinations must land on decoded instruction boundaries. This is a static byte partition and control ledger, not an independently measured reachable CFG or a whole-node function denominator. `semantic-windows.json` separately checks the windows supporting the interpretation; `field-operands.tsv` extracts their concrete displacements and immediates.

### Ownership boundary and callback map

The existing [compression packet](../RE-021-blake2b-compress-94/README.md) owns the BLAKE2b wrapper/compressor. PR #1373 (`RE-021-blake2b-runtime-94`) owns standard lookup/dispatch. PR #1413 (`RE-021-precompile-provider-94`) owns the private raw-spec-18 engine and its call-handler outcome path; PR #1429 (`RE-021-precompile-install-94`) covers installation. None of their selected function bodies appears in this packet's function set.

The earlier private-engine instruction ledger supplies the orchestration boundary. This packet resolves the following descriptor methods and their new downstream bodies. The table does not claim that an arbitrary live engine retains these callbacks after hook replacement.

| Descriptor VA | Borrowed method | Selected downstream operation |
| --- | --- | --- |
| `0x56bfa40` | `0x276d870` | Normalize final-frame gas using the instruction-status byte. |
| `0x56a7b98` | `0x244f400` | Add the separate refund adjustment and apply the one-fifth cap. |
| `0x56a7bc8` | `0x244f490` -> `0x2468410` | Credit the caller account for remaining gas plus refund. |
| `0x56a7bf8` | `0x244f4d0` -> `0x2468cf0` | Credit the beneficiary account for net gas used. |
| `0x56a6e18` | `0x244f6c0` -> `0x2469250` | Take a pending context error or produce state plus success/revert/halt output. |

`callback-vtables.json` preserves the complete descriptor words and all three method relocations. The borrowed methods are exact symbol-free R_X86_64_RELATIVE bindings. The other method bodies remain outside the selected scope. Consuming and mutable methods are not silently assumed equivalent.

Panic Location records independently contain the relative source suffixes `revm-interpreter-15.0.0/src/gas.rs`, `revm-19.2.0/src/handler/mainnet/post_execution.rs` and `revm-19.2.0/src/journaled_state.rs`. `source-locations.json` retains their pointer relocations, raw path bytes, lengths and line/column fields. These are binary source-attribution observations, not proof of an unmodified public crate or a recovered Cargo dependency graph.

### Final-frame gas and refund arithmetic

`0x276d870` selects one of two frame layouts by testing the first word for zero. The selected offset is either zero or sixteen bytes. It replaces the frame gas limit with environment `+0x238`, first clears remaining gas and refund, and then conditionally restores saved words:

| Raw status predicate | Remaining gas | Frame refund |
| --- | --- | --- |
| `status <= 4` | preserved | preserved |
| `16 <= status < 22` | preserved | zero |
| all other byte values | zero | zero |

`gas-status-cases.tsv` covers every byte input for this bounded arithmetic model. Some byte values are invalid at the later classifier; the normalizer itself uses the predicates above. The prior precompile outcomes `0x02`, `0x53` and `0x60` therefore take different normalization arms even when the local lookup caller had copied the original gas word into an error result.

`0x244f400` adds a signed adjustment to the signed interpretation of the refund word. Signed overflow calls the recorded panic endpoint before storing the sum. Otherwise it stores the sum, checks unsigned `limit - remaining`, and stores `min(sum_as_u64, floor(spent / 5))`. Thus a spent-gas underflow occurs **after** the refund-sum store. The quotient is backed by the encoded multiplier and shift, not a source-name guess. Negative signed sums are compared in their raw unsigned representation; the model preserves that distinction.

This does not prove that an exceptional result always pays the entire transaction limit. The separate adjustment can add a refund after frame normalization, and the already owned executor also contains a gas-floor adjustment outside these callback bodies. `settlement()` composes the selected callbacks with an explicit adjustment input; it does not model that executor adjustment or derive it from a transaction.

### Account credits and their state effects

The caller address comes from environment `+0x280` with its final word at `+0x290`; the beneficiary address comes from `+0xd0` with its final word at `+0xe0`. Both bodies use environment pointer context `+0xd8` and private database pointer context `+0xe0`.

For the observed four-limb arithmetic, let `cap`, `base` and `priority` be unsigned 256-bit values. The effective price is `cap` unless the priority-presence word equals one; that arm selects `min(cap, (base + priority) modulo 2^256)`. These source-level fee names are inferred from the operand roles and Location suffix. The arithmetic and exact environment offsets are observations.

The caller credit uses a checked unsigned sum `remaining + refund`. Multiplication retains the low 256 bits. Adding that product to the existing balance saturates at the maximum 256-bit value. The four balance stores are account `+0x40..+0x58`. Product truncation and subsequent addition saturation are separate operations.

The beneficiary credit first computes `max(effective_price - base, 0)`. After account loading it ORs flag `+0xb0` with four, then checks `limit - remaining` and subtracts refund with a second underflow check. The touched flag therefore precedes either gas-underflow panic. It uses the same truncated multiplication and saturating balance addition. Both credit bodies have non-five helper-result forwarding branches before balance stores. In the selected account helper, all observed normal-return arms construct result tag five; the presence of the forwarding guard is not evidence of an exercised database-error outcome.

The shared account helper `0x2460ad0` exposes the private database boundary without reclaiming its implementation:

- It asks an external entry helper for the full twenty-byte key in context map `+0x30`.
- An occupied entry returns the account pointer. If its flag contains `0x10`, it clears that bit and appends a tag-zero journal record; otherwise it returns without that append.
- A vacant entry calls external database function `0x1f651f0`. Raw tag five chooses an external default-account constructor; the other arm carries the supplied account payload. The new record's flags are eight or zero respectively. The absent/present interpretation is an inference, not an invented error enum.
- The new address passes through the external context-set insertion boundary. The helper writes mirrored control bytes, the full key and account payload into a bucket of stride `0xd0`, increments the occupied count, and conditionally appends the tag-zero record to the latest journal frame. The account pointer begins twenty-four bytes after the bucket key. Padding initialization is not claimed.
- A missing latest journal frame takes the recorded panic path. Partial-account destruction and unwind continuations are retained. Seed initialization, entry reservation, the address-set helper, default-account internals and database implementation remain external boundaries.

### State extraction, result classification and failures

`0x2469250` reads context error byte `+0xb8` and immediately replaces it with five. A previous value other than five is forwarded with outer sentinel `0x8000000000000002`, followed by frame-payload destruction; this bypasses the state-drain call. Otherwise, two checked subtractions calculate net gas before state extraction.

`0x2461110` releases transient-map storage, resets its header, allocates a single empty journal frame, releases old journal-entry allocations and resets depth to zero. It moves the account map to the output while replacing the context map with an empty seeded header, and moves the logs while replacing their context header with an empty vector. The process/TLS seed values are runtime inputs; this packet retains their arithmetic and external initialization boundary without inventing seed bytes. Allocation failure is not an atomic rollback: some context changes precede the allocation-null branch.

The output function then calls classifier `0x242be40`. `status-table.json` covers the selected table window for raw values zero through `0x6b`, with every relative displacement and terminal byte shape retained. There is no range check at this classifier entry. The selected 108-entry window is **not** a claim that every possible byte is a valid enum value; values outside it are not modeled. Within it, 68 entries target UD2. Five category destinations are retained separately in `output-table.json`.

| Classification | Output path and ownership |
| --- | --- |
| Category zero | Success at `0x246945c`: retains logs and output, stores net gas, refund and success reason, and carries the drained account map. |
| Category one | Revert at `0x2469503`: retains output bytes, carries the account map, and releases logs. |
| Category two | Halt at `0x24694f8`: uses sentinel `0x8000000000000001`, stores net gas and halt reason, carries the account map, releases logs and drops output bytes. |
| Categories three/four | Diagnostic/panic path at `0x24696a5`; no ordinary result is asserted. |
| Reserved table entries | UD2 in the classifier; no invented fallback. |

In particular, `0x02 -> (category 0, reason 1)`, `0x53 -> (category 2, reason 3)` and `0x60 -> (category 2, reason 13)`. The account map still carries post-call balance mutations for the halt result. Earlier rollback semantics remain the earlier packet's responsibility; this does not assert that reverted execution changes survive.

`failure-paths.json` binds fifteen conditional gates to their taken/fallthrough destinations and relevant earlier stores, including refund-sum publication, beneficiary touching and context-error reset. `exception-sites.json` and `exception-prefixes.json` retain the selected FDEs' actual call-site intervals, landing pads and action indexes. Frame-output cloning, state drain, log destruction, final payload destruction and diagnostic unwinds have distinct entries. Selected cleanup functions `0x245bdb0`, `0x245dc50`, `0x2024f30` and `0x25077d0` retain their branches and external drop boundaries. Action chains, personality execution and dynamically selected payload destructors remain unresolved. `external-edges.tsv` distinguishes resolved external calls, unresolved dynamic transfers and the two table-bound jumps.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker flags, rebuilt byte comparisons, native two-build comparison and captured behavioral equivalence: **not yet implemented/measured**. There are no normalization masks, transplanted executable bytes or compiling-node claims.

The Python arithmetic functions are independent static models of established integer operations. They never interpret or execute captured instructions. `arithmetic-cases.json` contains explicit synthetic inputs, including exceptional statuses with later nonzero refund adjustments, signed overflow, spent underflow, unsigned interpretation of negative refunds, and division boundaries. These are not captured transaction fixtures. The composition model takes balances as seen by each separate credit invocation; its retained examples use distinct accounts. It does not resolve addresses or simulate account aliasing. If both lookups return the same account, the second credit observes the first credit's updated balance. The classifier extractor recognizes fixed constant-return byte shapes and their table references; it is not an x86 emulator.

Validation: 28 focused unittest methods pass with zero skips. Controls include wrong artifact digest, altered whole body, every semantic-window mutation, invalid/NOBITS/ambiguous/cross-section ranges, missing/duplicate/extended FDEs, unsupported/truncated instructions, branch into instruction, changed table bytes and destination, changed terminal pattern, wrong relocation type and callback identity, malformed LSDA header and classifier-domain limits. Arithmetic checks include the target division multiplier against integer division and an independent base-2^32 multiplication/addition oracle. The retained generated set is compared byte for byte with fresh collection.

Two independent CLI regenerations under different hash seeds/timezones and an empty PATH agree with each other and with every retained generated file. Artifact verification and catalogue consistency pass. The full repository suite, hosted CI, containers and captured execution were not run. The initial focused run had one test-fixture failure: it selected an overlapping TLS NOBITS address; the corrected control selects `.bss`. No imported evidence or shared parser was changed.

## Results and limitations

`summary.json` reports 15 selected FDE intervals, 6,375 retained code bytes, 1,542 instruction-shaped rows, 244 control rows, 32 semantic windows and 33 exception call-site records. There are 47 resolved external transfer sites and 17 dynamically unresolved sites; neither count represents transitive helper closure. All selected counts come from bytes and the pinned corpus. They are not whole-component coverage.

The new result is the post-call distinction between preserved success gas and cleared exceptional frame gas, followed by explicit refund/credit arithmetic, account-state extraction, output/log ownership and distinct halt reasons. The five callback descriptors connect these operations to the previously mapped provider family without resubmitting its functions. The entire COMPONENTS first task is not complete: private fork identity, all transition inputs, upstream caller gas-floor behavior, later persistence, all vtables/helpers and native equivalence remain open. The evm gates remain **0/4**, with no catalogue or progress edits and no grade claim.

Overlap checks used the checkout, the supplied open/merged PR inventories and preserved earlier packets. Public main/PR refresh was attempted, but direct network access was denied and web results were unavailable or stale; no fresh public-head assertion is made.

Next question: reconstruct this callback ABI and the state/output ownership protocol in Rust, using the exact error-before-drain ordering and exceptional-status gas normalization, then seek separately authorized target comparison. Extend upstream gas-floor/input provenance only after coordinating ownership of the already mapped executor.
