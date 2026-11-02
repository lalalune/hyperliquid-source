# RE-021: private creation frames and the address-09 registry

The node #94 private revision-18 path for ordinary CREATE and CREATE2 reaches a full-key check against the installed address-09 precompile registry after incrementing the caller nonce, while its selected creation-opcode cost and input-limit decisions differ from the standard revision-9/10 path.

- Component ID: `evm`; RE-021 extends the existing BLAKE2b question and is not an official TASKS row.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred can1357 tree `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not implementation source.
- Claim status: **observed** for authenticated file bytes, selected operands, FDE/LSDA records, relocation addends and branch targets; **inferred** for opcode, account and field names, gas equations and conditional composition with other packets; **unresolved** for actual runtime selection, helper behavior, target execution and component equivalence.
- Scope included and excluded: private revision-18 opcode handlers, their creation-frame adapter, address derivation, both registry-membership arms, nonce journaling, checkpoint and transfer; selected standard revision-9/10 and revision-18 opcode comparisons. Previously documented provider, executor, registry constructors, result callback, BLAKE2b wrapper and compressor are dependencies, not selected FDEs. Node #115, visor, live traffic and captured-code execution are excluded.

## Reproduce

Run from the repository root with Python 3.12.3 and the authenticated artifact present:

```sh
python3 tools/artifacts.py verify
python3 tools/re21_private_create94.py --out research/work-items/RE-021-private-create-94
python3 -m unittest tests.test_re21_private_create94
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-private-create-94 && sha256sum -c MANIFEST.sha256)
```

For two independent outputs, replace the placeholders with different empty directories:

```sh
PYTHON_BIN=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/re21_private_create94.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/re21_private_create94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$PYTHON_BIN" -m unittest tests.test_re21_private_create94
```

The extractor authenticates the full input before parsing it, uses the standard library and shared `tools/elf_index.py` and `tools/fde_extents.py` readers, excludes SHT_NOBITS from file-byte mappings and starts no external program. All JSON and TSV files here are extractor outputs; this README and the manifest are packaging files. GNU objdump 2.42 was used only for human inspection; its output is not parsed or emitted. No target instruction is executed or emulated.

## Evidence

Addresses are linked ELF virtual addresses before load bias. `functions.tsv` records actual FDE start/end, file offsets, CIE/FDE/LSDA coordinates and interval hashes; `bodies.json` and `unwind.json` retain selected interval and unwind bytes. An FDE range alone does not prove a source-level boundary or supply a whole-node denominator. `windows.tsv` contains reviewed fixed instruction windows; `transfers.tsv` decodes only the listed direct transfers. `exception-sites.json` retains bounded LSDA call-site records, while `exception-edges.tsv` identifies four selected edges. Exception actions and catch types are not decoded.

| Stage | Newly selected FDE start | Selected observation |
| --- | --- | --- |
| Private opcode slots | `0x24f0410`, `0x24f07e0` | Table positions `0xf0` and `0xf5` publish action `0x6d` with a 136-byte frame. |
| Private revision-18 adapter | `0x276e8c0` | Supplies revision byte `0x12`, calls the creation routine, then drops its payload and releases the frame. |
| Address and collision path | `0x278b410`, `0x27c52e0` | Constructs a creation key and tests full 20-byte membership through the owned or borrowed map header. |
| Caller state | `0x2788220` | Checks the caller nonce, records journal entries and increments the 64-bit word. |
| New-account state | `0x2787ca0` | Opens a checkpoint; checks the destination; performs selected balance/nonce and journal updates, with rollback on two failures. |
| Standard comparison | `0x4c96150`, `0x4c96d10`, `0x4c95d80`, `0x4c96540` | Relocations select the corresponding `0xf0` and `0xf5` handlers under raw revisions 9/10 and 18. |

### Conditional handoff and previous evidence

The earlier `RE-021-blake2b-compress-94` packet binds the 20-byte key at `0x574f0c0` to the callback relocation at `0x574f0b0`. Pending PR #1373 maps its standard-registry lineage; pending #1413 maps the private provider's overlay and context installation. The private overlay preserves the earlier address-09 entry only under that prior packet's stated construction and no-replacement conditions. This packet does not reselect those bodies.

`dependencies.json` retains small integration anchors in the previously documented builder, constructor and executor. The private raw-18 case loads opcode table `0x56ac788`, and the constructor stores descriptor `0x56bfb30`; slot `+0x28` has a symbol-free relative relocation to `0x276e8c0`. Under the prior handler-to-engine copy relation and unmodified callback pairs, action `0x6d` selects index 1 of the executor's relative table at `0x3e5784`; that entry reaches the callback through engine `+0x248/+0x250`. The adapter then calls `0x278b410`. A relocation or a table entry alone does not prove that a live engine installed this callback.

The new probe `0x27c52e0` returns a Boolean membership result, **not a pointer to the BLAKE2b object**. Consequently, a hit on this creation path produces a collision result and does not invoke the earlier BLAKE2b wrapper. The separately owned ordinary-call lookup in #1373 remains the object-returning path; this packet does not claim to have found another unowned invocation path.

### Opcode selection, gas and frame layout

`selector-cases.tsv` decodes the selected standard revision table entries and case-local table loads. Raw 9 and 10 select table `0x5723e88`; raw 18 selects `0x5724688`. `fork-matrix.tsv` binds their four selected opcode slots and the two private raw-18 slots using actual `R_X86_64_RELATIVE` addends. The private raw-18 size/word-charge windows are byte-equal to the selected corresponding standard raw-18 windows. `window-comparison.tsv` retains both unmodified byte strings and hashes, with no masks. This is a comparison of those windows, not a full-body, source-version or private-fork identity claim.

The selected memory-error and journal-error paths also load relocated diagnostic records whose sanitized suffixes name `revm-interpreter-15.0.0/src/interpreter/shared_memory.rs` and `revm-19.2.0/src/journaled_state.rs`. `source-locations.tsv` retains the relocation-backed coordinates, record bytes, line/column numbers and hashes of the full embedded strings, but only the relative suffixes. These literals are dependency-version clues, not evidence that either upstream crate is unmodified or that the reth/revm fork boundary is fully recovered.

For ordinary bounded lengths let `w = ceil(length / 32)`. The following are the selected opcode charges when memory growth costs zero and the relevant gates and helpers succeed; they do not include external memory costs:

| Selected handler table | `0xf0` charge | `0xf5` charge | Input-length gate seen on the nonempty path |
| --- | ---: | ---: | --- |
| Standard raw 9/10 | 32,000 | 32,000 + 6w | The selected path enters offset/memory handling without the raw-18 gate below. |
| Standard raw 18 | 32,000 + 2w | 32,000 + 8w | Default limit 49,152; selected override handling below. |
| Private raw 18 | 32,000 + 2w | 32,000 + 8w | Same selected limit and word-charge instruction bytes as standard raw 18. |

For the raw-18 nonempty path, the configured object word at `+0x110` equal to 1 selects the word at `+0x118`; a value without its high bit set is doubled before comparison, while a value with its high bit set bypasses that comparison. Otherwise the default is `0xc000`. A length greater than the selected limit writes status `0x64`; equality continues. When all size limbs are zero, both opcode paths bypass this gate, the high-offset check and the input copy. Nonzero upper size limbs are rejected before that zero-length decision. Valid configuration domains and the external memory-growth helper are not established.

The raw-18 word charge is stored before the high-offset-limb check. Thus a later high-offset failure may leave the word charge deducted. The selected raw-9 path checks those offset limbs before its memory path and has no corresponding early word charge in the inspected opcode body. For `0xf5`, both paths remove three stack words first and test for the fourth salt word after the nonempty memory/copy route; a missing salt can therefore follow earlier work. The raw-9 copy-to-salt edge is retained at `0x4c96ff2`. `failure-paths.tsv` records selected raw status values and their ordering; it is not an exhaustive failure or exception graph.

`frame-lanes.tsv` derives the private handlers' stack-to-frame displacements from their store instructions. Both put the four-word input object at `+0x28`, the 32-byte value at `+0x48`, forwarded gas at `+0x68`, and a 20-byte caller at `+0x70`. The tag at `+0` is zero for `0xf0` and one for `0xf5`; the latter additionally stores a 32-byte salt at `+0x08`. Both copy 136 bytes into the allocated frame, replace the prior interpreter action and set action `0x6d` and status `0x20`. The old-action-drop LSDA landing installs the new pointer and action tag before resuming unwind; it does not perform the later normal-path status store. This is static ordering, not a captured exception.

### Key derivation, membership and state

The creation routine first checks depth `+0xa8`: values greater than `0x400` produce status `0x11`. After caller load and a four-limb value comparison, `0x2788220` rejects an all-ones nonce. On its selected success branch it conditionally journals a flag, appends a nonce journal entry, increments account `+0x60`, and returns the new word. The plain-creation arm encodes the **previous** nonce (new word minus one) with a 20-byte caller into the selected RLP-shaped preimage; zero, one-byte and multi-byte cases have separate instructions. The salted arm assembles 85 bytes:

```text
ff || caller[20] || reverse(frame_salt[32]) || digest(input)[32]
```

`salted-preimage-lanes.tsv` projects each of the 85 positions from the selected stores and byte-shuffle windows; the lane names and permutation are instruction-level inferences, not observed runtime bytes. The routine initializes a sponge-shaped state with rate `0x88` and delimiter 1 and calls the relocated absorb/finalize boundaries; it takes the last 20 bytes of the resulting 32-byte digest. Interpreting the digest as Keccak and the arms as CREATE/CREATE2 follows the input shapes, selected table positions and prior hash evidence; these names are not symbols. External hash helpers, dynamic input ownership and intervening calls are not independently reconstructed here.

The owned arm passes context `+0xe8` to `0x27c52e0`; a zero word at `+0xe8` selects the pointer at `+0xf0`. The probe checks the element count, hashes the overlapping little-endian key words using the map seed and process words, filters 16-control-byte groups using the upper seven hash bits, and compares all 16 leading plus four trailing key bytes. It considers matching candidates before testing for an empty `0xff` control and advances by increasing 16-byte steps. `0x576e3e0` relocates to `0x5788348` in `.bss`; no file-backed runtime seed is invented.

On a matching key the routine writes status `0x5e` after the nonce update and **before** calling the new-account checkpoint. It makes no local rollback call on this hit arm; an enclosing frame or transaction may still revert earlier effects. A miss loads the candidate account and calls `0x2787ca0`. That helper saves the prior indices, increments depth and opens a journal frame. A nonempty-code-hash or nonzero-nonce destination calls the previously documented rollback boundary and returns `0x5e`. A carry beyond four limbs similarly calls rollback and returns `0x5f`, after selected flag/journal writes. On the selected normal path the helper writes the four destination limbs, conditionally sets destination nonce to 1 for revision bytes greater than 4, debits the four source limbs and appends a transfer-shaped journal entry. Later code construction and result publication cross helper and callback boundaries; pending #1703 studies a conditional result-to-code-publication path. Arbitrary allocation, callback, journal and database behavior remains outside this packet.

The address-09 conclusion is conditional: prior registry lineage and private overlay must hold, the selected table and callbacks must remain installed, all earlier guards and helper contracts must hold, and the derived 20-byte key must equal the address-09 key. No preimage yielding that key, runtime hash seed, live request or invocation of compression is established.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, compiler/linker flags, two-build and Rust-to-target comparison, full helper/data/relocation closure, captured behavior and whole-ELF equivalence: **not yet implemented or measured**. The four binary-to-binary windows above use no normalization mask; they are not Rust equivalence. There is no target-byte transplantation.

The focused suite checks digest and body corruption; missing, duplicate and changed FDEs; invalid, ambiguous, crossing, non-executable and NOBITS reads; changed instructions, branches, selector, table entries and relocation type/addend/duplication; and selected LSDA header/landing corruption. Synthetic controls exercise all 160 key-bit changes, candidate-before-empty and deleted-control probing, nonce-encoding boundaries, salt byte order, raw-9 versus raw-18 gas boundaries and four-limb carry against independent integer arithmetic. The synthetic models do not run target instructions, prove real reachability or supply target behavior.

## Results and limitations

`summary.json` records 11 selected FDE intervals totaling 10,053 bytes, 98 fixed instruction windows, 91 selected transfers, 25 relative relocations, 16 frame-store lanes, 85 projected preimage lanes, 27 selected failure rows, six fork-matrix rows, four raw-equal binary-window pairs, ten source-location records, and 77 call-site entries in eight exception tables. These are selected evidence counts, not function coverage or matched-code denominators. The focused suite passes 28 tests with zero skips. Two independent regenerations and the final verification commands are recorded in the submission report.

The first HyperEVM task in `docs/COMPONENTS.md` also asks for private-fork boundaries and state-transition inputs beyond this selected path. It is not complete; no milestone gate is requested and `evm` remains 0/4. The original request for a *previously unowned object-returning* address-09 runtime lookup remains unresolved because the direct candidates are already owned. Other opcode families, dynamic registration, actual seed values, complete unwind actions, #115 and visor remain outside scope. The supplied PR inventory is a snapshot and requires a fresh ownership check at submission.

Next question: independently reconstruct and compare this CREATE-family frame and journal path in Rust, then validate its composition with the provider using a separately authorized target-grounded harness; the direct object-returning lookup remains with its existing owner.
