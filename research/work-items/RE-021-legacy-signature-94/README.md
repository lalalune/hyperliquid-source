# RE-021: legacy transaction decoding and signing input for address 09

Node #94 preserves the legacy transaction recipient and payload through a signed-list reader, and its separate signing writer replaces the signature fields with a chain-dependent suffix, making both the address-09 input layout and the two signing-preimage forms reconstructible.

- Component ID: `evm`; RE-021 is the bounded continuation of the existing BLAKE2b work item, not a new official task-queue row.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; the separately pinned inferred reference is `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference was not used as source.
- Claim status: observations cover selected ELF bytes, actual FDEs, relocation records, instruction shapes and local branch/exception targets. Field names, legacy transaction and signing-preimage roles, and composition across call boundaries are inferences. Runtime callback selection, external helper effects and behavioral equivalence remain unresolved.
- Scope included and excluded: 12 selected FDE extents for the legacy list and field readers, selected numeric readers, signature selector, six-field and signed writers, length calculations, preimage writer and its allocation wrapper. The prior recipient-option decoder, typed transaction entry, registry, precompile wrapper, compression function, allocator, dynamic writer methods, digest, recovery and database are boundaries; their bodies are not reselected. Node #115, visor, target execution, emulation, networking, keys and chain actions are excluded.

## Reproduce

From the repository root with the authenticated artifact present; CPython 3.12.3 on Linux x86-64 was used:

```sh
python3 tools/artifacts.py verify
python3 tools/re21_legacy_signature94.py --out research/work-items/RE-021-legacy-signature-94
python3 -m unittest tests.test_re21_legacy_signature94
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-legacy-signature-94 && sha256sum -c MANIFEST.sha256)
```

For separate empty output directories, replace the two placeholders with distinct writable relative directories:

```sh
RE21_PYTHON=$(command -v python3)
PYTHONHASHSEED=1 TZ=UTC PATH= "$RE21_PYTHON" tools/re21_legacy_signature94.py --out <tmp-dir-a>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu PATH= "$RE21_PYTHON" tools/re21_legacy_signature94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The producer checks the complete artifact SHA-256 before parsing or writing and uses the repository's `tools/elf_index.py` and `tools/fde_extents.py` for section and CIE/FDE/ULEB decoding. It excludes `SHT_NOBITS` from file-backed mappings, invokes no external program, and does not execute captured instructions. The JSON and TSV files are generated; README and MANIFEST are packaging files. MANIFEST covers all other files in this folder. A scoped instruction-shape walker, adapted from the repository's MIT-licensed `tools/evm_kvs_inventory.py`, accepts enumerated opcode shapes and fails on unsupported or truncated shapes. Semantic claims have additional exact-byte predicates. No timestamp, machine path, disassembler output or host-dependent ordering enters the generated files.

GNU objdump 2.42 was used only to interpret human-readable instructions; it is not an input to the producer or tests. For example, a short human excerpt of byte shapes also retained in `windows.tsv` is:

```text
135322b: 49 83 f0 1b       xor    $0x1b,%r8
135323b: 49 83 f0 1c       xor    $0x1c,%r8
13533b5: 48 83 c7 dd       add    $-35,%rdi
13533bd: 48 83 f9 01       cmp    $1,%rcx
13534d9: 48 0f a4 f9 3f    shld   $63,%rdi,%rcx
13534de: 40 80 e7 01       and    $1,%dil
```

## Evidence

All addresses are linked ELF virtual addresses, before load bias. `functions.tsv` records the corresponding original file offsets, FDE/CIE coordinates, exclusive ends and whole-extent hashes; `bodies.json` retains the original selected bytes and unwind records. The FDE/index join is checked using the shared readers. FDE extents and a linear instruction walk do not by themselves prove source-function boundaries, runtime reachability or complete call-graph coverage.

| Selected start | Bounded role inferred from byte and call relationships |
| --- | --- |
| `0x1352710` | Signed-list header, field-reader and signature-reader handoffs, declared-length check and output publication. |
| `0x13518c0` | Six sequential fields, including the prior recipient-reader boundary and byte-string payload allocation/copy. |
| `0x1352f90`, `0x1353560` | Separate bounded unsigned-word and four-limb scalar readers. |
| `0x13531a0` | Reads the signature selector, computes the chain option and parity, then reads two scalars. |
| `0x13520c0` | Writes the six fields in order. |
| `0x1352430`, `0x135ad20` | Writes the signed list, selector and two scalar encodings. |
| `0x1352b40`, `0x1352ca0` | Computes the six-field and signed-list lengths. |
| `0x1352e30`, `0x4e555a0` | Writes and allocates the selected signing preimage. |

The field reader `0x13518c0` begins exactly where the separate type-1 access-list FDE in pending PR #1876 ends. That prior end is exclusive: its selected FDE is `[0x1350e50, 0x13518c0)`, while this packet selects `[0x13518c0, 0x13520bb)`. No instruction byte or selected function is shared. Other selected starts were checked against the supplied open/merged PR snapshot and existing work-item evidence. The snapshot is the overlap-check baseline; no network refresh was performed.

### Reader, recipient and payload

The signed-list reader invokes the field reader through relocation slot `0x576e238`, then invokes `0x13531a0` at `0x1352944`. The raw-entry body in pending PR #1733 retains a high-bit branch and indirect-call bytes; those earlier bytes address slot `0x576e268`, whose RELATIVE addend is `0x1352710` in this packet. The prior BLAKE2b packet binds the object key to address `09`. The earlier raw entry and object remain separately owned dependencies; their composition with this packet is conditional on review.

The selected six-field writer reads the following result offsets. The names follow the observed ordering and the separately studied transaction layout; exact Rust types are not established.

| Inferred field | Result offset | Selected representation |
| --- | --- | --- |
| Nonce | `+0x60` | One unsigned word, bounded reader width 8 bytes. |
| Gas price | `+0x30`, `+0x38` | Two words, bounded reader width 16 bytes. |
| Gas limit | `+0x68` | One unsigned word, bounded reader width 8 bytes. |
| Recipient | tag `+0x70`, bytes `+0x71..+0x84` | Tag 1 writes prefix `94` and 20 bytes; tag 0 writes empty-string prefix `80`. |
| Value | `+0x40..+0x5f` | Four words, bounded reader width 32 bytes. |
| Input | pointer `+0x18`, length `+0x20` | Byte-string content; the preceding and following words are retained from the owner-producing boundary. |

The recipient call at `0x1351976` uses RELATIVE slot `0x576e208` to the earlier recipient-option boundary `0x135b670`. On its present-address success arm, the earlier packet describes an option tag and 20 input bytes. The new selected instructions make two overlapping moves into the field result and two more into the signed-list stage; `recipient-lanes.tsv` derives the tag and every one of the 20 lanes. The stages are option result `+0x01..+0x15`, six-field result `+0x70..+0x84`, signed result `+0x70..+0x84`, and writer input at the same offsets. The outer reader copies a 144-byte field stage and then a 208-byte combined stage. This projection assumes successful normal returns, valid nonaliasing storage and the earlier option-decoder contract; it does not prove the caller supplies the signed result unchanged to the transaction-environment converter.

On a nonempty payload, the selected path passes its length to the allocation slot, copies that many bytes through dynamic symbol `memcpy`, and passes the resulting local words to an external owner-producing helper. `dynamic-symbol.json` and `relocations.tsv` retain the original binding; they do not establish dynamic-loader behavior. For an empty payload, the selected branch bypasses allocation, supplies pointer value 1 and length 0 to the later copy/owner path. If the owner helper's first returned word is zero, the normal result stores are bypassed. Actual allocation, owner lifetime and helper error semantics remain external.

For the synthetic payload of 213 zero bytes, the selected string encoding is `b8 d5` followed by those bytes. `payload-cases.json` includes the same length with only 212 following bytes, which projects to detail 2 after consuming the two-byte header. This is a boundary example tied to the earlier wrapper's stated 213-byte requirement, not a captured call, valid signature or compression result.

### Signature selector and signing bytes

The selector reader first accepts an unsigned value of at most 16 bytes, then conditionally reads two scalar values of at most 32 bytes. For a successful scalar pair, the selected code writes parity at signature output `+0x40`. For valid option/parity states, the byte-derived selector rule is:

| Encoded integer `v` | Chain option | Parity |
| --- | --- | --- |
| 27 or 28 | absent | `v - 27` |
| 35 through `0x20000000000000022` | present, `(v - 35) >> 1` | `(v - 35) & 1` |
| Other values within the selected 16-byte reader | invalid selector | no successful scalar result |

Thus the largest accepted protected value corresponds to chain ID `0xffffffffffffffff` and parity 1; the following value is rejected. `v-cases.tsv` records the adjacent examples. This rule does not establish signature validity, curve recovery or chain admission.

The signed writer uses six fields followed by encoded `v`, `r` and `s`. On the valid absent-chain arm it emits `v = 27 + parity`; on the valid present-chain arm it emits `v = 35 + 2*chain_id + parity` using a two-word intermediate. The preimage writer emits an RLP list of the six fields alone when the chain option is absent, and appends encoded chain ID plus two empty integers when it is present. The chain-option tag and parity are assumed to be their reader-produced values; behavior for malformed internal tags is not generalized. The writer calls are dynamic output interfaces, whose full implementations are outside this packet.

`synthetic-transactions.json` provides five independently labeled constructions using the target-derived address bytes and a 213-byte input. The unsigned examples use `r = s = 1` only as structural placeholders. They are not captured transactions, native execution results, signature-validation fixtures or proof that the BLAKE2b wrapper was called.

### Selected failures, cursor updates and cleanup

| Condition | Observed local branch or bounded projection |
| --- | --- |
| Input exhausted, malformed prefix or wrong outer kind | The reader returns raw details 2, 1, 3, 4 or 6 on the pinned branches; `header-cases.json` records consumed-prefix examples. |
| Single-byte integer encoded with a redundant string header | The selected readers return detail 3 after consuming the header but before consuming that byte. |
| Literal zero as an integer | The selected integer readers reject it with detail 1; the empty-string form represents zero on their selected success arm. |
| Unsigned-word or gas-price payload too wide | The selected 8- and 16-byte reader paths return raw detail 0 after consuming the payload, before their leading-zero test. |
| Value or signature-scalar payload too wide | Both selected 32-byte paths check leading zero first and otherwise return raw detail 0. In the scalar reader, `0x13535ba` loads 8 as the destination offset and `0x13535c1` stores a zero word there; 8 is not the error value. |
| Invalid `v`, first scalar failure, or second scalar failure | The selector returns its error form. The first scalar failure bypasses the second scalar call; the caller does not take the signed-result publication branch. |
| Declared outer length differs from consumed length | The check runs after both field and signature readers. The mismatch form records raw detail 8, the declared length and the consumed count; the prior payload owner is passed to its cleanup method. Checked add and subtract failures use separate external boundaries. |
| Payload allocation returns null | The payload path reaches its selected external allocation-failure boundary. The cursor has already advanced on the inspected nonempty path. |
| Preimage length addition overflows or allocation fails | The wrapper reaches separate failure slots. An LSDA interval for its writer call lands at `0x4e5569f`, which conditionally calls the release slot before the external unwind target. |
| Signature-reader call unwinds | The signed reader's LSDA interval `0x1352934..0x1352949` lands at `0x1352b08`, where the selected owner cleanup precedes the external unwind target. |

The cursor is a pointer/count pair updated by the readers; local prefix consumption and allocation are not a transaction-wide rollback or persistence claim. `length-cases.json`, `integer-cases.json`, `header-cases.json` and `payload-cases.json` are synthetic projections of selected predicates and store order. The action and type portions of the exception tables, external cleanup behavior and all unselected paths stay open.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build scope, Cargo lock, compiler/linker flags, two-build result, target behavior and raw/normalized Rust comparisons: **not yet implemented/measured**. No normalization masks are used and no captured bytes are transplanted into an implementation.

The unit tests use an independently written recursive RLP reader to check the constructed lists and field boundaries. They also cover all 160 recipient-address bit positions, selector boundaries through the maximum chain ID, the 8-/16-byte versus 32-byte error precedence and the scalar's zero-word store, 213-byte payload truncation, cursor/count arithmetic, malformed inputs, digest and selected-code corruption, wrong branch targets, a branch into an instruction, bad relocation types/addends/duplicates, corrupted dynamic symbol data, broken FDE joins/ranges, corrupted LSDA bytes and non-file-backed, crossing or ambiguous reads. None executes or emulates target code.

## Results and limitations

`summary.json` records 12 selected FDEs, 8,557 code bytes, 2,237 linearly walked instruction shapes, 410 syntactic transfers including 223 conditional and 83 indirect transfers, 60 fixed windows, 96 annotated transfers, 16 relocation rows and 9 call-site rows in 2 LSDAs. It also records 21 recipient lanes and 17 selector, 15 outer-header, 76 integer, 13 payload, 7 length and 5 transaction synthetic cases. These are selected-corpus counts, not an EVM function-coverage or rebuilt-byte denominator.

The normal-return handoff from this legacy signed result into the previously studied environment converter remains unproved. Live provider and revision selection, complete helper/callback and unwind-action closure, state transition inputs, native behavior, Rust identity and whole-ELF equivalence are not established. The broad HyperEVM first task remains incomplete and its four component gates remain 0/4; no progress gate is requested.

Next question: identify a still-unowned caller that passes this legacy result to the existing environment converter, and establish the exact provider and frame binding without re-owning the prior lookup or execution functions.
