# RE-009: archive-shaped value serialization and receipt paths

Node #94's archive-shaped value writer selects a five-field named map or positional sequence, nests a `Reth115` block and a 15-to-21-field header, and encodes four header counters as eight-byte big-endian binary values; these observations constrain a reconstruction of the record and its optional fields.

- **Component ID:** storage/state roots, RE-009; bounded to an archive-shaped value serializer and its selected children.
- **Target release and full SHA-256:** Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- **Source commit / reference commit:** repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only for leads. No reference code is copied.
- **Claim status:** observations for the selected bytes, operands, FDE metadata, field order and control transfers; inference for the type identity, serialization terminology and relationship to persisted database values. Runtime reachability, complete payloads and compatibility are unresolved.
- **Scope included and excluded:** the byte-selector wrapper, five-field writer, nested block/header, selected collection and receipt writers, name classifier, and failure branches. Transaction payload internals, logs, nonempty precompile row children, full decoder behavior, other releases, runtime and actual database files are excluded. This packet requests no completion gate.

## Reproduce

From the repository root, with Python 3.12.3 and the standard library:

```sh
python3 tools/evm_archive_wire94.py --out research/work-items/RE-009-evm-archive-wire-94
python3 -m unittest tests.test_evm_archive_wire94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For a determinism check, choose two empty relative directories, then run:

```sh
OUT_A=work/re009-archive-a
OUT_B=work/re009-archive-b
PYTHONHASHSEED=7 TZ=UTC python3 tools/evm_archive_wire94.py --out "$OUT_A"
PYTHONHASHSEED=99 TZ=Pacific/Honolulu python3 tools/evm_archive_wire94.py --out "$OUT_B"
diff -r "$OUT_A" "$OUT_B"
```

`schema.json`, `header-cases.json`, `functions.tsv`, `anchors.tsv`, `calls.tsv` and `branches.tsv` are generated. `MANIFEST.sha256` includes those files and this README, and is checked from the packet directory with `sha256sum -c MANIFEST.sha256`. The generator authenticates the binary before parsing, reuses `tools/elf_index.py` and `tools/fde_extents.py`, excludes fileless sections from VA mapping, and uses fixed instruction encodings and little-endian ELF bytes. It invokes no external program and does not run the target. Development inspection used GNU objdump 2.42 only for bounded manual readings; its output is not an input or a generated evidence file.

## Evidence

Addresses are ELF link-time VAs; file offsets are recorded alongside them, and all ends are exclusive. The generator reconciles 35 selected FDEs with the unwind header and hashes each selected body. An FDE describes an unwind range; it is not alone proof of a complete source function or a complete call graph. The packet selects fixed instruction sites and does not claim a whole-image instruction census.

### Entry configuration and outer record

At `0x459c550`, the low selector byte is adjusted by `0xe9`, compared unsigned with 4, and selects configuration `0x01000400` for byte values 23 through 26 and `0x00000400` for the other 252 values. The separately written next byte is zero in both arms. For this caller's two configurations the writer at `0x45a1200` sees serializer bytes `+0xa = 0` and `+0xb = 1` or `0`. It requests a five-entry map or array header respectively, checks each name and child result, and writes these fields in order:

| Field | Input offset | Selected value path |
| --- | ---: | --- |
| `block` | `0x0` | single-entry variant map, key `Reth115`, then the nested block writer |
| `receipts` | `0x338` | sequence with 40-byte input row stride |
| `system_txs` | `0x350` | sequence with 272-byte input row stride |
| `read_precompile_calls` | `0x368` | collection materialized to 16-byte input rows, then a sequence |
| `highest_precompile_address` | tag `0x380`, payload `0x381` | tag 1 calls the 20-byte writer; otherwise the absent-value helper |

The record's offsets are in-memory source operands, not offsets in the encoded value. The named mode supplies all five names; the positional mode supplies none. `Reth115` is a literal in the authenticated #94 binary, not evidence about the separately tracked node release #115. The selected writer reads its variant as a one-entry map even when the outer struct uses the positional mode.

A separately located JSON-shaped writer at `0x466e210` supplies the same five names in the same order with corresponding source offsets. For the final field it passes the option starting at `+0x380`, whereas the selected binary writer passes its payload starting at `+0x381` after testing the tag. This cross-check does not establish identical input grammar or malformed-input behavior for the two formats. The name classifier at `0x1e749e0` uses the same five names and yields inner tags 0 through 4 and other-name tag 5; its outer result tag is 9. Its reviewed 22-entry length table is preserved in `schema.json`. The two long comparisons use overlapping 16-byte constants, whose overlaps are checked before constructing the names. This establishes the classifier only; it does not characterize how a containing decoder handles unknown, duplicate or missing fields.

The bytes also contain the diagnostic `struct EvmArchiveBlock with 5 elements`. It and the shared five-name set support the inferred archive type, but this packet does not establish a direct type-descriptor-to-writer call chain. The present-address arm reads through input offset `0x394`; the previously reported `0x398`-byte decoded block record is large enough for these accesses, but size alone does not identify the two values. The existing [database code table](../RE-009-db-code-table-94/README.md) labels selector 23 `Eb`; this packet does not establish that a particular invocation of this writer receives that selector or that its returned bytes reach a specific database key.

### Nested block and header

Inside `Reth115`, `0x45951c0` writes `header` and `body`. The first contains `hash` from `+0x2d0` and `header` from the input base. The second supplies `transactions` from `+0x2f0`, `ommers` from `+0x308` and `withdrawals` from `+0x320`; a sentinel comparison selects the absent or present withdrawals child. The inner header writer is `0x46bfbe0`. The following table is ordered by serialization, with offsets relative to its input; optional offsets identify the option representation passed to the child, not necessarily the first payload byte.

| Header field | Input offset | Gate | Value call target |
| --- | ---: | --- | --- |
| `parentHash` | `0x50` | always | `0x4595c30` |
| `sha3Uncles` | `0x70` | always | `0x4595c30` |
| `miner` | `0x258` | always | `0x4596e80` |
| `stateRoot` | `0x90` | always | `0x4595c30` |
| `transactionsRoot` | `0xb0` | always | `0x4595c30` |
| `receiptsRoot` | `0xd0` | always | `0x47afa90` |
| `logsBloom` | `0xf0` | always | `0x47aeb30` |
| `difficulty` | `0x1f0` | always | `0x47ae6c0` |
| `number` | `0x210` | always | `0x47ad870` |
| `gasLimit` | `0x218` | always | `0x47ad6f0` |
| `gasUsed` | `0x220` | always | `0x47ad800` |
| `timestamp` | `0x228` | always | `0x47ae5b0` |
| `extraData` | `0x30` | always | `0x47af530` |
| `mixHash` | `0x230` | always | `0x47afa90` |
| `nonce` | `0x250` | always | `0x47ae3f0` |
| `baseFeePerGas` | `0x0` | qword at `+0x0` nonzero | `0x47ae450` |
| `withdrawalsRoot` | `0x26c` | byte at `+0x26c` equals 1 | `0x47ae220` |
| `blobGasUsed` | `0x10` | qword at `+0x10` nonzero | `0x47af6e0` |
| `excessBlobGas` | `0x20` | qword at `+0x20` nonzero | `0x47af880` |
| `parentBeaconBlockRoot` | `0x28d` | byte at `+0x28d` equals 1 | `0x47ae220` |
| `requestsHash` | `0x2ae` | byte at `+0x2ae` equals 1 | `0x47ae220` |

The header count arithmetic uses 16 minus the borrow from comparing the first qword with 1, plus dwords at `+0x10` and `+0x20`, and bytes at `+0x26c`, `+0x28d` and `+0x2ae`, with 32-bit arithmetic. For valid zero-or-one option discriminants it gives 15 plus the number of present options. `header-cases.json` enumerates all 64 such combinations in field order. The separate gate comparisons are retained in `branches.tsv`; noncanonical in-memory discriminants are not assigned a valid object interpretation.

The byte mode established by the wrapper causes the selected hash, address, bloom and nonce paths to pass respectively 32, 20, 256 and 8 input bytes to a binary-value writer. The four scalar fields `number`, `gasLimit`, `gasUsed` and `timestamp` reach `0x45c7600`, which byte-swaps the 64-bit value and passes eight bytes to that writer. On successful writes, the length writer's selected encodings yield `c4 20`, `c4 14`, `c5 01 00` and `c4 08` prefixes for those widths. For example, the static model of scalar `0x0102030405060708` is `c4 08 01 02 03 04 05 06 07 08`. The nonce path passes its eight source bytes directly; the observed scalar byte-swap is not generalized to it. This example is model output, not a captured node serialization.

### System transactions and shared receipts

The `system_txs` element writer `0x45a0d20` writes a two-field `tx`, `receipt` record. The transaction starts at the row base and the optional receipt representation starts at `+0xe0`. A sentinel chooses an absent `c0` value or a call to `0x4c064e0`, which is also the element writer for the outer `receipts` sequence. The transaction value uses a one-entry variant map and delegates each selected variant payload to a different child.

The transaction writer and the receipt's `tx_type` writer each have the following five inspected signed-relative table entries. The two input discriminants are separate; no rule requiring them to agree is claimed.

| Inspected index | Transaction and receipt name | Transaction child target |
| ---: | --- | --- |
| 0 | `Legacy` | `0x46be9c0` |
| 1 | `Eip2930` | `0x49d5d10` |
| 2 | `Eip1559` | `0x49d49d0` |
| 3 | `Eip4844` | `0x49d6960` |
| 4 | `Eip7702` | `0x49d79f0` |

The next adjacent word interpreted as another relative entry points outside each selected FDE. Neither dispatch has a local bounds check at the reviewed site: the analysis admits these five rows and does not claim how the target handles arbitrary invalid discriminants or that no other implementation exists.

The shared receipt writer orders `tx_type`, `success`, `cumulative_gas_used`, and `logs`. Its selected input operands are respectively byte `+0x21`, byte `+0x20`, qword `+0x18`, and the input base. For valid boolean bytes 0 and 1, the success path supplies marker bytes `c2` and `c3`. Gas and log bodies are passed to separate helpers; this packet does not reconstruct them. A nonempty precompile collection row is handed to a two-element sequence writer, but the element payloads and tree ordering are unresolved.

### Error paths and prior evidence

`branches.tsv` records the selected branch opcodes and destinations, including outer header/name/child failures, nested block failures, each optional header gate, the result check after each of the 21 header field calls, collection-row failures, system receipt selection and receipt field failures. On a writer result other than sentinel `0x8000000000000004`, the wrapper follows its cleanup arm and initializes the returned three words to `(0, 1, 0)` before an error cleanup call. That is consistent with an empty vector representation if cleanup returns; it is not a claim about a database operation, a panic, or rollback outside this wrapper. A child may already have advanced the temporary writer before an error.

The previously characterized generic map/array/string marker helpers are used as call targets only; see [stream codecs](../stream-msg-codecs-94/README.md). The earlier [EVM key/value packet](../RE-009-evm-kv-schema-94/README.md) establishes separate account, code and slot schemas and leaves the decoded block record layout open. None of its selected FDEs is a selected FDE in this packet. The 35 selected starts were also checked against the existing `research/work-items` evidence; no exact selected start was found there.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No native execution, real database fixture, build, normalized comparison, relocation closure, or whole-ELF identity measurement was performed. No byte mask is applied. The Python classifier, field-count cases and binary-prefix examples are bounded static models, not a substitute for executing the target. The selected tests exercise wrong identity, changed code and branch conditions, changed direct and tail-call displacements, malformed jump tables and vector constants, changed field names, NOBITS and unmapped ranges, length boundaries, and invalid model inputs.

## Results and limitations

The extractor records 35 selected FDEs, 113 fixed anchors, 86 direct transfers and 117 conditional branches; the field and table records are in `schema.json`. Fifteen focused unittest methods pass, including all 256 selector bytes, 64 valid header-option combinations, corruption of each of the 21 header child-result branches and 17,850 single-byte field-name substitutions. These are bounded static controls, not a measured node-function denominator or a claim of runtime equivalence.

The inner header's variable-size values, five transaction payload writers, receipt log writer, precompile elements, full decoder/error grammar, direct persistence binding and cross-release compatibility remain open. No milestone gate is requested. Next question: bind a non-overlapping storage entry point to this serializer and independently recover one complete nonempty transaction or receipt value before comparing authorized offline fixtures.
