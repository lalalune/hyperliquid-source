# RE-015: configuration-name gate on a 32-byte storage response

Node #94's storage-read callback applies the configuration-name gate after its lookup phase and lock release, so a reconstruction can keep the prior `NvTestnet` default's byte 32 separate from the lookup and response while preserving the conditional handoff to the existing build-mode initializer boundary.

- Component ID: `constants`, task `RE-015`; the EVM RPC and storage routines are the selected downstream consumer and are not assigned global-configuration ownership.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed `can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23` supplied leads only.
- Claim status: observations are authenticated ELF bytes, selected relative operands, FDE records and relocation addends; function roles, the named method association and the small synthetic models are inferences. No target execution or component gate is claimed.
- Scope included and excluded: thirteen previously unclaimed unwind extents from the callback adapter through the object reader, two value readers, state query and response writers. The route-table and constructor instructions, old directory/config initializer and name table are context only, not selected function bodies. Existing address decoder, two state lookup helpers, Once dispatcher, formatter, allocator, vectorized hex helper and error-producing helpers are boundaries. Node #115, visor and the rest of the component are separate targets or out of scope.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12.3 and the pinned artifact available, replace the two placeholders with distinct empty writable directory names:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_storage_read94.py --out <tmp-dir-one>
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_storage_read94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
for f in <tmp-dir-one>/*; do cmp "$f" "research/work-items/RE-015-config-storage-read-94/${f##*/}"; done
python3 -m unittest tests.test_config_storage_read94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-config-storage-read-94 && sha256sum -c MANIFEST.sha256)
```

The generator authenticates the complete input size and digest before parsing. It imports the repository's shared ELF section, `.eh_frame` and ULEB readers, rejects ambiguous, non-file-backed and crossing spans, and checks each selected body hash and selected instruction pattern. It reads fixed-format RELA records, branches, RIP displacements and bounded LSDA call-site tables directly from ELF bytes. It does not invoke external programs or execute the artifact. Two generation runs and the focused tests also ran with a PATH containing no binutils. The generated files contain neither host paths nor timestamps. `MANIFEST.sha256` covers this README and the ten generated files.

GNU objdump 2.42 was used only for human inspection, for example:

```sh
objdump -d -M intel --start-address=0x27b6080 --stop-address=0x27b6539 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x1c35e70 --stop-address=0x1c36d90 artifacts/node/94/hl-node
```

No disassembler output is a generator input or a generated evidence file. `functions.json` preserves all bytes in each selected FDE and SHA-256 digests; `witnesses.tsv` and `transfers.tsv` cover selected windows and transfers only, not a decoded instruction or branch census. `references.tsv` and `relocations.json` retain the chosen RIP operands and RELA slots. `unwind-callsites.tsv` retains LSDA call-site entries and raw action indexes. `fields.tsv`, `name-context.tsv` and `error-codes.tsv` read data and table words from the binary. The focused tests use explicitly synthetic models of local instruction sequences, not target executions.

## Evidence

All addresses are linked ELF virtual addresses before load bias; FDE ends are exclusive. File offsets are recorded in the generated files. An FDE is an unwind-described extent, not independent proof of a source-function boundary or of a full function census. Seven selected FDEs carry LSDA pointers; their exception action tables are not decoded here.

### Route, callback and configuration identity

The earlier `RE-011-evm-rpc-method-path` records the method-table call at `0x27ab96d` with the 16-byte literal `eth_getStorageAt`. As boundary context, the constructor reached by that call loads vtable `0x56918d0` at `0x1f6d588`. The vtable has file-backed size and alignment words 8 and 8. Its selected relocations at `+0x18`, `+0x20` and `+0x28` resolve to the adapter `0x1f9b4b0` and twice to callback `0x1f704b0`. The adapter's direct call reaches that callback. The constructor and route table are existing work and are not selected FDEs. This static association does not prove which indirect slot a live request would use.

The retained full template bytes at `0x1ef5f5` and `0x1fc0ec` contain the prior `/static_config` and `/cham` suffixes. A RELATIVE relocation binds slot `0x576e928` to configuration cell `0x577b288`, and the cell's first word to the previously studied initializer. The file-initial word at cell `+0x50` is 3; no running-process state is asserted. Prior `constants` and `constants-aws-name-parse-94` evidence associates cell byte `+0x48` with the name and distinguishes parse success from the fallback, both producing 32 for `NvTestnet`. This packet independently reads the nine-byte descriptor and seven names selected by the new consumer; it does not resubmit the 76-entry inventory or claim a newly discovered direct reference to either template. Available `RE-015-address-query-94` and `RE-015-vault-leader-gate-94` drafts already describe the same timing/name mask at other consumers. The new question here is its position in this disjoint 32-byte storage-response path, not discovery of that mask.

### Selected extents and handoff

| FDE start | Bounded role shown by local bytes |
| --- | --- |
| `0x1f9b4b0` | Callback adapter and reference-count cleanup |
| `0x1f704b0` | Object/positional input choice, query handoff and response builder call |
| `0x1b2c750` | Reader wrapper, depth seed, trailing-input check and cleanup |
| `0x1c35e70` | Object key dispatch, value calls, missing/duplicate and structural errors |
| `0x251f4a0` | Nullable block-field prefix and local truncation/mismatch paths |
| `0x27e3910`, `0x27e3960` | Missing-index result and two-attempt index-value adapter |
| `0x27b6080` | Locked lookup, local 32-byte result selection, name gate and publication |
| `0x24c94f0`, `0x2976bd0` | Response allocation and success/error writer selection |
| `0x1e6ad10`, `0x2979660`, `0x2806800` | ID writer, error-code writer and scalar hexadecimal result writer |

At `0x1f70768` the callback calls the selected query; at `0x1f7089d` it calls the response builder. The object wrapper calls its reader at `0x1b2c797`. The reader's selected calls pass `address` to the existing address-decoder boundary, `index` to `0x27e3960`, and the block field to `0x251f4a0`. The other positional adapters are existing boundaries. The callback's object path calls the wrapper only after its own leading-byte check; the reader's separate array entry is not asserted to be reached through that object branch.

### Argument and local error decisions

The object reader compares length first and then the exact bytes below. Seven-byte keys use overlapping four-byte comparisons; the eight-byte alias uses one eight-byte comparison. The two block spellings reach the same slot and duplicate check.

| Field literal | Comparison | Local result |
| --- | --- | --- |
| `address` | `0x1c3606a`, `0x1c36074` | Its seen bit is checked at `0x1c36289`; missing at object close reaches the missing-field template. |
| `index` | `0x1c3610c`, `0x1c36117` | Its initial tag is 2; a repeat reaches the duplicate-field template. At close, an unfilled tag calls `0x27e3910`, which writes tag 2 and an error pointer. |
| `blockId`, `block_id` | `0x1c36086`, `0x1c36090`, `0x1c360a4` | Both share the tag-3 unfilled sentinel. Repeating either spelling reaches the duplicate-field path naming `block_id`; an unfilled block slot becomes tag 2. |

Unknown names take the external value-skipping boundary. Missing colon, exhausted input/depth, value-reader errors and non-whitespace after an otherwise accepted value have separate local exits retained in `transfers.tsv` and `witnesses.tsv`. The exact formatting engine and error-object internals are boundaries. The error templates and length-delimited names are retained as binary bytes in `data.json`.

The nullable block adapter compares `n`, `u`, `l`, `l` in order and writes tag 2 after the fourth byte. It advances the cursor as each byte is consumed. After an initial `n`, an exhausted prefix and a later mismatched byte take distinct local error routes; a non-`n` initial byte is passed to another decoder. The synthetic prefix model is intentionally limited to that prefix and leaves any trailing bytes for its caller.

For an input that passes its initial tag check, the index adapter tries two external conversions. A failure of both reaches the length-delimited binary diagnostic `data did not match any variant of untagged enum JsonStorageKey`; success paths write different local tags. This does not establish all accepted index encodings or the internals of either conversion.

### Locked query and name gate

The query forms a lock address at context `+0x578`. A value with the tested bit set, a value at or above the observed unsigned threshold, or a failed compare-exchange reaches the external slow acquisition helper; otherwise it attempts an atomic `+0x10`. Normal release uses atomic `-0x10`, and the recorded flag condition can call a wake helper. Cleanup on an exceptional path also contains a release. The external lock and unwind implementations are not reconstructed.

The query passes a 20-byte input to the previously documented state lookup at `0x37d0fb0`. If its returned first word is zero, the local path initializes both halves of the 32-byte output to zero. If it is nonzero, the query forms a 32-byte key and calls the previously documented storage lookup at `0x37d11d0`. A result tag other than 1 also leaves the local 32-byte value zero. For tag 1 the retained unpack, shuffle and pack sequence reverses the order of the 32 bytes read from the result. The focused tests model that selected instruction sequence; they do not run the binary. Interpretation of these as missing-account and missing-slot outcomes follows the existing schema packet and remains conditional on those external helpers' contracts.

The lookup and lock release precede the configuration read. The later `ucomisd` at `0x27b63dc` compares a local sum with the binary64 `3.0` at `0x20aab8`; `jbe` bypasses the name read for less-than, equal and unordered values when the comparison completes normally, including with masked floating-point exceptions. On the ordered greater path, the code checks the cell's `+0x50` word, optionally calls the Once boundary, then reads byte `+0x48`. It requires `name <= 31` and a set bit in `0x803c6000` before checking a second Once word. The selected bits are 13, 14, 18, 19, 20, 21 and 31; the previously established fallback byte 32 fails the bound.

The second word is at `0x577ab98`; the authenticated file initially contains 3, which does not establish its value in a running process. If that word is nonzero, the cold branch passes a closure holding cell `0x577ab80` to the external Once slot `0x576e8b8`. The cell's RELATIVE relocation addend is `0x143ef30`. The existing `RE-001-build-mode-init-94` packet owns that initializer body and identifies its `/cham/` comparison and error paths; `RE-001-build-mode-94` interprets its output as invocation-name build mode. Those are prior findings and the Once implementation is a boundary here. Under normal returns from the external helpers, all local branches join the same already-selected 32-byte stores at `0x27b6416`; the gate does not locally choose the lookup or its value. This does not rule out arbitrary external helper effects or concurrent changes.

### Response and error branches

The query writes local result tag 3 and two 16-byte halves. On the selected success route the callback passes this result to the response builder, which allocates an initial 128-byte buffer and branches to an allocation-failure helper if the allocation is null. The response writer references `jsonrpc`, `2.0`, `id` and `result`, with a distinct error-writer path. Complete serialization and buffer growth remain external boundaries.

The result writer reaches `0x2806800` for the selected inline 32-byte value. Its scalar loop uses the binary alphabet `0123456789abcdef`, a `0x` prefix, 32 input bytes and a 66-byte string passed to the downstream writer. A CPU-feature branch instead reaches the already documented vector helper; this packet does not independently prove its behavior. The local writer checks downstream errors. The focused tests model the scalar loop on synthetic bytes, not a full captured JSON reply.

For the error writer, eight selected signed relative words at `0x3f5d9c` enter seven immediate-code arms and one arm retaining its incoming code. `error-codes.tsv` records the codes and targets. The immediately adjacent word targets outside this FDE and is retained as a negative boundary control. The call site does not itself establish a valid index bound, so these eight entries are a selected table range, not a claim that all other values are rejected. The writer separately references `error`, `code`, `message` and `data`; individual write failures take local error routes.

### Selected unwind call sites

Seven selected FDEs have LSDA pointers. Their 68 call-site records are decoded using the shared ULEB reader; the next greater LSDA pointer or exception-section end bounds each read and is not claimed to be the LSDA object's exact size. Ranges and landing offsets are checked against their FDE, but are not independently verified as instruction starts. Raw action indexes are retained without decoding action or type tables.

The range `0x27b6196..0x27b6256` covers both selected lookup calls and names landing `0x27b6500`. At that landing, the recorded bytes atomically subtract 16 from the saved lock word. A conditional branch can call the wake boundary before the `_Unwind_Resume` transfer. The callback's `0x1f70630..0x1f7076d` range includes the query call and names landing `0x1f70bfb`. The response writer call lies in `0x24c964c..0x24c965e`, whose landing `0x24c9f51` tests the saved buffer length, conditionally calls a deallocation boundary, and continues through cleanup and unwind boundaries. These are static table associations, not evidence that an unwind occurs, of personality behavior, or of the external cleanup implementations.

### Inferences and unresolved questions

The recorded method literal, constructor vtable and relocation-linked callbacks make the selected code a strong candidate for the named storage-read path. The local state names and the byte-reversal interpretation follow the selected instructions and the earlier state-schema evidence. No request-time dispatcher invocation, real input, disk state, timing, concurrency interleaving or complete helper contract was observed. The name gate's position is a local control-flow conclusion under normal-return assumptions, not a claim that configuration can never have any other effect.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Build manifests, compiler/linker settings, raw or normalized target comparison, operand masks, fixture behavior and complete helper, dynamic call, relocation, vtable/data and whole-ELF closure are not yet measured. The captured body bytes are evidence only and are not an implementation. The models and corruption controls test static extraction and narrowly stated deductions; they do not establish behavioral equivalence.

## Results and limitations

The retained output covers 13 selected FDE extents totaling 12,662 bytes, 59 selected byte windows, 94 selected direct transfers, 35 selected RIP references, 17 selected RELA records, 68 selected LSDA call-site rows, four key literals, eight contextual name descriptors and eight selected error-code words. These denominators describe this packet only. The focused suite passed 58 tests with zero skips, including digest, byte, relative-target, relocation, table-arm, LSDA truncation and range, out-of-range, NOBITS and ambiguous-mapping controls; all 256 possible name bytes, floating boundaries, key mutations, null-prefix cursors and scalar hex/shuffle cases were checked in synthetic models. Two outputs under different hash seeds and time zones were identical.

The original first task and all four `constants` gates remain open. No node or visor executable was run, and no full-node, network, behavioral or binary-equivalence claim is made. Next question: identify a previously unowned producer of a configuration-dependent value that changes a storage or file decision before the result, and independently close its input and failure boundaries.
