# RE-011: node 115 raw-transaction forwarding path

This packet makes it possible to reconstruct the `eth_sendRawTransaction` adapter's captured selector, named and positional input handling, byte normalization, request construction, selected asynchronous transitions, and distinct forwarding failures from node 115 evidence.

- Component ID: `evm-rpc` (RE-011; the dependency observations also concern `evm`).
- Target release and full SHA-256: Linux x86-64 node `115`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; public `upstream/hyper-evm-sync` submodule `d0945c699d9d4774417f4355b10744e7cd420df8` is used only for the dependency comparison below.
- Claim status: static observations with explicitly identified inferences; reconstruction and runtime behavior remain unresolved.
- Scope included and excluded: one method registration, its argument parsing, selected forwarding and return branches, and a limited dependency/fork matrix. The generic response decoder, generic request builder, HTTP transport internals, local EVM execution and persistent state are boundaries, not reconstructed implementations.

## Reproduce

From the repository root with the verified target installed at `artifacts/node/115/hl-node`:

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_node115_evm_raw_forward
python3 tools/node115_evm_raw_forward.py --out research/work-items/RE-011-evm-raw-forward-115
(cd research/work-items/RE-011-evm-raw-forward-115 && sha256sum -c MANIFEST.sha256)
```

For a separate determinism check, use two empty directories under the ignored `work` directory:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/node115_evm_raw_forward.py --out work/evm-forward-a
PYTHONHASHSEED=97 TZ=Pacific/Honolulu python3 tools/node115_evm_raw_forward.py --out work/evm-forward-b
diff -r work/evm-forward-a work/evm-forward-b
```

The retained output was generated on Linux x86-64 using Python 3.12.3. Human exploratory disassembly used GNU objdump 2.42; the generator and tests do not call it or any other external program. The generator checks the full target digest before creating output and imports `tools/elf_index.py` and `tools/fde_extents.py`. It reads ELF sections, FDEs, relocations, code and data statically. The captured executable is never executed; no network, key, chain action or data synchronization is used. All generated files listed in `MANIFEST.sha256` are reproducible; README and the manifest are separately authored.

## Evidence

All addresses below are linked ELF virtual addresses before runtime relocation. `functions.tsv` and `windows.tsv` also give file offsets, `functions.tsv` records the FDE/CIE coordinates and body hashes, and `relocations.tsv` retains the complete selected RELA records. FDE extents are unwind coverage, not proof of a complete function boundary. The source suffix at `0x44c811` is `evm_rpc/src/evm_write_forwarder.rs`; two relocated descriptors and four references from the two poll extents bind it to the selected path without establishing source equivalence.

### Registration, capture and indirect calls

| Step | #115 observation |
| --- | --- |
| Method | `0x17512f3` references the 22-byte literal at `0x4806e7`, and `0x1751305` calls `0x16b3c40`. |
| Callback | The registration code selects descriptor `0x6409120`; relative relocations at `0x6409140` and `0x6409148` point to `0x16b3d20`. That callback returns descriptor `0x6409150`, whose slot `0x6409168` relocates to outer poll `0x16b3dd0`. |
| Captured selector | `0x17512dc` stores the low argument byte at stack offset `0x100`; the copied input begins at offset `0x38`, a difference of `0xc8`. The pointer is adjusted by `0x10` and placed at forward-object offset `0x3b8`; `0x1748125` loads it and `0x1748148` reads byte `+0xc8`. `selector-layout.tsv` records the individual sites. |
| Forward future | Outer poll allocates and copies `0x3c8` bytes, selects descriptor `0x640e940`, and calls its `+0x18` slot at `0x16b40a8`. The RELATIVE relocation at `0x640e958` points to `0x17480e0`. This edge assumes normal relocation and that the descriptor is not replaced at runtime. |

The four output-field construction calls in `request-helper-calls.tsv` converge on the same helper. The helper's full semantics are outside this packet. These are selected code windows and edges, not a whole-program call census.

### Input and failure branches

The outer poll sends an input beginning with `{` to named parsing and sends other selected inputs to positional parsing. The exact two-byte input `[]` is converted to a zero-length positional slice. Empty positional input reaches `0x173f7f8`, constructs `No more params`, and supplies `Invalid params` and signed `-32602` to an error constructor. Named parsing compares a five-byte key to `bytes`; an unmatched key takes a separate skip call, while missing and repeated `bytes` select separate format descriptors. The wrapper passes a failed named result to the error adapter at `0x173f9b0`, which supplies the same `-32602` code. This is an internal constructor argument; the final serialized response is not independently established.

Both named and positional value paths meet at `0x1702c60`. Its `[` dispatch reaches the array collector `0x16ef140`; its quoted-string path reaches `0x16ef310` and the relocated hex decoder `0x167afd0`. Other JSON value variants and the full numeric parser remain outside the established scope.

For the sequence accessor at `0x1705620`, the byte mask identifies exactly space, tab, carriage return and line feed as skipped whitespace. The following are local accessor outcomes, before the separate item and closing parsers:

| State and next significant byte | Observed/modelled outcome |
| --- | --- |
| First item, `]` | End; the closing byte is left for the closing parser. |
| First item, another byte | Ask the item parser to consume it. |
| After an item, `]` | End. |
| After an item, comma followed by another byte | Ask the item parser to consume the next byte. |
| After an item, no comma | Error tag `7`. |
| Comma followed by end of input | Error tag `5`. |
| Comma followed by `]` | Error tag `21`. |
| End of input while looking for the next delimiter | Error tag `2`. |

The item visitor accepts a parser result of kind `1` or `2` only when its 64-bit payload compares below `256`, then appends its low byte; other observed kinds or out-of-range payloads take an error path. `array-delimiters.tsv` and `array-item-cases.tsv` are synthetic models of those local predicates, not complete JSON test results. In particular, the numerical syntax and the handling of negative zero, fractions and exponent notation are not established.

For the string-derived byte slice, `0x167afe4` tests odd length before checking for a prefix. Only an initial lowercase `0x` is stripped; an uppercase `0X` is not. The 256-byte table at `0x46d50c` accepts ASCII digits and both letter cases and marks all other byte values invalid. The invalid-byte helper reports the first offending byte and a zero-based index relative to the slice after any stripped prefix. Thus the static model returns an odd-length error for `0x0`, an invalid byte at index `1` for `0X`, and an invalid byte at index `0` for `0xzz`. These examples describe the internal decoded byte slice, not arbitrary raw JSON encodings.

The outgoing encoder at `0x14500d0` writes lowercase hex with a `0x` prefix; it has scalar and feature-selected vector paths. The generator checks all 256 input table entries, all 16 lanes of the vector validation predicate, and all 484 pairs of accepted hex characters against the vector conversion arithmetic. The generator does not execute either path. Empty and prefix-only strings decode to an empty byte sequence in the static model; no downstream transaction-validity claim follows.

### Forward selection, constructed request and results

At `0x1748153`, a byte is compared unsigned with `2`; the branch at `0x1748377` reuses those comparison flags. These are the actual code paths for the complete byte domain, not a claim that every value is reachable from node configuration:

| Selector byte | Selected literal or action |
| --- | --- |
| `0` or `1` | Unsupported-chain path. |
| `2` | `https://rpc.hyperliquid-testnet.xyz/evm` |
| `3` through `255` | `https://rpc.hyperliquid.xyz/evm` |

The code constructs the byte strings `jsonrpc`, `2.0`, `method`, `eth_sendRawTransaction`, `params`, and `id`, and supplies them to four calls of the same construction helper. It also builds a one-element value from the normalized bytes, stores the numeric immediate `1` for the identifier, and uses `Content-Type`/`application/json` literals. The most direct inference is a JSON-RPC request with method `eth_sendRawTransaction`, `params` containing the re-encoded byte string, and id `1`. Exact serialized byte ordering and the generic helper's behavior remain unverified.

The send task is created at `0x1749b76`; a later body poll is called at `0x174a75b`. On selected pending branches, the forward poll writes output tag `4` and outer state byte `3`; on the body-pending path it also writes nested state `4`. Outer poll converts the forward pending tag `4` to outer output tag `2`, and records state `3`; the ready path records state `1`. The exact stores and state-table targets are retained in `state-writes.tsv` and `jump-tables.tsv`. Table entry counts are bounded by the adjacent selected tables and are not proofs that all entries are reachable.

| Observed branch | Internal result evidence |
| --- | --- |
| Selector `0` or `1` | Kind byte `0`; the formatter sees the `Unexpected error (code=` prefix and immediate `30000`. |
| Forwarding failure sentinel | Kind byte `1`, message `Unable to send transaction.` |
| Response decoder failure sentinel | Kind byte `2`, message `Invalid transaction response.` |
| Other decoded result | The forwarder either stores a result tag `3` or calls an opaque conversion helper, depending on the returned discriminant. |
| Request formatting failure | The tested branch reaches a diagnostic containing `a Display implementation returned an error unexpectedly` and then a `ud2` sink if the intervening call returns. |

The called body poll at `0x16fbea0` has its own six-entry selected dispatch table. A pending result from the first, second and later polls stores body states `3`, `4` and `5`, respectively, at `+0xab`; its rescheduling branch returns tag `2`, while the other branch returns tag `1`. At `0x174a7ad`, the forwarder tests body tag `1`, arranges the forwarding-error sentinel and eventually enters the same kind-`1` result path. A ready body poll stores state `1` and output tag `0`. In `0x16fc064`, two qword fields at `+0xe0` and `+0x80` are added, and a carry goes to a terminal handler and `ud2` if that handler returns. The fields' complete types and any practical body-size policy are not established. `body-states.tsv` and `body-length-cases.tsv` retain the selected stores and synthetic carry boundaries.

The first three forwarding errors place the same packed immediate `0xffff830000000007` in the result; its upper 32 bits decode as signed `-32000`. At the decoder boundary, a returned discriminant of `0x8000000000000001` selects the response-decode error; `0x8000000000000000` selects a copy into result tag `3`, and the remaining branch calls an opaque conversion helper. The outer poll later passes its result to another opaque helper at `0x16b4324`. `response-markers.tsv` records the constants and comparison sites. These are observations of internal values, not proof of a specific final wire response. Allocation, unwinding, transport, response-decoder internals, and other cold paths are not exhaustively classified. The send/body calls establish an external I/O boundary only; they do not establish successful broadcast, transaction acceptance, EVM execution or a local persistent-state mutation.

### Fork and dependency boundary

`fork-tokens.tsv` searches file-backed `.rodata` for the six exact token families below; it records 43 token occurrences, not 43 unique dependencies or a complete Cargo graph. Each hit is a binary path-string observation, not evidence of a source revision, linking completeness or private fork diff.

| Binary token family | #115 occurrences | Public sync project comparison |
| --- | ---: | --- |
| `z_forks/reth-chainspec` | 1 | No revision identified from this node observation. |
| `z_forks/reth-ethereum-forks` | 1 | The sync lockfile references `reth-ethereum-forks` from the public reth `v1.1.5` tag. |
| `z_forks/reth-rpc-eth-types` | 2 | No revision identified from this node observation. |
| `z_forks/reth-rpc-server-types` | 1 | No revision identified from this node observation. |
| `z_forks/revm-precompile` | 12 | The sync lockfile lists registry `revm-precompile` `16.2.0`. |
| `z_vendor/revm` | 26 | The sync manifest pins registry `revm` `19.2.0`. |

The public sync manifest also declares `reth-primitives` from reth `v1.1.5`, whose lockfile names commit `3212af2d85a54eb207661361ac9fe1d7de4b5b8e`. These are facts about the separately pinned public sync project, not established versions of node 115. No fork equivalence or dependency closure is inferred.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. There is no new Cargo graph or lockfile, compiler/linker configuration, two-build comparison, executed differential fixture, normalized byte mask or whole-ELF equivalence claim. The accompanying Python models transcribe only the specified static predicates. The unit tests include changed digest, changed instruction, ambiguous or NOBITS section, incorrect RELA type/addend, missing or duplicate relocation, invalid branch target, invalid jump-table target, altered lookup table, vector constant, odd-length/prefix/invalid-byte and numeric-boundary controls.

## Results and limitations

The retained output records 24 selected unwind extents, 123 checked instruction windows, 89 selected direct-call/branch records, 68 entries across selected relative tables, 7 relative relocations, 21 literal records, and 43 fork-token occurrences. It reports 256 character cases, 4,096 vector-classifier lane cases, 484 valid vector arithmetic pairs, 17 hex examples, 14 sequence-delimiter examples, 12 numeric-result cases, 5 unsigned-addition boundaries and 256 synthetic selector values. These denominators describe selected static cases only, not all node functions or runtime tests. The dedicated suite passed 26 tests with no skips using a Python-only command path.

The response decoder and success/error conversion are intentionally left as boundaries; their internal function ownership is not asserted. The known upstream callers and other EVM request paths are not part of this packet. No component gate is advanced. Next question: establish the runtime-independent response result and error envelope across the opaque decoder boundary without overlapping the existing JsonRpcResult work, then separately validate the transport and any state effects under an authorized offline differential harness.
