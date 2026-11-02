# RE-021: trace a node 94 call target into the execution environment

On a selected node #94 descriptor-linked request path, the decoded `to` value fills the 20-byte environment slot identified by a separate preparation analysis as the precompile lookup input, making conditional address-09 wiring reconstructible.

- Component ID: `evm`; RE-021 continuation of `RE-021-blake2b-compress-94`.
- Target release and full SHA-256: node #94, Linux x86-64, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead, not implementation source.
- Claim status: **observation** for the pinned bytes, selected FDE ranges, relocations, immediate values, and branch destinations; **inference** for source-level names, the conditional multi-function composition, and the descriptor table's role; **unresolved** for its method-name association, live RPC routing, decoder behavior, downstream frame construction on the base repository, arbitrary callbacks, and native equivalence.
- Scope included and excluded: one array-style argument route, the `to` field and its error paths, request-to-environment copying, a preparation gate and selected state writes, and the returning result/error conversion. The 19 newly selected FDE bodies do not reselect the existing compression, registry, provider, installer, executor, settlement, or separately drafted frame-construction bodies. Node #115, visor, captured execution, networking, chain actions, and whole-component progress are excluded.

## Reproduce

Run from the repository root with the authenticated artifact and Python 3.12.3. The exporter uses the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it authenticates the complete input before parsing, excludes SHT_NOBITS from file-backed VA mapping, and starts no external program. GNU objdump 2.42 was used for human inspection only; its text is not an input to the exporter or tests. All code addresses below are original ELF virtual addresses before load bias; `functions.tsv`, `windows.tsv`, and `relocations.tsv` also give file offsets. FDE ends are exclusive.

```sh
python3 tools/eth_call_target94.py --out research/work-items/RE-021-eth-call-target-94
python3 -m unittest tests.test_eth_call_target94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-eth-call-target-94 && sha256sum -c MANIFEST.sha256)
```

For two independent outputs, replace the placeholders with different empty relative directories:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/eth_call_target94.py --out <tmp-dir-a>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/eth_call_target94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The generated `.tsv` and `.json` files are exactly the output of the exporter. The README and manifest are packaging files. The tests and both regeneration runs were also performed with an empty program-search PATH by invoking Python directly. The tool emits no timestamps, host paths, hash-seed-dependent lists, disassembler output, or target execution receipts.

## Evidence

### Corpus and boundaries

`summary.json` records **19 selected FDE ranges**, totaling **38,873 bytes**; these are a bounded corpus, not a function-coverage denominator. `function-bytes.json` retains every selected range and `unwind-records.json` retains the corresponding raw CIE/FDE records. `functions.tsv` supplies the extracted extents, hashes, file coordinates, and inferred roles. The exporter cross-checks the shared `.eh_frame` parser against the unwind index and fixed body hashes; an FDE is an unwind extent, not proof of an exact source-level function boundary.

The packet also retains **70 selected semantic windows**, **no dependency windows**, **87 selected direct transfers**, **75 relative table entries**, and **9 relocation records**. The two error-dispatch tables include deliberately bounded prefixes through the selected tags; they do not claim the tables' full lengths or valid input domains. The transfers are an explicitly selected list, not an exhaustive control-flow graph. `flow.json` derives key field offsets, copy ranges, gate operands, result variants, and the target key from the binary. `synthetic-cases.tsv` and `result-variant-cases.tsv` are explicitly labelled Python models, not observations from executing the node.

The selected relative relocations at `0x5691888`, `0x5691890`, and `0x5691898` identify the adapter and method below; treating them as offsets `+0x18`, `+0x20`, and `+0x28` of a descriptor at `0x5691870` is an inference. The earlier `RE-011-evm-rpc-method-path` associates `eth_call` with a separate factory, but that factory is already recorded in the repository and is not selected here. This packet does not establish that the factory uses this candidate descriptor or that a live router selects the method.

| Stage | Selected FDE start(s) | Selected byte-backed relation |
| --- | --- | --- |
| Descriptor and argument routing | `0x1f9b220`, `0x1f6e9f0` | The adapter calls the method; one input arm calls the array argument parser and then the preparation adapter. |
| First argument and object | `0x1e68cc0`, `0x1b2af40`, `0x1bda270` | The argument path reaches the request-object visitor, returns its object, and copies it through the selected normal arms. |
| Field name | `0x21a0f30`, `0x21a1100` | Both selected name classifiers compare the two bytes `to` and return the same discriminant. |
| Nullable value | `0x2523c40`, `0x26a9800`, `0x28070b0` | The value goes through a nullable parser and a value/string adapter; the bytewise `null` route is distinct. |
| Fixed-width adapters | `0x280fb50`, `0x2883a60` | Both indirect-call the same decoder with width 20 and copy its 20-byte result only when the helper status is 3. |
| Preparation and engine handoff | `0x27bff10`, `0x247db80`, `0x247e720` | The object is copied, checked, converted into an allocated environment, and its pointer is passed to the engine boundary on the selected success arm. |
| Return and errors | `0x4e59140`, `0x4e5c710`, `0x4e5d830`, `0x24cc0c0` | One return variant produces a 32-byte result; selected errors pass through packed conversion and the response wrapper. |

### Field selection and input failures

In both name classifiers, the length-two table entry reaches an exact `to` comparison. The resulting discriminant is `0x17`; the visitor subtracts `0x16`, so index 1 of its selected relative table reaches guard `0x1bda952`. That guard accepts its not-yet-seen sentinel 3; otherwise it branches to `0x1bdc4f2`, whose separately addressed duplicate-field label contains the same two bytes. These are comparisons of the parser's field-name bytes; they do not establish which textual escape forms the external string parser accepts.

The visitor checks for the field separator and calls the nullable parser. A successful literal `null` writes outer tag 0 and inner tag 2. A missing field is normalized to inner tag 2 on the selected object-completion branch. For a non-null successful decoder result, the option adapter supplies inner tag 1 and the decoder's 20 bytes. Both string adapters call through the relocation at `0x57705c0`; decoder internals and the textual representation that yields any particular byte sequence remain external. Decoder status other than 3 takes the error arm. Missing or incorrect letters of `null`, a missing separator, and the duplicate-field guard each have distinct selected error destinations in `control.tsv`.

The method subsequently invokes three further argument helpers. For each, full returned value 4 takes its default path; otherwise a low 32-bit value of 3 takes the accepted continuation, while a different low 32-bit value takes its respective error branch. `flow.json` and `control.tsv` retain the three helper and branch destinations; the helper internals and meanings of their values are not inferred here.

### Address provenance and preparation

The object visitor packs one tag and the 20-byte payload as five contiguous chunks of sizes 4, 2, 8, 4, and 2. Its reconstructed request has tag at `+0x1bf` and payload at `+0x1c0`. The exporter reads ten selected `0x1e0` copy lengths and five selected `0x1c8` tail-copy lengths and checks that the `+0x18` tail includes this field. The intermediate copies also rebuild the first `0x18` bytes separately; these counts identify selected copy sites, not every possible path.

The environment converter reads those request offsets. For tag 2 it sets the eventual environment tag to 0; on the tag-1 arm it retains tag 1 and the 20 payload bytes. The tag and payload are staged at stack offsets `0x3bc` and `0x3bd`. The two selected bulk copies carry this range as follows:

| Copy | Source stack offset | Destination stack offset | Length |
| --- | ---: | ---: | ---: |
| First | `0x291` | `0x780` | `0x147` |
| Second | `0x7cf` | `0x668` | `0xf8` |

Subtracting the allocated object's stack base `0x4b0` gives environment tag `+0x294` and payload `+0x295`; the final allocation/copy is `0x2b0` bytes. This calculation assumes the intervening helper calls return normally without aliasing or changing the selected stack bytes, and normal `memcpy` resolution. For tag 2 the payload is not asserted to contain zeros; the tag is the established result. If allocation returns null, a separate failure call and `ud2` are selected; its external target is not analyzed.

The caller forwards the allocated pointer only on the selected tag-`0x21` result arm. If its additional saved word is nonzero, it forwards directly; if zero, it checks four environment words and may enter a separate helper before forwarding. The preparation adapter then calls the engine boundary with the returned pointer. The engine body is owned by earlier provider and installation work and is not selected or re-exported here.

Before environment conversion, if the preparation input's 32-bit word at `+0x80` equals 1 and its unsigned 64-bit word at `+0x88` exceeds **30,000,000**, the selected early branch stores result tag `0x0d` and subtype `0x08`. Equality takes the continuation. On that continuation the code stores 30,000,000 at another argument's `+0x70`, clears its 16 bytes at `+0x78` and its word at `+0x88`, stores 1 at a second argument's `+0x43` and `+0x45`, and clears the input word at `+0x90`. These are byte-level writes; their source-level field names and rollback after later failures are unresolved.

### Return and selected error conversion

On preparation result tag other than `0x21`, the adapter stages the error behind marker `0x8000000000000002`, copies it through the recorded `0xa0`-byte ranges, and the marker arm calls the error converter. For the observed early-error tag `0x0d`, table index 13 selects `0x4e5cc7b`; the first byte of its payload is the subtype. Relocations bind the next converter and formatter slots. Subtype `0x08` falls in the selected two-value range starting at 7, which loads signed 32-bit code **-32000**. If the formatter returns zero and the intervening cleanup/copies return normally, the converter writes packed result tag 2, kind 7, and that code. A nonzero formatter result branches to a separate failure call followed by `ud2`. The final message text and formatter implementation remain outside this packet.

On the other result route, converter `0x4e59140` uses its input header and an input selector byte. In the selected normal variant it copies 32 bytes starting at input `+0x20 + (selector << 4)` and stores tag `0x21`; its caller then writes two 16-byte chunks and output tag 3. For a special negative-header variant it produces tag `0x0d` and subtype `0x13`. In the separately selected generic error variant, auxiliary bytes 0 through 4 map to subtypes 15, 16, 16, 17, and 18; byte 14 maps to 2; other bytes map to 20. These are bounded instruction-level observations and a model of their branch arithmetic, not assertions that every synthetic header or selector can arise in a real request. The converter's cleanup and external helper semantics remain unclosed. The method calls the response wrapper analyzed below; its final wire encoding remains unverified.


The method copies the packed error into an input object for `0x24cc0c0`, retaining its tag at wrapper input `+0x10`, kind at `+0x40`, and code at `+0x44`. The wrapper takes a separate branch for tag 3. For the early error's other tag, its bounded error-kind table sends kind 7 to `0x24cc7a8`, which loads the input code into a local. The wrapper then calls `0x2977ac0`; if that helper returns zero and earlier allocation/copy operations complete normally, the wrapper writes error flag 1 at output `+0x28` and the unchanged code at `+0x2c`. A null allocation has a different failure call, while a nonzero helper result follows another arm. This establishes an internal response-object code, not final JSON bytes or network delivery. The helper and the other error-kind entries are not reconstructed here.

### Conditional address-09 composition

`flow.json` reads the 20-byte address attached to the earlier precompile object at `0x574f0c0`; it is nineteen zero bytes followed by `09`. If the external decoder returns those exact bytes successfully, the tag-1 object path and the selected copies complete normally, and the selected forwarding gates allow the environment through, those bytes appear at environment `+0x295`.

A separate `RE-021-precompile-preparation-94` draft, not present in this repository base and not needed to reproduce this packet, reports a subsequent environment-to-frame copy. The registry, revision-bound provider, installation, lookup, and wrapper are described in earlier RE-021 work, including PRs 1373, 1413, and 1429. Their composition with this packet is conditional on that separate preparation evidence being accepted, the appropriate revision and callbacks remaining installed, normal helper behavior, and the earlier validation, account, value, depth, and lookup guards allowing the path. This packet does not independently reselect those already mapped bodies and does not prove live reachability. In particular, the current base alone does not establish the environment-to-frame step.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker settings, two-build results, relocation masks, native-byte comparison, whole-ELF comparison, and captured target behavior: **not yet implemented/measured**. The source-level function and field names above are inferred from byte uses, not copied source definitions.

The Python models cover only the selected copy arithmetic, tags, early gate, result variant and conditional error code. They do not execute, interpret, or emulate target instructions. Synthetic inputs are controls, not target-grounded runtime results. The 57 focused tests include full-digest, FDE extent, body/window, relocation and control-byte corruption; out-of-range, ambiguous and NOBITS mappings; modified copy offsets/lengths and branch slots; all 160 single-bit changes to the address-09 key; the limit on both sides and at equality; and all 256 synthetic auxiliary bytes of the selected result variant. No test skips are used.

## Results and limitations

The 19 FDEs, 38,873 bytes, windows and synthetic examples are a finite evidence selection, not a recovered node or a complete list of paths. The descriptor's actual method name and router activation, the real decoder contract and accepted text forms, all helper and callback behavior, the pending environment-to-frame link, formatter output, all exceptional paths, and native behavior are unresolved. The requested larger HyperEVM first task also includes private-fork boundaries and state-transition inputs beyond this path; it remains incomplete. No component gate is advanced, and the `evm` milestone remains 0/4.

The supplied PR snapshot and existing work items were checked for overlap, but a fresh public main/PR refresh was unavailable and is necessary at submission. Next question: independently review and land the pending environment-to-frame evidence, then resolve the descriptor-to-router association and the decoder's accepted input forms without reselecting the established registry or wrapper bodies.
