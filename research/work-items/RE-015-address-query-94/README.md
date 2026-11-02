# RE-015: how does a configuration-name gate relate to the address-keyed boolean query?

The #94 `eth_usingBigBlocks` registration supplies a vtable linked to an address-bearing callback whose selected state byte can reach a boolean response, while its slow-path configuration-name gate excludes the `NvTestnet` default at discriminant 32.

- Component ID: `constants` (`global_constants/*`), with an EVM RPC consumer used to trace one configuration-dependent path.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference names and behavior are hypotheses, not source provenance for the target.
- Claim status: selected bytes, relocations and transfers are observations; callback association, data types and source correspondence are inferences; runtime reachability and helper closure are unresolved.
- Scope included and excluded: static, digest-bound #94 route registration, two argument paths, keyed lookup, name gate and selected result-writing path. Node #115, visor, target execution, networking, complete router dispatch, full helper semantics and implementation equivalence are excluded.

## Reproduce

From the repository root, Python 3.12.3 on Linux x86-64 was used. The generator uses only the standard library and the repository's `elf_index` and `fde_extents` readers. It verifies the entire artifact's length and SHA-256 before parsing and never executes it. `windows.tsv` contains exact byte-pattern windows; `transfers.tsv` contains decoded relative transfers; `path.json` retains the complete bytes and SHA-256 for each selected unwind extent, selected RIP targets, relocations, literals and modeled controls. These files are byte-for-byte regenerable:

```sh
python3 tools/config_address_query94.py --out work/re015-address-query-check
cmp work/re015-address-query-check/path.json research/work-items/RE-015-address-query-94/path.json
cmp work/re015-address-query-check/windows.tsv research/work-items/RE-015-address-query-94/windows.tsv
cmp work/re015-address-query-check/transfers.tsv research/work-items/RE-015-address-query-94/transfers.tsv
python3 -m unittest tests.test_config_address_query94 -v
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-address-query-94 && sha256sum -c MANIFEST.sha256)
```

The author also manually inspected selected instructions with GNU objdump 2.42, for example:

```sh
objdump -d -M intel --start-address=0x27baca0 --stop-address=0x27bb100 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x29769c0 --stop-address=0x2976bca artifacts/node/94/hl-node
```

Objdump output is not a generator input or generated evidence. The generator and tests invoke no disassembler or subprocess and emit no clock value, random value or absolute pathname. The byte-pattern windows are manually selected; they are not an instruction census. `MANIFEST.sha256` covers this README and the three generated evidence files.

## Evidence

All code and data addresses below are linked ELF virtual addresses, before any load bias; FDE ends are exclusive. `path.json` separately records file offsets and `.eh_frame` coordinates. An unwind extent describes an unwind record, not an independently proven source-function boundary. The raw retained bodies cover every byte within the 11 selected extents; the branch observations below cover selected sites, not every instruction in those bodies.

### Entry, registration and callback map

Prior `RE-011-evm-rpc-method-path` records the 18-byte method literal at `0x3f078c`: the route-table site `0x27abbab` passes it to `0x1f6d7c0` at `0x27abbbf`. Those already studied ranges are boundary context only. At `0x1f6d828` the constructor loads `0x5691960`, stores that address with its captured data, and passes the record to the GOT slot `0x5770950`. The slot's `R_X86_64_RELATIVE` addend is `0x2a484d0`. At `0x2a4851f` the selected callee copies the record, including its vtable word, and at `0x2a48575`–`0x2a485cd` writes a control byte and record fields in an indexed table. The zero-entry outcome branches at `0x2a4850a`, copies the supplied name into a separate result and goes through cleanup; the exact condition returned by `0x2a48ad0` remains unresolved. Allocation and unwind branches are retained.

The vtable at `0x5691960` has raw size and alignment words of 8 and 8. Its relative relocations at `+0x18`, `+0x20` and `+0x28` resolve to `0x1f9a950`, `0x1f6f830` and `0x1f6f830`, respectively. The first forwards directly to the second at `0x1f9a9a0`; both its normal and unwind paths decrement the captured reference count. Runtime selection of a particular slot is not established here.

| Selected unwind extent | Observed role in this bounded path |
| --- | --- |
| `0x2a484d0`–`0x2a48720` | Registration entry record, table writes, allocation and cleanup branches |
| `0x1f9a950`–`0x1f9a9e3` | Callback forwarding and reference-count cleanup |
| `0x1f6f830`–`0x1f6fbfc` | Input shape selection, callback lookup and result assembly |
| `0x1b2c870`–`0x1b2c97e` | Object wrapper, depth initialization and trailing-byte check |
| `0x1ca3ad0`–`0x1ca41f4` | Field recognition, missing/duplicate branches and value-decoder call |
| `0x1e685c0`–`0x1e68930` | Positional adapter and empty-argument error construction |
| `0x1b2a8c0`–`0x1b2aa7b` | Value adapter leading to the same external decoder |
| `0x27baca0`–`0x27bb100` | Keyed state lookup, lock, default cell and configuration-name gate |
| `0x24caae0`–`0x24cb5cd` | Result buffer construction, serializer call, failure and cleanup |
| `0x29769c0`–`0x2976bca` | Response-field and boolean literal selection |
| `0x25acd00`–`0x25acf0a` | Buffer capacity check, copy, growth and unwind paths |

### Selected branch and failure table

| Condition and site | Observed successor or effect |
| --- | --- |
| Input has the checked nonempty representation and first byte `{`, `0x1f6f896` | Calls `0x1b2c870`; other representations use the positional route. Leading whitespace is not shown to take this first-byte object branch. |
| Input length 2 and bytes `[]`, `0x1f6f92d`–`0x1f6f944` | Constructs the empty positional representation; `0x1e685ee` reaches `0x1e68841`, which constructs `No more params`, `Invalid params` and code `-32602` before calling `0x28cd6a0`. This is static construction, not a captured reply. |
| Object wrapper succeeds with remaining bytes, `0x1b2c8d8`–`0x1b2c901` | The mask `0x100002600` accepts byte positions 9, 10, 13 and 32; another trailing byte goes to local error code `0x16` at `0x1b2c93a`. |
| Object key has length 7 and the two overlapping 4-byte comparisons match, `0x1ca3c83`–`0x1ca3ca2` | The compared literal is `address`, at `0x3ef90a`; matching reaches the seen-bit check. All seven one-byte mutations are negative in the explicit comparison model. |
| Seen bit already set, `0x1ca3d35`; closing object without it, `0x1ca3e57` | Reach distinct duplicate and missing paths at `0x1ca4119` and `0x1ca403c`; both point to the seven-byte `address` name and different formatting records. |
| Missing colon, exhausted depth or decoder tag 1 | Branches at `0x1ca3d87`, `0x1ca3b6e` and `0x1ca3da9` reach separate error paths; local code stores and transfers are retained. Unknown keys go to the external helper at `0x1b2dd60`. |
| Object result is not tag 1, or positional result has tag 3 | The callback copies 20 bytes and calls `0x27baca0` at `0x1f6f993`. Exact address decoding and all error precedence depend on external helpers. |
| Root at state object `+0x49d0` is zero, or tree height is exhausted | The lookup reaches its default-cell selection. A matching key selects a row; both found and missing cases first check the lazy default cell's state. |
| Default-cell state is nonzero, `0x27bae76` or `0x27bae8c` | Calls the helper through `0x576e8b8` with the cell's `+0x20` state, then resumes selection. Failure or unwinding in that helper is not assumed to return normally. |
| Post-lookup timing sum compares ordered greater than the binary64 constant 3.0 | Only then does `0x27baf85` read the configuration cell. Equality, a lower value and unordered NaN skip this name check. The unit of the timing value is unresolved. |
| Name byte exceeds 31 or its mask bit is clear, `0x27bafa0` and `0x27bafaa` | The branch skips the secondary once-state check. A set bit reaches that check, whose nonzero-state path calls the once helper; the previously selected byte is returned if all helpers return normally. |
| Response allocation returns zero or serializer returns an error | `0x24cab13` reaches the allocation-failure path; `0x24cac54` reaches the direct output path only for a zero serializer result. Nonzero serializer and writer outcomes take separate helper/cleanup branches. |

### Keyed value and configuration boundary

The lookup obtains the state object through the context at `+0x78`, and passes the incoming 20-byte key and each tree key to GOT slot `0x576e488`; its dynamic relocation names `memcmp`. The node key array begins at `+0x168`, its 16-bit count is at `+0x246`, adjacent keys advance by 20, and the selected row advances in 32-byte units. Descending uses a child array at `+0x248`. On a hit the selected row's byte at `+0x1c` is loaded; on a miss the same offset is loaded from the default cell addressed by slot `0x5773960`, relocation addend `0x5786388`. The shared-lock interpretation is inferred from the atomic `+0x10` acquisition and `-0x10` release; helper calls, wakeup and unwind release are retained. No account-state mutation is established by the read itself. Reference-count, lock and lazy-initialization state can change.

The separate name cell is reached through `0x576e928`, whose relative relocation names `0x577b288`. Its state check is at `+0x50`; the byte is at `+0x48`. At `0x27bafa2` the checked immediate is `0x803c6000`, with set bits 13, 14, 18, 19, 20, 21 and 31. Reading the corresponding eight 16-byte descriptors from the earlier name-table base yields these selected names and the first excluded boundary:

| Byte | Descriptor literal | Gate |
| ---: | --- | --- |
| 13 | `HeavyTestnet` | selected |
| 14 | `HeavyMainnet` | selected |
| 18 | `SoloTestnet` | selected |
| 19 | `SoloMainnet` | selected |
| 20 | `LockerTestnet` | selected |
| 21 | `LockerMainnet` | selected |
| 31 | `SoloSandbox` | selected |
| 32 | `NvTestnet` | excluded by the preceding `>31` branch |

The descriptor-order interpretation and `NvTestnet` fallback are from the prior `constants` and `constants-aws-name-parse-94` packets. The current tool independently reads these eight descriptor relocations, lengths and literal bytes, but does not resubmit the 76-entry inventory. The old `/static_config` and `/cham` full-template leads were used to locate the shared configuration cell; their prefix argument and rendering remain prior-work questions, not new claims here. This gate is after the selected byte load and lock release, not an observed selector for that byte.

### Value to response

On the lookup-success route, `0x1f6f9d2`–`0x1f6f9e8` places tag 3, an inline marker 1 and the returned byte into the result passed to `0x24caae0`. That builder copies the tagged payload and calls `0x29769c0`. For this tag and inline marker, `0x2976b66` reads the same byte, selects the literals at `0x3f601c` and `0x209f00`, and calls `0x25acd00`. Byte 0 selects the 5-byte literal `false`; byte 1 selects the 4-byte literal `true`. The writer's fast path calls the GOT slot `0x576dfe0`, whose dynamic symbol is `memcpy`, and advances its buffer length; the other path delegates growth. `jsonrpc`, `2.0`, `id` and `result` literals are also passed in the serializer. Other byte values, external writer failures, request ID serialization and complete wire output are not proven by these observations.

### Inferences and unresolved questions

The registration argument flow and vtable relocations make these routines a strong candidate for the #94 callback associated with the method literal. The inferred reference's no-parameter version of this method is therefore insufficient evidence for a reconstruction of the observed address-bearing path. This is not proof that a live request reaches a given vtable slot, that all supported arguments were enumerated, or that the returned row byte has a particular business meaning. The external decoder, registry lookup, default initializer, once machinery, writer growth and serializer helpers are boundaries, not silently assumed implementations. The selected consumer reads the name byte rather than directly referring to a new full-pool entry; previously unowned direct references to the two prefix templates remain unresolved.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker flags, two-build comparison, normalized comparison masks, full call-target and relocation closure, and runtime fixtures: not yet measured. The retained FDE body hex is raw evidence, not transplanted implementation code. The tests exercise digest, byte and relocation corruption; missing relocations; unmapped, ambiguous, crossing and NOBITS ranges; bit-mask and timing boundaries; the overlapping key comparison; and deterministic output. The negative controls are models and evidence checks, not executions of node behavior.

## Results and limitations

The packet records 11 selected FDE extents, 73 exact checked windows, 59 selected direct transfers, 24 selected RIP-relative references and 15 selected relocation slots. These denominators refer only to the manually selected evidence, not all functions, calls, branches, or component coverage. The full component remains 0/4; no milestone gate is requested. The source reference is unlicensed and inferred, and neither #115 nor visor is compared.

Next question: statically resolve the router's request-time method lookup and indirect vtable call, then close the address decoder and default-cell initialization so the argument/error and missing-key behaviors can be reconstructed independently.
