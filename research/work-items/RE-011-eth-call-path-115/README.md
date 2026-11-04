# RE-011: Trace the node 115 eth_call adapter through request preparation

Node #115's `eth_call` adapter routes four typed parameters through an expensive-call limiter and carries the request's `gas` option into a worker context with a 30,000,000 bound, providing concrete reconstruction rules for its missing-input, duplicate-field, waiting, and bounded-value paths.

- Component ID: `evm-rpc` (RE-011; EVM fork markers are supporting context).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. The older RE-011 method-registration packet is a #94-only lead, not a source of #115 addresses, layouts, or observations here.
- Claim status: selected static byte observations and explicitly marked inferences; runtime behavior and equivalence unresolved.
- Scope included and excluded: registration, positional parameter parsing, selected JSON `gas` paths, limiter, worker handoff, request preparation, conditional balance arithmetic, and selected return-state transitions. Excludes a complete EVM interpreter, all block/state override contents, downstream state commit semantics, exact RPC response serialization, networking, and binary execution.

## Reproduce

Run from the repository root on Linux with Python 3 and the repository's `tools/elf_index.py` and `tools/fde_extents.py` present. Analysis used Python 3.12.3. The tool checks the complete input SHA-256 before creating the output directory, parses the ELF section table, unwind header and FDEs with the shared modules, reads selected RELA records and instruction bytes with the standard library, and does not invoke a disassembler or the target. The evidence is independent of binutils text formatting. VA mappings exclude `SHT_NOBITS` and reject ambiguous or incomplete ranges.

```sh
python3 tools/artifacts.py verify
python3 tools/node115_eth_call_path.py --out research/work-items/RE-011-eth-call-path-115
python3 -m unittest tests.test_node115_eth_call_path
(cd research/work-items/RE-011-eth-call-path-115 && sha256sum -c MANIFEST.sha256)
mkdir -p work/eth-call-a work/eth-call-b
PYTHONHASHSEED=1 TZ=UTC python3 tools/node115_eth_call_path.py --out work/eth-call-a
PYTHONHASHSEED=2 TZ=Pacific/Honolulu python3 tools/node115_eth_call_path.py --out work/eth-call-b
diff -r work/eth-call-a work/eth-call-b
```

The generator overwrites only its three evidence outputs. `functions.tsv` records the selected unwind-described ranges, actual file offsets and complete-range SHA-256; `windows.tsv` retains the selected raw instruction bytes; `path-evidence.json` retains decoded direct branches, RIP-relative targets, relocation records, vtables, location metadata, jump tables, value vectors and file-backed fork path markers. `MANIFEST.sha256` covers these files and this README. The executable was only read.

## Evidence

All addresses below are link-time ELF virtual addresses, with end addresses exclusive. The emitted files contain the corresponding original file offsets. These are not runtime addresses after loading or ASLR. An indexed FDE supplies an unwind-described range; it does not by itself prove a complete source function boundary or coverage of code without unwind data. Labels below are inferred roles, not recovered symbols.

| Role in this path | Selected FDE VA range | Key connection |
| --- | --- | --- |
| Router initialization and limiter construction | `0x2e375a0..0x2e3863e`; `0x175ceb0..0x175d24e` | GOT relocation at `0x64e22a8` resolves to constructor; direct call at `0x2e377b8` reaches registration. |
| Method registration | `0x2a05f60..0x2a06528`; `0x2d02f60..0x2d0303d` | At `0x2a05fab`, eight bytes at `0x459618` spell `eth_call`; the call at `0x2a05fbf` reaches the registration helper. |
| Registered callback and outer future | `0x2dd67c0..0x2dd68aa`; `0x2d087e0..0x2d09986` | Three RIP-relative vtable addresses and their RELATIVE relocations connect registration to the callback, the outer poll, and the handler poll; the outer poll calls the third vtable's slot at offset `0x18`. |
| Request and option parsers | `0x2d10310..0x2d10743`; `0x2d0f2e0`; `0x2d0f5a0`; `0x1d6bfb0`; `0x1d6c480`; `0x1e26230..0x1e28e9d` | Direct calls and error-label literals distinguish `request`, `block_id`, `state_overrides`, and `block_overrides`. Full FDE endpoints are in `functions.tsv`. |
| Field and value selection | `0x299fd90`; `0x299fbc0`; `0x29a0530`; `0x29ffb40` | Length and field discriminant tables select the `gas` arm; the optional-value parser has explicit `null`, success and error tags. |
| Limiter and permit selection | `0x2a2a0e0..0x2a2b882`; `0x2a04070..0x2a0465c`; `0x29cc120`; `0x2a353d0`; `0x175d250` | Handler poll invokes limiter poll, a guarded permit selection, then a relocated limiter selector. |
| Spawn, context, and worker | `0x2b3c190`; `0x2b215d0`; `0x29c1ee0`; `0x2a4dc20` | The task record points through relocation `0x6449ab0` to `0x2b215d0`; calls at `0x2b21812` and `0x29c1f6b` lead to the worker. |
| Adapter and preparation | `0x2a098b0..0x2a0acb9`; `0x2a04660..0x2a05ab8`; `0x2a2fd10..0x2a2ffd3` | The worker calls the request adapter; its copied request is normalized, prepared, and passed to `0x2962aa0`. |

**Parameter/error observations.** The first positional parser receives an empty input or a closing `]` and reaches `0x2d10634`. There, two overlapping immediate stores assemble `No more params`, and the call at `0x2d106a0` receives integer `-32602`, the 14 bytes `Invalid params`, and that detail. The outer error arm supplies `request` and `TransactionRequest`. These are arguments to an internal constructor; this packet does not establish the final wire response. The next parser emits internal tag `4` for absent `block_id`, and the outer code maps that case to byte `2`. The state-override parser emits tag `3` for its empty-input path. Error arms retain the binary literals `block_id` / `Option < BlockId >`, `state_overrides` / `Option < StateOverride >`, and `block_overrides` / `Option < Box < BlockOverrides > >`. These literals identify selected arms, not every accepted JSON form.

**`gas` field and data flow.** At `0x299fe72` the field classifier checks the three bytes `gas`, producing discriminant `0x1c`. The length table at `0x600974` and discriminant table at `0x5cfd88` lead to the field handler at `0x1e269fe`. A pre-existing field value whose internal tag differs from sentinel `2` branches to `0x1e28583`, whose error construction references the three-byte `gas` literal. The value parser consumes `null` into tag `0`, a successful non-null value into tag `1`, and a parse error into tag `2`. The nested quantity visitor also contains an explicit three-byte `0x0` string comparison leading to zero; exact accepted quantity syntax outside this arm is unresolved.

The object builder stores the gas tag and word at offsets `0x80` and `0x88` of its `0x1e0`-byte result. The wrapper, handler, task record, worker callback and context adapter carry the aggregate through the copies recorded in `windows.tsv`. In the adapter at `0x2a09b53`, tag `1` and an unsigned word below `30,000,001` preserve the word; all other observed tag paths set tag `1` and word `30,000,000`. In particular, valid option tags `0` and `1` produce the following static model:

| Input tag | Input word | Output tag | Output word |
| --- | --- | --- | --- |
| `0` | ignored | `1` | `30,000,000` |
| `1` | `0` through `30,000,000` | `1` | unchanged |
| `1` | above `30,000,000` through `2^64-1` | `1` | `30,000,000` |

`0x2a0a36e` copies the normalized aggregate into the preparation call. The preparation function copies it, carries the word via its local slot, and stores it at result offset `0xd8`; its absent-tag fallback is bypassed on this normalized path. The caller stages that result at stack word `0x6e8`, conditionally adjusts it, applies another unsigned minimum with `30,000,000`, and copies the containing aggregate into argument register `r8` at the call to `0x2962aa0`, preserving word offset `0xd8`. The dynamic relocations for the copy and overlapping-move slots name `memcpy` and `memmove`; actual dynamic binding and downstream use remain assumptions. The generator checks the offsets and both threshold immediates, and emits eight boundary vectors.

**Other selected branches and state.** When the original gas tag is zero and either of two adjacent words in the prepared aggregate is nonzero, the adapter calls `0x2a2fd10`. That helper performs a four-limb subtraction; either final borrow branches to a tag-`1` result which the caller handles separately. The non-borrow path checks a divisor for zero and otherwise calls an indirect arithmetic helper, then bounds an upper-limb result to the 64-bit maximum. The full account lookup and arithmetic helper semantics are not claimed.

| Condition | Observed transition or destination |
| --- | --- |
| Limiter poll returns tag `2` | Limiter emits `0x29`; the handler returns internal tag `4` and records pending state `3`. |
| Limiter result tag `0x28` | Handler builds the worker task; other nonpending tags take the arm at `0x2a2a598`. |
| Spawned-worker poll equals `0x8000000000000004` | Handler records nested pending state `3`, handler state `4`, and returns internal tag `4`. |
| Handler poll result is `4` | Outer future records pending state `3` and returns its own pending representation. |
| Handler poll result is not `4` | Outer future releases the handler future, passes the result aggregate to `0x22d7030`, writes its returned fields, and records completion state `1`. |
| Allocation failures or invalid future states | Dedicated allocator/panic/unwind arms exist; they are not identified as ordinary JSON-RPC errors. |

Three limiter and two handler relative jump tables are emitted as indexed signed displacements with targets checked inside their selected FDEs. The four listed entries per future table are only the selected states; no guarantee is made for invalid state bytes. The limiter selector caps two configuration counts at `2^61-1`, conditionally replaces reference-counted records, and selects using a byte-derived stride of `16`; valid selector values and concurrent runtime behavior remain unresolved. At `0x2a4de0b` the worker releases a guard with an atomic operation after the adapter call. This is local synchronization state, not evidence of a persistent chain-state commit.

**Dependency/fork context.** The ELF contains selected `z_forks/` path prefixes for reth chainspec, Ethereum forks, RPC types, RPC server types and revm precompiles, plus `z_vendor/` revm component prefixes. Their bytes and all selected occurrence coordinates are in the JSON. Embedded paths do not identify exact dependency commits, patch contents, reachability from this call, or the actual version used by the node. The companion sync repository's lockfile is not treated as proof of the binary's dependency graph.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo graph, compiler/linker flags, comparison masks, two-build comparisons, relocation/data/helper closure, and runtime fixtures: not yet implemented or measured. The Python decision model is a narrow transcription of checked branch predicates for valid option tags; it is not a target execution or a binary-equivalence test. There is no captured-node execution in this packet.

## Results and limitations

The extractor produced 29 selected FDE records, 121 authenticated instruction windows, 94 selected branch/reference records, and seven jump tables. These are scoped evidence counts, not a denominator of node functions or instruction coverage. Seventeen focused tests passed with no skips, including changed hash, modified window, bad instruction, invalid branch target, `SHT_NOBITS`, ambiguous/range-overrun mapping, corrupt RELA, FDE/index disagreement, out-of-range jump target, absent gas, unsigned cap edges, malformed tag, and out-of-range word controls. Two independent regenerations under different hash seeds and time zones must match byte-for-byte.

Names such as callback, permit, worker, and gas bound are inferences from byte-level connections, embedded literals, and calling convention. No component gate is advanced. In particular, this is not a complete dependency/fork matrix, full `eth_call` reconstruction, proof of persistent state changes, result/error wire format, or proof of semantic equivalence. Next question: trace the downstream call at `0x2962aa0` and the result builder at `0x22d7030` far enough to distinguish successful return data, revert/error translation, and any state overlay discard or commit using #115 evidence.
