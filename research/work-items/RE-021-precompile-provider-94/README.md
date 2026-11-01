# RE-021: private provider installation through BLAKE2b dispatch and rollback

This packet establishes that the private EVM provider preserves the standard `0x09` callback while adding `0x0800..0x0813`, and connects one raw-spec-18 builder path through registry materialization, context installation, address lookup, precompile result handling and journal rollback; an independent reconstruction can now separate private provider state from the existing BLAKE2b implementation.

- Component ID: `evm`; RE-021 continuation of the existing compression packet.
- Target release and full SHA-256: node #94, Linux x86-64 ELF, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied. New Python is MIT repository code.
- Claim status: **observation** for FDE extents, instruction bytes, relocations, branch targets, stack records and call-site exception tables; **inference** for semantic role names, source-level containers and the preservation proof; **unresolved** for runtime seeds, complete Rust types, external helper closure and execution equivalence.
- Scope included and excluded: the provider/caller extension is new. The existing compression packet owns `0x4e9a8a0` and `0x4e9d2a0`; PR #1373 (`RE-021-blake2b-runtime-94`) owns the standard registry constructors, selector and generic enum dispatch. Those are named dependencies, not re-submitted function bodies. This packet owns the FDE entries in `functions.tsv`, including the alternate provider's materialization chain, but follows only provider A through the private engine caller. No #115, visor, captured execution, networking, keys, chain actions or component gate advancement.

## Reproduce

Run at the repository root with the pinned artifact available. Python 3.12.3 was used; only the standard library and the repository's `elf_index.sections` and `fde_extents.eh_frame_records`/`uleb` parsers are imported. The tool locates the root from its own script location and checks the entire input digest before parsing. It never launches an external program. ELF addresses below are original image VAs, before the runtime load bias; `functions.tsv` also gives file offsets and FDE/CIE addresses. RELATIVE addends are image VAs, not captured process pointers.

```sh
python3 tools/precompile_provider94.py --out research/work-items/RE-021-precompile-provider-94
python3 -m unittest tests.test_precompile_provider94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For independent byte comparison, substitute two empty relative output directories for the placeholders:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/precompile_provider94.py --out <tmp-dir-a>
PYTHONHASHSEED=923 TZ=Pacific/Honolulu python3 tools/precompile_provider94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The generated set is every `.json` and `.tsv` file beside this README; README and MANIFEST are editorial files. No output contains a clock, randomized ordering, host path or tool-dependent disassembly text. The test suite and both generation runs were also checked with a Python-only PATH. Human disassembly was consulted during research, but neither evidence generation nor tests parse its text. `MANIFEST.sha256` authenticates every other file in this directory.

## Evidence

### Evidence layers and denominators

`summary.json` reports **40 selected FDE extents, 53,881 bytes, 10,745 decoded instructions, 2,302 control-transfer records and 1,012 RIP-relative operands**. These are bounded ledger counts, not node coverage or 40 fully reconstructed functions. Each FDE range is obtained through the shared parser and checked for unique file-backed `.text` membership. `instructions.json` contains all bytes in those ranges with decoded operands; unsupported encodings fail closed. Internal direct branches must land on decoded boundaries. A linear instruction ledger is not a reachable CFG or a proof that every byte is reachable code.

`control-flow.tsv` records direct targets, conditional fallthroughs, indirect call sites and resolvable GOT addends. `edge-closure.tsv` separates selected entries, prior precompile dependencies, external static targets and unresolved dynamic targets. `rip-references.tsv` and `relocations.tsv` retain the supporting operands and raw RELA records. `unwind-records.json` contains raw FDE/CIE records. `exception-call-sites.tsv` contains **530 intervals, 431 with landing pads, from 32 selected FDEs**; `lsda-records.json` preserves headers and call-site bytes. Action chains and catch type records are not interpreted.

`path-windows.json` extracts the audited semantic windows from the ledger, including builder copies, provider and call-handler invocations, registry commit, transfer arithmetic, result handling and rollback. `path-branch-tables.tsv` contains qualified table windows with raw signed displacements. It does not guess enum bounds by scanning until a target stops looking plausible. Other indirect switches remain visible in the full ledger and closure file.

### End-to-end provider A route

| Stage | New evidence | Observed effect |
| --- | --- | --- |
| Build engine and handler | `0x247fd20`, calls `0x2464bd0` at `0x247ff2d` | Copies a `0x110`-byte context and a `0x11a0`-byte handler into adjacent storage. Handler base is engine base plus `0x110`. |
| Choose handler family | `0x2464bf3`, table `0x3e2908` | Raw byte values through `0x13` use a 20-entry branch table. The raw `0x12` branch is `0x2465d61`; the default is separately visible. No chain activation names are assigned. |
| Construct callback pairs | `0x278fae0`, `0x2792da0`, stores at `0x2466cd4..0x2466d6c` | Preexecution pairs begin at handler `+0x48`; execution pairs begin at `+0xe8`. Raw-spec-18 execution pair `+0x20` uses vtable `0x56bfaa0`. |
| Install private provider | `0x247ff9f..0x248002b`; standalone installers `0x244fe00`, `0x24b6590` | Retains twenty captures, allocates an Arc-shaped `0xb8`-byte object, stores the raw spec byte at payload `+0xa0`, releases the old provider and writes vtable `0x56a6850` at handler `+0x50`. |
| Invoke provider | builder calls `0x25154a0` at `0x24804db`; executor calls vtable `+0x28` at `0x251553c` | Engine `+0x158/+0x160` is handler `+0x48/+0x50`. RELA at `0x56a6878` resolves to `0x24448a0`. Alignment-based Arc payload calculation gives object `+0x10` for this vtable. |
| Materialize registry | `0x24448a0`, `0x25b6e20`, `0x26ba880`, `0x20482c0`, `0x26ba640`, `0x27c9190` | Selects a standard registry, converts borrowed storage to a seeded owned map, clones standard values, then inserts twenty private records. |
| Warm keys and commit map | `0x25b6ca0`, `0x26b8980`, executor `0x251569d..0x25156c2` | Extends the warm-address set at context `+0x80`; drops the old registry; copies the five-word result to context `+0xe8`. |
| Invoke CALL handler | `0x2515792..0x25157c7` | Engine `+0x218/+0x220` is handler `+0xe8+0x20`. Vtable `0x56bfaa0` slot `+0x28` relocates to `0x276d390`, which calls `0x2788710`. |
| Lookup and dispatch | `0x2788db0..0x2788ede`, hit `0x27891fe`, dispatch `0x2789782` | Reads the installed map at context `+0xe8`; compares all twenty address bytes. Tags `0..3` use the prior mutable enum dispatcher through GOT `0x5774e38`; tag zero is the preserved standard callback case. |
| Result and state disposition | `0x27897a6..0x278994f`, `0x2787af0`, `0x2997ab0` | Converts result/gas predicates to status, decrements depth on success, or reverses journal state and truncates checkpoint vectors on ordinary failure. Fatal errors take a distinct return. |

The builder also handles a requested spec change: it reconstructs the handler at `0x24801b5` and replays registered callbacks at `0x248026a`. The installed registration vtable `0x56b8038` resolves its replay slot `+0x28` to installer `0x24b6590`; its consuming slot `+0x18` resolves to `0x244fe00`. The concrete chain above is qualified to raw spec `0x12` and the observed installed callback pairs, not arbitrary dynamic registration order.

### Why private materialization preserves address 0x09

`private-records.tsv` reconstructs **40 records across two provider copies**, twenty per copy, directly from constant loads, suffix immediates, tag stores, capture stores and relocated vtable methods. Each temporary record is 48 bytes: key at `+0`, padding through `+0x17`, tag at `+0x18`, capture at `+0x20`, and vtable at `+0x28`. The key order is `0x0800, 0x0813, 0x0801..0x0812`; all values carry raw tag `2`. The referenced private trait-object vtables have payload size 80 and alignment 8. Callback addresses are retained as data, without claims about their bodies.

`clone-tag-table.tsv` shows raw tags zero and one sharing the payload-copy branch (`0x2048370` in A; `0x3577680` in B). Tag two retains shared ownership; tag three invokes the clone method. Thus a standard tag-zero value's two payload words survive the conversion. The private extension performs full-address replacement only. Its key set is disjoint from the twenty-byte big-endian address nine. This proves **conditional preservation**: if the selected standard registry has address nine, this provider retains its callback; a registry without nine does not gain it from the private extension.

`fork-mode-samples.tsv` records the byte-to-mode table in both copies. Inputs `0..5 -> 0`, `6..8 -> 1`, `9..10 -> 2`, `11..16 -> 3`, `17 -> 4`, and `18..19 -> 5`. Incrementing raw `0xff` wraps to index zero and yields mode six; the dependency selector table points that mode to the same branch as mode five. The sample does not establish which bytes the complete source enum admits. Registry membership and the final dispatcher-to-wrapper link remain the prior runtime packet's findings; the original compression packet identifies the callback `0x4e9d2a0` and its input/gas checks.

Provider B (`0x3268ce0`) independently corroborates the same key set and mode conversion through `0x3421670`, `0x3438b20`, `0x36e35f0`, `0x35775d0`, `0x3be4700`, and `0x379c750`. Its vtable methods differ in places. This is a materialization comparison, not a proof that its private callbacks or complete execution path are equivalent to A.

### Context, lookup and private database boundary

The context map occupies five words at `+0xe8`: controls pointer, bucket mask, growth capacity, occupied count, and seed. A zero first word selects borrowed storage, whose pointer is at `+0xf0`. Owned buckets precede the controls and have stride 48. Runtime lookup first checks occupied count at `+0x100`; on a hit it passes the value at `controls - 48 * index - 24` to dispatch. Tags four and five have separate context-aware indirect calls. Scheme byte six bypasses the precompile lookup and takes the ordinary account/code path.

The owned insertion and lookup hash use four overlapping little-endian address words, at offsets `0,4,8,12`, two process words and the map seed. `key_hash` records the independently expressed multiply-high/xor algebra. Lookup filters by the top seven hash bits, compares the complete key, stops on an empty control byte, and advances by successive 16-byte group strides. The tests use explicit synthetic seeds; the actual process seed lives outside file-backed bytes and is not invented. The model's bounded invalid-table rejection is a test guard, not a claimed target branch.

Context `+0xe0` supplies the private database object, before the precompile map. `0x2787460` loads or installs an account and calls the private database boundary `0x1f651f0` at `0x27874f2`; `0x2788350` resolves code through `0x1e6af40` at `0x27883d9`. `0x27cc680` returns account state from context `+0x30` using twenty-byte keys and 208-byte buckets. These external database implementations are not included. Their exact calls distinguish the private context path from the generic runtime path owned by PR #1373.

### State changes and failure branches

Before dispatch, `0x2788710` checks context depth `+0xa8` against `0x400`; a greater value returns status `0x11`. It loads the addressed account, saves vector lengths, increments depth, and appends an empty journal frame. Database result bytes other than five propagate to the outer error representation.

For raw value tag zero, four value limbs at input `+0x08..+0x20` are examined. Nonzero value loads sender and recipient from input addresses `+0x88` and `+0x74`. Account balances occupy `+0x40..+0x58`. The debit window checks the final borrow and branches with status `0x12`; the credit window checks the high-limb carry and branches with status `0x5f`. Both go through `0x2789258` to rollback. Touch records use journal tag two; a completed transfer appends tag three with both addresses and the four limbs. Zero value uses the touch path. The recorded store ordering is preserved; no general transaction atomicity or database invariant is inferred from these windows alone.

The precompile result is read as five words. Model field `gas_after` denotes the local returned gas word; it does not model later transaction-level charging. `result_policy` models only the following integer predicates, without invoking any captured code:

| Predicate | Raw status / disposition | Byte evidence |
| --- | --- | --- |
| First word nonzero and cost word at `+0x20` no greater than gas | Status `2`; remaining gas is gas minus cost; decrement depth | `0x27897ce`, `0x27897fe`, `0x2789844`, `0x278991b` |
| First word nonzero and cost greater than gas | Destroy returned buffer; status `0x53`; rollback | `0x2789803..0x2789827` |
| First word zero and low bit of second word set | Outer result tag `4`; separate fatal return; local rollback path is bypassed | `0x2789829..0x278983f` |
| Ordinary error with third word equal to `0x8000000000000000` | Status `0x53`, selected by signed-negation overflow | `0x278984f..0x2789860` |
| Other ordinary error | Status `0x60`; optional error allocation release; rollback | `0x278985a..0x278989b` |

`0x2787af0` decrements depth, reverses journal frames via `0x2997ab0`, truncates the saved vectors and releases removed buffers. Its depth-zero and checkpoint-subtraction failures have explicit panic calls. The reverse-journal table window maps tags `0..10`; the full helper bytes, direct branches and nested account-value cleanup table are retained. This does not recover all source enum names or all called storage helpers.

Allocation, reference-count and unwinding exits are included in the selected FDEs and exception table ledger. In particular, installers have allocation-failure and old-provider-release landing paths; the private extension drops replaced values and releases remaining array entries on unwind. The raw `lock inc`/signed-`jle` retain guard is retained as machine instructions rather than paraphrased as an inaccurate unsigned threshold.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, Rust compiler/linker settings, independent builds, machine-code comparison, relocation normalization, whole-ELF comparison and captured behavioral comparison: **not yet implemented/measured**. No normalization masks or byte transplantation are used.

The Python models cover key preservation, explicit-seed lookup and post-dispatch result predicates. Their fixtures are synthetic and labeled as such. They are not behavioral observations from the node. The binary-derived private records, callback relocations, exact predicate windows and duplicate insertion/lookup hash operands provide the target grounding; the tests separately check boundaries and corruption controls.

Validation: 28 focused unittest methods pass, with zero skips. Controls include wrong target digest, wrong expected bytes, non-FDE addresses, invalid ranges, `.bss` access, section crossing, relocation-type corruption, changed private tag/key placement/vtable, unqualified spec values, full-key mismatches despite matching fingerprints, wrapped probing, malformed tables, instruction truncation, branch-into-instruction rejection, and missing exception landing boundaries. Result cases include zero/equal/maximal gas, one-above-gas cost, fatal low bits and neighboring error-niche values. A first test incorrectly used the first NOBITS section (TLS storage whose VA overlaps another allocated file-backed section); it was corrected to test `.bss` specifically. The file-backed range rule itself excludes all NOBITS sections.

Two generation runs under different hash seeds/timezones and a Python-only PATH produce identical bytes. Artifact verification and catalogue freshness checks pass. The global suite, hosted CI, containers and node execution were not run.

## Results and limitations

The new reconstruction decision is to retain the standard precompile value during private map conversion and install the resulting map at the private context's `+0xe8`, with its separate database field at `+0xe0`. The raw-spec-18 callback construction makes the provider-to-runtime association explicit, rather than relying only on matching field offsets.

The selected FDEs, raw relocation records and local branch/exception tables are reproducible. Complete source types, reachability across arbitrary registrations, runtime hash seeds, every indirect switch's enum domain, external allocation/storage/helper semantics, LSDA action/type interpretation, and target behavioral equivalence remain unresolved. The alternate provider has only materialization coverage. No full EVM reconstruction, full node build, binary equivalence, or milestone gate is claimed; all existing component gates remain unchanged.

The supplied PR snapshot identified #1373 as owner of the original requested lookup. Live public-main/PR refresh was attempted but unavailable in this environment; submission must repeat the ownership check against current main and open PRs. Selected FDE entries were checked against existing repository evidence before this directory was staged.

Next question: recover the private database account/code adapters `0x1f651f0` and `0x1e6af40`, with their result variants, to replace the remaining external state-input boundary without re-opening the standard precompile dispatch work.
