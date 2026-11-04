# RE-017: the input-2 local-state restore and frozen-state handoff

This packet identifies a previously unmapped input-2 branch that reads a local ABCI state, conditionally resets its frozen-state fields, and can carry the selected materializer pointer to the parent result, providing an independent reconstruction with a concrete restore and failure ordering.

- Component ID: `abci`; this RE-017 question supports RE-009 storage, snapshots and state roots.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was consulted only to navigate, and no reference source was copied. The historical evidence packet was retained in repository history at `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4`.
- Claim status: selected ELF bytes, relative transfers, encoded operands, relocations, FDEs and LSDAs are observations; source roles and the pointer handoff are conditional inferences. No captured node was run.
- Scope included and excluded: the parent input-2 continuation, one local-read/materialize/frozen-reset branch, selected decode errors, the ordering gate and one conditional result handoff. Existing parent, Location, GOT and materializer findings are cited as boundaries, not newly owned functions. This does not map every branch of the future, all begin/action/end-block behavior, the complete state root, the process entrypoint or dynamic behavior.

## Reproduce

From the repository root, with the authenticated `artifacts/node/115/hl-node` and the checked-in `tools/elf_index.py` and `tools/fde_extents.py` present:

```sh
python3 tools/abci_local_restore115.py --out research/work-items/RE-017-local-state-restore-115
python3 -m unittest tests.test_abci_local_restore115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
mkdir -p work/re017-local-restore-check
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_local_restore115.py --out work/re017-local-restore-check/one
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_local_restore115.py --out work/re017-local-restore-check/two
diff -r work/re017-local-restore-check/one work/re017-local-restore-check/two
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-local-state-restore-115 work/re017-local-restore-check/one
(cd research/work-items/RE-017-local-state-restore-115 && sha256sum -c MANIFEST.sha256)
```

Use empty output directories for the two independent generations. Optional independent cross-check of the original release-94 lead, when that separate capture is available:

```sh
python3 tools/abci_local_restore115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-local-restore-check/history
```

The optional mode authenticates both input digests before reporting release-specific coordinates; its 14 generated #115 evidence files are byte-identical to normal generation. The extractor authenticates the complete #115 input before parsing or creating its output, uses the standard library and the two repository parsers, excludes `SHT_NOBITS` from file mappings and rejects ambiguous mappings. It does not execute the capture or call external programs. Generation and the focused tests were run on Linux x86-64 with Python 3.12.3, also with a PATH containing Python and no binutils. GNU objdump 2.42 was used for human inspection only; its text is neither parsed by the tool nor included in generated records. `MANIFEST.sha256` records the hashes of this README and every generated file. There are no network, chain, key or node-execution side effects.

## Evidence

All code and data addresses below are linked ELF virtual addresses; the tables also record file offsets. `fdes.tsv` reconciles 15 selected `.eh_frame` ranges with `.eh_frame_hdr`, hashes their complete file-backed contents and rejects overlapping selected ranges. An FDE is an unwind extent, not proof of the original function's complete boundary or of all callers. `windows.tsv` retains 56 selected raw byte windows, including six labeled parent-context windows; `transfers.tsv` decodes 119 selected branch/call instructions. `references.tsv` ties 11 RIP-relative references to their actual targets; `dispatch.tsv` contains 21 selected relative table cells. These are selected records, not coverage denominators. The single key descriptor, literals, relocation records, locations, operand widths and independent offsets are in the correspondingly named files. `unwind-sites.tsv` retains 365 selected LSDA call-site entries and `unwind-links.tsv` connects 34 pinned calls to containing entries; raw action values are not interpreted as a complete exception model. `model-cases.tsv` contains 21 explicitly synthetic examples, not observations of a running node.

### Route from the established parent

| Stage | Selected #115 coordinates | Observation and boundary |
| --- | --- | --- |
| Existing parent | FDE start `0x2cbbbe0`, dispatch `0x2cbbc40` | The separately proposed `RE-017-abci-loader-handoff-115` packet mapped the input-byte-not-2 route and left input 2 open. When parent byte `+0x21` selects the previously recorded index-0 entry, the `cl == 2` fallthrough proceeds toward a nested result. The old parent FDE and its previously published calls are context, not new owned extents. |
| Child preparation | `0x2cbbd1d` through `0x2cbbdf6` | After an indirect helper returns, a first result byte of `0x44` reaches the child initialization; other values branch away. For another result byte, `0x2cbee69` calls the new error adapter `0x2cbfc40`: its diagnostic says `error loading gossip config for non-validator: ` and its Location is `node/src/startup.rs:355:17`. If the formatting boundary returns, the adapter reaches `ud2`; if the adapter returns, the parent also reaches `ud2` at the previously recorded `0x2cbf001`. The parent writes zero at `parent+0xb6` on the `0x44` route, then calls the child with base `parent+0x68`. Thus that initialization sets the child's dispatch byte at `child+0x4e` to zero. The preceding reference-count and helper-return conditions also matter. |
| New future | call `0x2cbc4b4` to FDE `0x2cc1120` | The selected table at `0x60bcf8` maps index 0 to `0x2cc1177`; `0x2cc11c5` continues into the local-read setup. Other resumption entries and other variants remain outside this route. |
| Path selection | `0x2cc1205`, call `0x2cc1217` to `0x2c7d5f0` | A relative reference and the relocated 16-byte descriptor point to the 10-byte key `abci_state`. On the checked length and byte comparisons, the builder chooses `rmp`; for another length or differing bytes it chooses `json`. The result is conditional on stable key bytes across its possible lazy-initialization helper. This is a distinct FDE from the previously examined `0x59429e0` selector. It does not by itself establish the fully rendered pathname. |
| Reader | call `0x2cc1249` to `0x26a3610` | The caller passes the descriptor for `node/src/local_abci_state.rs:32:30` in `rdx`; the callee overwrites `rdx` with its second argument at `0x26a361e` before its first helper call. The Location is therefore a call-site fact, not evidence that this pointer reaches a subsequent helper. The preceding path-check slot and the selected normal returns remain boundaries. |
| Materializer | `0x2cc15ba`, `0x2cc15de`, `0x2cc19ea` | On the reader's low status bit zero, the returned pointer in `rdx` supplies the word at `+0x28` to `0x25d3f20`. A first returned word unequal to `0x8000000000000000` continues via `0x2bacad0` to a **new call site** through the previously identified materializer slot `0x64e73a0`, whose authenticated relative relocation names `0x3c13610`. The new caller saves its return at future `+0xe0` and sets byte `+0xfd9` to 1. The slot and materializer themselves are prior boundaries. |
| Result projection | `0x2cc2bbd` to `0x2cc1295`, then `0x2cc1651` and `0x2cc294e` | Under the ordering and intervening-call conditions below, the saved pointer is reloaded, placed at future `+0x20` with tag `0x8000000000000001`, later reloaded to stack `+0x20`, and stored separately at child output `+0x380`. The `0x308`-byte prefix copy immediately before this store does **not** include that pointer. |
| Parent result | `0x2cbc4b9` through `0x2cbc535` | A leading dword of 2 follows the parent's pending path. For another value, the parent copies `0x3b8` bytes to a temporary and reads the word at temporary `+0x380`: stack `+0x30d0` minus temporary base `+0x2d50` is `0x380`. The pre-existing parent packet covers the following check and return; its old call sites are not claimed here. |

The relative table for the parent's initial dispatch and its already published branch at `0x2cbbc61` are prior context. This packet authenticates the previously identified state Location `l1/src/abci/state.rs:123:37` at `0x64767a8` and the materializer relocation only to join to that context. It does not claim that the input-2 route calls the old Location function: the observed new call is directly through the materializer slot.

### Selected read and decode branches

| Condition | Selected consequence |
| --- | --- |
| Path-check result is zero | `0x2cc123a` takes the fallback at `0x2cc1261`, releases a nonempty path buffer and selects the alternate tagged value. It does not reach the materializer through this read. |
| Reader status has low bit 1 | The caller invokes the first entry of the returned object's table at `0x2cc1259` and joins the same fallback. A low bit of 0 reaches the intermediate check. The meaning of other status bits is unresolved. |
| Intermediate word equals `0x8000000000000000` | `0x2cc15f8` falls through cleanup, calls the selected drop helper, releases the `0x27a8`-byte object and rejoins the fallback. Any other first word selects the materializer path after normal helper returns. |
| Path component or suffix does not meet the checked conditions | Reader `0x26a3610` tests the component tag, handles `..`, searches for a last dot and calls existing comparator `0x159fca0` with the `rmp` bytes. The selected matching result takes a binary-read branch; failure takes the text-read branch. Case-insensitivity is inferred only with the previously reported comparator behavior, not from the suffix literal alone. |
| Binary or text read returns the signed-negation overflow sentinel | `0x26a3787` / `0x26a37c1` distinguish `0x8000000000000000` and call the separate adapters `0x26a40c0` / `0x26a4140`; their literal prefixes are `read:` and `read_to_string:` respectively. Their return and cleanup effects remain conditional on indirect helpers. |
| Decoder or trailing JSON content is invalid | The binary branch calls `0x1b44f30`; a first output byte other than 9 selects adapter `0x26a4020`. In the text branch `0x1d74270` calls a parser and accepts only bytes `09`, `0a`, `0d`, `20` after a successful parse. A different trailing byte selects error value `0x16` and cleanup before adapter `0x26a41c0`. This does not establish the entire JSON or binary schema. |
| Binary depth word | In one binary path the 16-bit field at decoder input `+0x22` is checked before decrement. A zero takes a distinct branch; decrementing a nonzero value to zero reaches the store of output tag 8 at `0x1b45cdd`. Other marker, length and recursion paths are not reconstructed. |
| Adapter cleanup tag | The binary adapter's table maps tags 0 and 1 to `0x26ae520`, tags 2 through 4 directly to the return block, and tags 5 and 6 to a conditional buffer-release block. Values above 6 bypass the table. The JSON adapter has different tag checks; do not interchange the two representations. |

The parent error adapter's formatting call has an LSDA landing at `0x2cbfc76`, where its tag-dependent cleanup begins. The reader's selected binary and text parse calls lie in distinct LSDA ranges with landing addresses `0x26a38f0` and `0x26a38f2`. The future's read call is covered by a range landing at `0x2cc464a`; both selected reset-child calls share a range landing at `0x2cc4332`. These are encoded unwind-table facts, not proof that a particular error or unwinding occurred in execution.

### One fallback continuation

When the absent-path, reader-error or intermediate-sentinel arm reaches `0x2cc1279`, it constructs the tagged word `0x8000000000000003`; assuming the temporary helper and logging path preserve it, the classifier at `0x2cc1457` decodes it to 3 and falls through to `0x2cc1489`. By contrast the selected materializer tag ending in 1 takes the other classifier branch. A nonzero context mode byte at `+0x10` sends this fallback to `0x2cc1f06` with the context subobject at `+0x18`.

There, a count at subobject `+0x20` chooses between an allocation/copy length formed with a 64-bit scale of four and an empty representation whose raw pointer word is 1. If the separately tested subobject `+0x38` is nonzero while its `+0x28` word is zero, `0x2cc1f5d` takes an error boundary; a null nonempty allocation takes a different error boundary. Both reach `ud2` if the respective calls return. On the selected empty case, and after normal helper returns, the code stores the staged fields in the future, calls `0x2360050`, and jumps to `0x2cc48a0`. That continuation checks a thread-local condition and, for a sufficiently large helper-produced count, swaps 32-bit entries in a loop. Either selected out-of-bounds comparison reaches an error call and then `ud2` if it returns. This is not a claim about the random distribution, source-level container type or final result of the whole fallback path; the alternate TLS path and later continuation remain unresolved.

### Frozen-state decision and stores

Let `P` denote the selected materializer return **if** intervening helpers preserve the saved pointer. The following instruction excerpt is included for human reading; exact bytes and file offsets are in `windows.tsv`, `operands.tsv` and `transfers.tsv`.

```text
2cc1aa6  83 b8 e8 10 00 00 01    compare dword [P+0x10e8] with 1
2cc1ab3  48 8b 48 28             load qword [P+0x28]
2cc1ab7  48 39 88 f0 10 00 00    compare qword [P+0x10f0] with that word
2cc1abe  0f 82 1a 23 00 00       branch if unsigned below
2cc1ac4  0f 85 33 02 00 00       branch if unequal
2cc1c8b  49 c7 86 e8 10 00 00 00 00 00 00    store qword zero at [P+0x10e8]
```

| Guard | Byte-backed path |
| --- | --- |
| Low 32 bits at `P+0x10e8` differ from 1 | Bypass the following reset stores. This is a dword test even though the later reset writes a qword. |
| Low 32 bits equal 1 and unsigned `[P+0x10f0] < [P+0x28]` | `0x2cc1abe` reaches an assertion literal and `l1/src/exchange/exchange.rs:607:17`; if the indirect failure call returns, the jump reaches `ud2` at `0x2cc7f3b`. The words' role as freeze height and current height is supported by the literal, not a recovered Rust type. |
| Low 32 bits equal 1 and target is greater | Bypass the reset. |
| Low 32 bits equal 1 and target equals height | After a log-like path containing the literal prefix `applying hardfork to frozen local abci_state`, execute the ordered stores below. A hypothetical qword tag `0x100000001` meets this local dword test; validity of such a representation is not established. |

| Store or call | Observed value at that instruction |
| --- | --- |
| `P+0x10` | Copy the qword loaded from `P+0x28`. |
| `P+0x18` | Increment the previous qword with unsigned saturation at `0xffffffffffffffff`. |
| `P+0x20` | Copy the qword initially loaded from `P+0x30`. |
| `P+0x10e8` | Write eight zero bytes. |
| `P+0xdf0` | Copy the same initially loaded qword from `P+0x30`. |
| `0x2754c70`, then indirect boundary | Pass `P+0xd88` to the first helper; the following indirect call is a separate, unresolved boundary. |
| `P+0xef8`, `0x2754e50` | Reload `P+0x30` after those calls, store the reloaded word at `+0xef8`, and pass `P+0xed8` to the second helper. The two copies from `P+0x30` can differ if a call mutates it. |
| `P+0x3e28`, `P+0x3ee0`, `P+0x39b0` | After another indirect call, write two 16-bit zeroes and byte 2. |

The helpers contain their own data-dependent paths. In the first, a nonzero subobject `+0x40` with zero `+0x30` reaches a failure call followed by `ud2` if that call returns; a separate missing-item condition reaches another failure call. In the second, a nonzero subobject `+0x40` with zero `+0x30` reaches a failure call at the end of its selected FDE. They also call other helpers and traverse data; neither complete container semantics nor all helper effects are established.

### Selection and later handoff

The reset and bypass paths meet at `0x2cc1d06`. If future `+0xd8` is zero, control branches elsewhere; the selected continuation requires it to be nonzero. Before the ordering test, a qword returned at stack `+0x148` is subjected to two unsigned wrapping comparisons. For input `x`, constants are read from the pinned instructions:

```text
if ((x + 0xffdf3b645a1cac08) mod 2^64) <= 0xffbe76c8b4395810: use default comparison inputs
else if ((x + 0xffff574000000000) mod 2^64) < 0xfffeae7ffffeae81: use default comparison inputs
else: call the conversion boundary; zero result uses defaults, nonzero uses its selected outputs
```

At `0x2cc29c6`, the selected comparison takes the first 32-bit word as signed and the next two as unsigned. A lexicographically greater or equal left triple reaches `0x2cc29f4`; a smaller triple takes the alternate path. The tool's boundary examples are synthetic consequences of those instruction windows, not observed dates or runtime fixtures.

The successful ordering path reloads future `+0xe0` at `0x2cc2bbd` after logging and cleanup calls. At `0x2cc1295` it stores the pointer at future `+0x20` with the high-bit-plus-one tag. The later classifier selects this variant, and at `0x2cc16ae` the pointer is saved at stack `+0x20`. If the context mode byte is nonzero and state byte `+0xb9a` equals context byte `+0x5a`, the branch reaches `0x2cc180e`. In the selected empty/sentinel vector case, `0x2cc1958` reaches `0x2cc22cc`; normal allocation, helper and reference-count paths eventually reach the separately stored output pointer. Null allocation results for the selected `0x30`, `0x2f0` and `0xa8` requests reach size-specific failure calls and then `ud2` if those calls return. A reference-count failure also reaches that trap. Other vector, mode, suspension, conversion, allocation and unwinding paths remain unresolved.

The data-flow join assumes the helpers return normally, the selected branch predicates hold, the saved pointer and stack slot are not changed through aliases, and the copy-like calls have the effect indicated by their argument setup. The parent must then receive a non-2 result and its existing checker must accept it. These static conditions show a possible handoff; they do not prove that the branch occurs at runtime or that a later block uses the same object. Previous `RE-017-abci-loader-handoff-115`, `RE-017-abci-block-root-115`, and `RE-017-abci-linked-commit-115` packets independently trace selected constructor, begin/action/end and root-input continuations; matching offsets or a common boundary alone do not close their runtime identity gap.

### Historical #94 comparison

The original `RE-017-abci-state-link-94` lead is bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The optional check reconciles the #94 FDE/index entries for caller `0x32725d0` and callee `0x3273810`, decodes call `0x3272785` through its own relative relocation, and verifies the callee's reference to Location VA `0x56dfbf8` (file offset `0x56ddbf8`, line 107, column 37). It also checks the #94 comparison to 2. Independently, #115's previously located record is VA `0x64767a8` (file offset `0x64747a8`, line 123, column 37); this packet's new local reader passes a different `local_abci_state.rs` Location.

The #94 instruction at VA `0x3272799` forms a stack address at `+0x68`, and the checked qword-zero store at VA `0x327280f` (file offset `0x327180f`) addresses stack `+0xbf8`, a difference of `0xb90`. The new #115 store at VA `0x2cc1c8b` (file offset `0x2cc0c8b`) instead addresses its selected pointer at `+0x10e8`. These are independent release-specific observations: neither the addresses, layouts, tags nor whole path are assumed equivalent.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler/linker flags and two-build result: not yet applicable. Raw or normalized source-build comparisons, masks, and whole-ELF equivalence: not yet measured. The exact target windows are retained as research evidence and are not transplanted into a reconstruction. Dynamic binding, helper semantics, alias closure, other relocations and vtables, serialized state compatibility and a root digest remain unresolved.

## Results and limitations

The focused suite has 31 tests with no skips. Its negative controls alter the capture hash, an instruction, a direct-call displacement, an indirect-call displacement, a RIP-relative reference, a dispatch entry, two relocation fields, a source Location, a descriptor length, an FDE range and an LSDA encoding. It checks invalid and ambiguous address mappings, unsigned and saturation boundaries, all 256 possible trailing bytes, all 2,550 one-byte mutations of the selected 10-byte key, time-gate boundaries and selected unwind links. Synthetic tests validate the stated local models; they do not execute the capture or prove the models are a complete implementation.

The 15 selected FDEs and the named branches are bounded evidence, not a complete block path, function census, runtime trace or component-completion metric. No component gate or `docs/PROGRESS.md` milestone is advanced. In particular, the requested full begin/action/end-block-to-root scope remains incomplete: the selected reader-to-parent result is now grounded, but pointer identity through the later constructor and into block execution is still conditional.

Next question: can a previously unowned #115 continuation establish, without assuming alias preservation, which returned parent object is installed into the owner slot later read by the block engine, including the failure and replacement branches?
