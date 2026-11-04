# RE-015: node 115 alert-tracker initialization from global configuration

Node 115 builds two distinct, type-specialized alert trackers from the selected global-configuration directory and initializes their owner in a fixed order; a non-regular-file result attempts default serialization, while timestamp or read failures take a separate fallback that stores an error-like value.

- Component ID: `constants`, task `RE-015`, using `RE-001` for function-boundary evidence; the selected consumer is adjacent `base` code, not a claim that it belongs exclusively to `global_constants`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical unlicensed reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`, as recorded in the retained historical work. No reference implementation is copied or used as collector input.
- Claim status: observations are bounded byte sequences, FDEs, relocation entries, data descriptors, selected instruction edges and output stores; names and source-level roles are inferences; external helper internals, live file contents and full runtime behavior remain unresolved.
- Scope included and excluded: owner initializer, two tracker initializers, their two specialized readers and two writers, selected normal/error routes and LSDA call-site records. Generic formatting, metadata, synchronization, serialization internals, output publication and all other callers are boundaries. No function census, component completion or binary equivalence is claimed.

## Reproduce

Run from the repository root with the authenticated node #115 capture. The collector uses Python 3 standard-library byte reads and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it authenticates the entire input before decoding. It invokes no external program and does not execute either captured binary. This run used Python 3.12.3 on Linux x86-64; GNU objdump 2.42 was used separately for human inspection, never parsed by the collector or placed in generated files.

```sh
python3 tools/re015_tracker_initialization_115.py --out research/work-items/RE-015-alert-tracker-init-115
python3 -m unittest tests.test_re015_tracker_initialization_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

For independent deterministic outputs, use two distinct empty directories below a writable temporary directory. For example, from the repository root:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_tracker_initialization_115.py --out work/re015-tracker-a
PYTHONHASHSEED=93 TZ=Pacific/Chatham python3 tools/re015_tracker_initialization_115.py --out work/re015-tracker-b
diff -r work/re015-tracker-a work/re015-tracker-b
```

The generated files in either directory must match their counterparts beside this README. `README.md` and `MANIFEST.sha256` are authored separately and are not collector outputs. The manifest hashes every other file in this work item. Each reported VA is a linked ELF virtual address before rebasing; file offsets are separately provided. Ranges are half-open. FDE lengths are decoded from the capture and cross-checked against the unwind header; neither an FDE nor its presence in executable bytes proves a complete function census.

An optional independent comparison authenticates the historical capture if that separate file is available. It prints the comparison to standard output without changing the generated #115 evidence:

```sh
python3 tools/re015_tracker_initialization_115.py --out work/re015-tracker-old --compare-94 references/can1357-hl/bin/hl-node-mainnet-new
```

## Evidence

The new route starts at an initializer whose file relocation binds slot `0x64efeb8` to `0x150c020`. The constructor calls the `crit_msg_ignore` initializer first and the `bug_alert_ack` initializer second; after both return normally and the following allocation succeeds it copies their 96-byte results into owner offsets `+0x30` and `+0x90`. It also allocates 20 bytes, copies the captured `N/A (non-production)` marker, and initializes additional owner fields. These are local writes observed at this entry, not evidence about when a concurrent lazy initializer runs or whether any particular runtime configuration takes this path.

| Selected role | FDE VA interval | Selected role in the route |
| --- | --- | --- |
| Owner initializer | `0x150c020..0x150c1de` | Ordered calls, two result copies, additional owner stores, allocation failure and cleanup. |
| Ignore tracker | `0x154a360..0x154a89d` | Selected-directory template, regular-file branch, default/read result and failure stores. |
| Acknowledgement tracker | `0x1549e20..0x154a35d` | Same selected branch shape with its own descriptor and specialized callees. |
| Ignore / acknowledgement readers | `0x15039e0..0x1503d45`, `0x1503670..0x15039d5` | Expanded-path check, extension comparison, type-specific binary/text decoding and error results. |
| Ignore / acknowledgement default writers | `0x1504c10..0x1505077`, `0x1504330..0x1504797` | Exact special-device comparison, encoding selection, parent preparation and output handoff. |

Human-readable excerpt, checked against the full FDE and the generated transfer and reference records:

```text
150c02b  48 8d 35 86 01 ef 04  lea  0x63fc1b8
150c035  e8 26 e3 03 00        call 0x154a360
150c03a  48 8d 35 8f 01 ef 04  lea  0x63fc1d0
150c046  e8 d5 dd 03 00        call 0x1549e20
150c083  0f 11 43 30           store 16 bytes at owner +0x30
150c0c2  0f 11 83 90 00 00 00  store 16 bytes at owner +0x90
```

The location descriptors are RELATIVE relocations to the 20-byte diagnostic `base/src/crit_msg.rs` with line/column pairs 766:13 and 767:13. These source locations and the two captured names support the role labels; they do not establish the original Rust definitions. `references.tsv` independently resolves each selected seven-byte RIP-relative instruction from its first byte. The two name descriptors and all pointer slots are read from relocation records, rather than interpreting zero-valued on-disk pointer words as loaded pointers.

### Directory, descriptors and formats

Both tracker initializers load the same configuration slot `0x64e0918`, whose RELATIVE relocation points to the initial configuration cell `0x64f06c0`; they add `0x18` to that cell before constructing the first formatting argument. The selected complete template starts at `0x43ec01`. Its six tokens comprise three `c0` argument tokens, a 23-byte literal, a five-byte literal and a zero terminator; `template.tsv` retains every token and its VA. The second argument points at the captured pair `(1, 0)`, and the final argument points to one of the two relocated labels. The literal byte slices spell the separator-delimited `file_mod_time_tracker` segment and the `.json` suffix.

Under the compact-format interpretation established by the historical prefix-correction work, the result is the selected directory followed by that tracker segment, the selected label and `.json`; the argument contents and template tokens are observations, while that rendered composition and the meaning of the selected directory are inferences. The actual directory and formatter internals are not supplied by static inspection.

The data confirms the two labels are 13 bytes (`bug_alert_ack`) and 15 bytes (`crit_msg_ignore`). Their selected binary encoding/decoding call sites separately pass the captured type labels `BugAlertAcks` and `CritMsgIgnores`. These labels are evidence for different specialized paths; the full in-memory types and their encoders are not established by the labels alone.

### Initializer decisions and owner output

| Local condition, assuming the preceding call returns normally | Byte-backed result |
| --- | --- |
| Regular-file predicate returns zero | The initializer writes the three words `0, 8, 0` into a temporary value, calls the corresponding default writer, and on a zero result copies that temporary into tracker output `+0x18..+0x30`. The writer's callees are boundaries, so preservation of the temporary through every helper is not assumed. |
| Default writer returns nonzero | The initializer calls the captured unwrap-diagnostic boundary at `0x1680c30`; the local continuation reaches `ud2` if that boundary returns. |
| Regular-file predicate returns nonzero; timestamp result tag is 1 | The selected route skips the value reader and goes to the fallback route. |
| Timestamp tag is not 1; reader returns first word `0x8000000000000000` | The selected `neg`/overflow branch reaches fallback rather than the loaded-value route. |
| Reader returns a different first word and original formatted-path word differs from that sentinel | The tracker copies three value words to `+0x18`, `+0x20`, `+0x28`, copies the timestamp fields beginning at `+0x50`, and writes zero at `+0x48`. |
| Fallback after a returned timestamp or reader error | After a logging boundary, the code writes `0, 8, 0` at `+0x18..+0x30` and stores the carried error-like word at `+0x48`. A separate sentinel branch involving the original formatted-path word also reaches this block; its feasible inputs and carried value are unresolved. |

The selected initializers write binary64 bits `0x4014000000000000` at `+0x30`, which represent 5.0. Their default/fallback code also writes integer `0xf6401a` at `+0x50` and zero at `+0x58`; the exact source-level time representation and units are not proven here. `route-probes.tsv` models the local branch sequence for 11 supplied combinations, including precedence and neighboring sentinel values. These synthetic inputs are algebraic controls, not executions of the node and not proof that each combination is reachable.

The owner's allocation-failure branch leads to the allocation-failure boundary and then `ud2` if that call returns. The LSDA table entry covering the second initializer call selects landing `0x150c1c5`, which calls the first tracker's cleanup helper before the unwind boundary. The entry covering the owner's allocation-failure call selects `0x150c1a8`, whose selected code calls both cleanup helpers. `exception-headers.tsv` and `exception-edges.tsv` decode all call-site rows for the seven selected LSDAs; action-table contents and the full unwind semantics are deliberately left opaque.

### Reader and writer boundaries

Each specialized reader first calls the same expansion and regular-file predicate boundaries. On a nonzero predicate result it examines a path-component result and compares the selected extension slice with the three captured bytes `72 6d 70`. A nonzero comparator result selects the binary read/decode sequence; the alternate result selects the text read/decode sequence. The two instances use different type-specific decoder targets. Failed reads or decodes reach separately identified error-construction boundaries and produce the signed-minimum result word on the selected paths. A zero predicate result constructs a missing-file diagnostic and the same outer error sentinel. Exact path-component parsing, comparator behavior, codec grammar and external read behavior remain boundaries.

The two default writers have a local nine-byte comparison: if the length and all compared bytes match the captured device sentinel `2f6465762f6e756c6c`, the code returns zero before encoding or output handoff. Otherwise the writer uses the extension comparison to select binary or text encoding; the selected nonzero/error-sentinel branches reach type-specific error construction. On a successful encoding route, a parent-directory predicate can lead to a creation helper with mode field `0x1ff`; a nonzero creation result is wrapped as an error, while the selected passing route calls the output boundary at `0x15024a0`. That shared boundary is already covered by open RE-009 work #2123 and is not selected as a new function here. No claim is made about successful file creation, publication atomicity, final syscalls or durability.

`device-probes.tsv` contains the exact byte match, both neighboring lengths and nine single-bit changes. These probes evaluate the lifted local comparison after checking both instances' instruction witnesses; they do not execute the captured binary. Other path representations and invalid runtime pointers are untested.

### Historical leads and release separation

The old clues remain bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The optional comparison above independently authenticates both files, resolves the old RIP displacements and selected old descriptor, and reads the matching #115 bytes; it does not inherit any #94 coordinate as a #115 coordinate.

| Lead | Node #94 linked VA | Node #115 linked VA |
| --- | --- | --- |
| Complete `cham` suffix entry | `0x1fc0ec`, referenced at `0x164f840` | `0x44ab69`, referenced at `0x17780f3` |
| Complete `static_config` suffix entry | `0x1ef5f5`, referenced at `0x164fbae` | `0x4401ef`, referenced at `0x177840e` |
| `NvTestnet` descriptor | slot `0x5668488`, index 32 | slots `0x63f8998` and `0x6410ef8`, index 33 in both selected arrays |

The selected default-immediate bytes are `40b520` at #94 VA `0x164fc56` and `40b521` at #115 VA `0x177845c`. These are cross-release context already treated by open #2042 and #2054, not newly selected #115 function bodies; this packet's new work is the seven consumer FDEs above. The old 76-row discriminator inventory is not reproduced. The historical `RE-015-format-prefix-correction-94`, `RE-015-rip-xref-tail`, and `RE-015-xref-instruction-starts` work items remain tied to the old digest in the parent of the stated source commit.

### Generated records

`functions.tsv` records seven FDEs and their full-body hashes; `references.tsv`, `relocations.tsv`, `literals.tsv`, `label-descriptors.tsv`, `locations.tsv`, `template.tsv` and `name-descriptor.tsv` bind data and references. `branches.tsv`, `transfers.tsv`, `witnesses.tsv`, `windows.tsv`, `exception-headers.tsv` and `exception-edges.tsv` retain selected control flow, byte windows and all call-site rows from these seven LSDAs. `route-probes.tsv` and `device-probes.tsv` are finite models of selected predicates. `summary.json` records their byte-derived counts and the target digest.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo dependencies, compiler/linker flags, source-to-target byte comparisons, masks, complete helper closure, and runtime differential results: not yet measured. No captured machine bytes are transplanted. The 25 focused unittest cases include wrong hashes, body corruption, invalid/non-file-backed and overlapping spans, broken relocations and descriptors, altered opcodes/displacements, malformed LSDA encodings and ranges, sentinel boundaries, device-byte changes and deterministic generation. All 25 passed with no skips in a Python-only PATH.

## Results and limitations

The collector validates seven selected FDEs totaling 7,120 bytes, 61 conditional branches, 66 transfers, 36 instruction witnesses, 25 RIP references, 21 RELATIVE relocations, 54 LSDA call-site rows, 20 byte windows, 12 device probes and 11 abstract route probes. The two separately generated evidence sets matched byte-for-byte with different hash seeds and time zones. Artifact hashes and signatures, the catalogue check and inventory reproduction passed. The repository-wide unittest discovery was not run under the requested memory constraint.

These numbers are a bounded evidence inventory, not an instruction or component coverage denominator. The record does not prove every branch in the seven FDEs, complete exception actions, the behavior of shared helpers, actual output paths or any filesystem effect. It does not provide Rust implementation or an equivalence comparison, and requests no component gate. Next: connect a separately unowned refresh/update consumer to these tracker outputs and establish its value-replacement and timestamp precedence using #115 bytes.
