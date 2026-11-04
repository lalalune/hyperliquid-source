# RE-009: compact ABCI state to root and freeze snapshot

Under the selected copy and dispatch conditions, a node #115 task carries the pointer at constructor input `+0x320` to a root visitor and, on the special branch, to the `state.rs:201` snapshot writer, whose 64-bit freeze-tag comparison differs from the visitor's 32-bit comparison.

- Component ID: `abci`; RE-009 covers the state-root and snapshot part of RE-017.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was a navigation lead only and no source was copied.
- Claim status: selected bytes, FDE extents, relocations, instructions and literals are observations; the data-flow joins and arithmetic interpretations below are inferences under the stated conditions. Synthetic cases are not observations of a running target.
- Scope included and excluded: one compact-state route from an upper caller to two invocations of the end selector, the listed collection and root/snapshot branches, selected state writes and a partial returned-result handoff. The process entrypoint, complete action handling, all root inputs, runtime loader-to-caller identity, full snapshot contents and component gate are unresolved.

## Reproduce

Run from the repository root with `artifacts/node/115/hl-node` and the repository's `tools/elf_index.py` and `tools/fde_extents.py` present. Use empty temporary output directories and set `TMPDIR` to an available writable temporary directory.

```sh
python3 tools/abci_freeze_snapshot115.py --out research/work-items/RE-009-abci-freeze-snapshot-115
python3 -m unittest tests.test_abci_freeze_snapshot115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
: "${TMPDIR:?Set TMPDIR to a writable temporary directory}"
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_freeze_snapshot115.py --out "$TMPDIR/re009-freeze-one"
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_freeze_snapshot115.py --out "$TMPDIR/re009-freeze-two"
diff -r "$TMPDIR/re009-freeze-one" "$TMPDIR/re009-freeze-two"
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-009-abci-freeze-snapshot-115 "$TMPDIR/re009-freeze-one"
(cd research/work-items/RE-009-abci-freeze-snapshot-115 && sha256sum -c MANIFEST.sha256)
```

For the optional release-specific historical anchor check, the following additionally requires the historical binary from the navigation reference; it does not change the generated #115 evidence:

```sh
python3 tools/abci_freeze_snapshot115.py --old-elf references/can1357-hl/bin/hl-node-mainnet-new --out "$TMPDIR/re009-freeze-history"
```

The input is authenticated before output is created. The tool uses Python's standard library and the shared ELF and FDE parsers; it does not execute either binary or call another program. On Linux x86-64, the focused tests and generator ran with Python 3.12.3, including with Python available but binutils absent from `PATH`. GNU objdump 2.42 was used only for human instruction inspection; the generator and tests do not parse or invoke it. Output hashes are in `MANIFEST.sha256`. The commands do not access the network, keys or chain.

## Evidence

All addresses below are linked ELF virtual addresses; generated records include file offsets. The extractor authenticates the complete ELF, parses its sections and relocations, checks the `.eh_frame` records against `.eh_frame_hdr`, and checks 31 selected FDE extents and 103 exact byte windows without normalization. An FDE is an unwind range, not proof of source-level function boundaries or a complete caller/CFG census. The 85 decoded transfers are explicitly selected sites, not an instruction count. `functions.tsv`, `windows.tsv`, `transfers.tsv`, `locations.json`, `constants.json`, `task.json`, `upper.json`, `collection.json`, `root.json` and `captures.tsv` retain the byte-backed records. The other generated files contain explicitly synthetic models and counts.

### Observations: entry, collection, and return

| Stage | Selected coordinates | Observation |
| --- | --- | --- |
| Task construction | `0x2b3aba0` | Selected copies carry constructor input `+0x320` to the allocated task at `+0x360`. The task stores a pointer to slot `0x6449fb0` at task `+0x10`; that slot has a unique relative relocation to upper dispatch `0x2b1df60`. A final copy transfers `0x400` task bytes before the scheduler call. A null task allocation reaches a failure call. The scheduler's dynamic invocation and the constructor input's origin are not observed. |
| Upper dispatch | `0x2b1df60`, `0x2b1e11a..0x2b1e1f8` | Two external copy calls place an incoming pointer from input `+0x360` at upper-stack `+0x990`, then at seed-stack `+0x620`; the constructor input begins at stack `+0x200`, so the pointer is at constructor-input `+0x420`. The copy slot's ELF relocation names `memcpy`; its runtime binding is not observed. A null 24-byte allocation reaches the failure call at `0x2b1eddd`. |
| Context construction | `0x2d275d0`, call `0x2d2766f` | The constructor places that pointer at local context `+0x450`, calls the end selector once on that local context, processes its returned buffer, and copies `0x470` bytes to its caller. On normal return, the upper output begins at stack `+0xd18`; its state-pointer slot is `+0x1168`. The upstream copy, helper and alias conditions below still apply. |
| Block adapter and engine | `0x2774590` -> `0x2d23610` | The upper call at `0x2b1e3ee` supplies the context output to the adapter. The adapter reads its input `+0x20`, then the engine reads context `+0x450`, saving the old tag and target from state `+0x10e8/+0x10f0`. On the selected route the engine calls the separately studied clock helper `0x2bdf270` and later the end selector at `0x2d24ed9`. The helper is a boundary, not newly owned here. |
| Item collection and join | `0x22ed710` -> `0x2ccdbf0`; `0x26a1e90` -> `0x231b370` | The collection call receives the state-pointer slot and returns a three-word record subsequently passed to a length-checked join. The reserve operation uses 32-byte elements; the join forms selected 40- and 24-byte input spans and a 64-byte output stride. Full element meanings and helper effects are unresolved. |
| End-result handoff | `0x2d24fbd..0x2d24fea`, `0x2b1e511..0x2b1e55a` | The engine copies `0x80` bytes of the end result to its output `+0x78` and writes a separate byte at `+0xf8`. The upper stack receives the result at `+0x200`; the corresponding first end-result word is `+0x278`. The upper path treats `0x8000000000000000` as a cleanup bypass and checks zero before a release call. Subsequent uses of all returned fields are not closed. |

The join compares the two input lengths at offset `+0x10`. A mismatch reaches a failure call and `ud2` at `0x26a1f39` if that call returns. In the selected allocation, the product must fit the checked bound `0x7ffffffffffffff8`; for 64-byte rows the maximum is `0x1ffffffffffffff` items. A zero-size path uses the raw value 8; a nonzero allocation failure also reaches a failure call and `ud2` if it returns. The 32-byte reserve checks available capacity, checks again after a grow call, and compares the produced count with the requested count before advancing its stored length; the underflow, insufficient-capacity and count-mismatch exits are separately recorded. `collection-cases.json` covers synthetic neighbors of these checks, not the implementations of the grow or producer helpers.

### Observations: ordered freeze and snapshot decisions

Let `height` be the qword at state `+0x28`, `tag` the field at `+0x10e8`, `target` the qword at `+0x10f0`, `mode` the dword at context `+0`, and `interval` the qword at state `+0x39c8`. Height and target comparisons below are unsigned. These rows describe the selector at `0x2d25620`; the engine's earlier checks also apply when it is called from the block engine.

| Test in instruction order | Observed selected consequence |
| --- | --- |
| Engine entry: full 64-bit `tag == 1`, `target < height` | Branches to `0x2d2523c`, which references the literal `assertion failed: freeze_height >= self.locus.context.height()`. |
| Engine entry: full 64-bit `tag == 1`, `target == height` | Takes a different branch, referencing `assertion failed: !self.state.is_frozen()`. A non-1 full tag bypasses both tests. |
| End selector: height is not periodic, low 32-bit `tag == 1`, `target < height` | The first past-target failure precedes the mode test. |
| No first failure and low 32-bit `mode == 2` | Stores `0x8000000000000000` as the result's first word and takes the return path. |
| No prior exit, low 32-bit `tag == 1`, `target < height` | Takes the later past-target failure. In the periodic case this is the first such check reached. |
| No prior exit and height periodic, or low 32-bit `tag == 1` and `target == height` | Enters the root path without interval division and sets the later snapshot condition. |
| No special condition and nonzero interval | Divides height by interval; a nonzero remainder bypasses the root path, while zero remainder enters it. This ordinary interval path does not pass the later snapshot condition. |
| No special condition and interval zero | The reached division instruction has a zero divisor. Whether this input can occur and any external exception handling are unresolved. |

The selected code multiplies height by `0xd288ce703afb7e91`, rotates right by 4 and compares unsigned against `0x68db8bac710cc`. The multiplier's inverse modulo `2^64` is 625. As an inference from these bytes, the comparison accepts precisely the unsigned multiples of 10,000: acceptance forces the low four product bits to zero, and for the remaining values the inverse relation maps the accepted interval exactly to `10000 * k` without u64 wrap. The boundary tests check this inference, including values near `u64::MAX`; the mathematical argument supplies the general claim.

After the selected root call, the following are two distinct guarded context-write paths, not unconditional state updates:

| Guard | Exact selected stores |
| --- | --- |
| Context `+0x400 == 0x8000000000000000` and context `+0x418 < 32` | Zero eight bytes each at context `+0x408` and `+0x418`. |
| Context `+0x400` differs from that sentinel, the lookup call at `0x2d25925` returns nonzero, and context `+0x418 >= 64` | Store 0 at context `+0x400`, 8 at `+0x408`, and 16 zero bytes at `+0x410`. |

Other branches and all meanings of that context object remain open. On two selected intervening paths, the code saves the condition in `ebx` at stack `+0x88` and later restores it; another selected call preserves it through `ebp`. For the snapshot condition, the selector chooses the literal `freeze` when the selected tag and target equal the height and `periodic` otherwise, and calls `0x22ed1f0` at `0x2d262ea`. The 0x38-byte returned record is then carried into the selected end-result construction.

### Observations: root-field and snapshot handoffs

The selected root chain is `0x2d25712` -> `0x2bb37c0` -> `0x26a21b0` -> `0x269a1b0` -> `0x2b7f5b0` -> `0x29f9300` -> the selected serial worker `0x26e1660`. The worker's split/parallel alternatives and all callback bodies are not closed. The 74 capture pointers in `captures.tsv` are decoded from a selected straight-line instruction sequence. The first descriptor groups 16 captures; the next 58 select one each. Capture 28 is state `+0x10e8` and is passed to descriptor 13. The capture function prepares 59 slots of 24 bytes, initialized to `0x8000000000000001`. The descriptor at `0x644b4b0` has raw words `[0, 16, 8, 0, 0]`; its two unique `R_X86_64_RELATIVE` entries bind `+0x18` to visitor `0x22a0fa0` and `+0x20` to a constructor `0x22a0b60` that initializes two 24-byte child slots.

The visitor compares only the low 32 bits of the tag with 1. If they equal 1, and its container and first-child checks succeed, it supplies field `+8` to the first child and then the eight-byte literal 1 to the second. If they differ from 1, it skips the payload and supplies the eight-byte literal 0 to the second child. Invalid container status and a first-child result other than 4 exit earlier. After the builder, status 4 reaches a separate reduction call; a different status selects a zero-filled local representation. The final root algorithm and digest are not derived here.

The selected snapshot chain is `0x22ed1f0` -> `0x26a23d0` -> `0x269ab70` -> `0x26a2810` -> `0x22ebdc0` -> `0x2c6bee0` -> `0x2ceabe0` -> `0x25e9c70`, conditional on the recorded helper, flag and direct-branch checks. The builder uses `state.rs:201:9`; the write handoff uses `state.rs:195:17`. The top and inner writer request maps with 1 and 59 fields; in the named-field mode the outer key is `exchange` and the selected inner key is `scheduled_freeze_height`. The corresponding normal-capacity map header bytes are `81` and `de003b`.

The field writer compares the **full 64-bit** tag with 1. On its selected normal-capacity path a different tag writes `c0`; tag 1 and a payload below `2^32` write these bytes:

| Payload range | Field-value bytes |
| --- | --- |
| 0 through 127 | One byte containing the value. |
| 128 through 255 | `cc` followed by one value byte. |
| 256 through 65,535 | `cd` followed by two big-endian value bytes. |
| 65,536 through 4,294,967,295 | `ce` followed by four big-endian value bytes. |
| 4,294,967,296 through `u64::MAX` | Delegated to a helper outside this packet; its output remains unresolved here. |

These are MessagePack-compatible value encodings inferred from the checked markers and stores, not a claim that the entire snapshot is reproduced. A name-write, unsigned-write or growth failure returns a non-success record; the caller checks for `0x8000000000000004`. A different record takes the `state.rs:193:56` failure path. A nonzero output-helper result takes the `state.rs:195:64` failure path; a later nonzero preparation result takes `state.rs:201:32`. Those selected error calls are followed by `ud2` if they return. A marker can already have been written before a later growth failure; rollback has not been established.

### Inferences, controls and release boundaries

The pointer arithmetic above joins the selected task and upper inputs, context constructor, engine, root and snapshot sites only on normal helper returns, conforming calls to the externally bound copy routine, the scheduler selecting the recorded dispatch slot, and no intervening alias writes that replace the pointer. The loader packet `RE-017-abci-loader-handoff-115` reports a #115 loader path that clears state `+0x10e8`; matching offsets alone do not prove that its returned object is the pointer at task-constructor input `+0x320`. Its loader GOT slots and call sites are not repinned here. The separate `RE-017-abci-block-root-115` packet already describes an expanded-state block and root implementation with analogous conditions, result-byte rule and descriptor visitor. This packet examines distinct compact-state function addresses and adds the `state.rs:201` snapshot route; it does not claim those general rules were first discovered here.

For the final byte, the compact engine takes the low 32 bits of the old and new tags. If their bitwise AND is nonzero it stores 1 when payload qwords differ and 0 when they match; otherwise it stores the low byte of their OR. For canonical 0/1 tags this acts as a change indication. Synthetic noncanonical inputs show why a reconstruction should not silently replace the actual rule with a boolean comparison: for example, old tag 2 and new tag 0 yield byte `02`. Such inputs are negative controls only; no claim is made that they are reachable in the node. Likewise, the root visitor and end selector compare 32 tag bits, while the engine entry and snapshot field writer compare all 64.

The historical RE-017 state-link record applies to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The optional cross-check authenticates that binary, validates old caller `0x32725d0`, old wrapper `0x3273810`, call `0x3273862` and `state.rs:107:37` Location `0x56dfbf8`; independently, it validates #115's `state.rs:123:37` Location `0x64767a8` referenced at `0x3c1352f`. These are release-specific navigation anchors, not equivalent layouts or behavior. No #94 instruction, offset or source label is promoted to a #115 fact.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph and build flags: not yet implemented; two-build comparison, raw and normalized implementation comparisons, masks, helper and dynamic-binding closure, vtable/data closure, and whole-ELF comparison: not yet measured. Raw target windows are evidence only and are not transplanted into implementation. No target process was run.

## Results and limitations

`summary.json` records 31 selected FDEs, 103 selected byte windows, 85 selected transfers, 5 Location records, 3 contextual relative relocation witnesses, 74 root captures and 59 initialized root slots. The root descriptor has two additional relative relocation records, and the task dispatch has one. It also records 25 selector/wire cases, 12 change-byte cases, 13 collection cases and 8 context-mutation cases; these are synthetic controls, not runtime traces or coverage percentages. The focused suite has 28 passing tests and no skips, covering digest failure before output, a changed byte in every selected window, transfer displacement changes, invalid or NOBITS mappings, duplicate and changed relocations, task-copy, capture and descriptor damage, bounded state writes, selected integer marker boundaries, both comparison widths, allocation and length failures, divisor zero, and periodic and u64 boundaries. Different hash seeds and time zones produced identical outputs. Artifact signature/digest verification and the catalogue check passed.

This packet does not satisfy the complete begin/action/end-block task or request an `abci` progress gate. It does not establish the full set of action variants, all branches or resulting state changes, the wide-integer writer, loader-to-task-pointer identity, snapshot completion under real I/O, the tree digest, a Rust equivalence comparison, hosted CI, or node execution. Next question: establish whether the earlier loader's returned pointer becomes the task-constructor input `+0x320` without re-owning the already studied parent, and identify intervening calls or alias writes that can change state `+0x28` and `+0x10e8..+0x10f7` before either end-selector call.
