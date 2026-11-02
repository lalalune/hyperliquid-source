# RE-015: network-selected configuration publication in node 94

This packet shows how a four-value input selects three different fields of the configuration object and passes their copies into guarded global alert state, while input zero exits before those writes; a reconstruction can now preserve that selection, publication order and the local failure routes.

- Component ID: `constants`, task RE-015; the alert-state consumer is the bounded downstream path.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit: `e5c9b6436876b2a4a39daef813171f9879317699`. The inferred, unlicensed reference commit `999556f6e0a474b8312db96ec3149e1c44e97c23` was used only to locate questions.
- Claim status: FDE ranges, instruction encodings, relative targets, table entries, relocation addends and local stores are observations. The four network names for the input bytes follow the prior reader's index correspondence; alert-state roles and the interpretation of the format template are inferences. External calls, exception actions and runtime values remain unresolved.
- Scope: the previously unclaimed entry, two context callbacks, an auxiliary initialization helper and an unwind cleanup helper, plus a four-entry table, selected state cells and failure routes. The earlier static-config and JSON-file initializers, their parsers, the Once dispatcher, allocator, formatter, dynamic callees, #115, visor and the whole component are boundaries.

## Reproduce

From the repository root, with the authenticated node #94 artifact present:

```sh
python3 tools/config_channels94.py --out <tmp-dir-one>
python3 tools/config_channels94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
python3 -m unittest tests.test_config_channels94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-015-channel-publication-94 && sha256sum -c MANIFEST.sha256)
```

Use two distinct empty writable directories in place of the placeholders. Compare each generated file with its same-named file in this work item. The collector verifies the full input size and digest before parsing; imports the shared ELF and FDE readers; rejects ambiguous, out-of-range and non-file-backed address mappings; and reads selected RELA records directly. Its restricted x86 instruction-length and transfer reader rejects unsupported and truncated instructions and direct local branches into operands. It neither runs the captured binary nor invokes an external program. `data.tsv` retains the complete selected format entry and length-delimited diagnostic as hex.

For the determinism check, the collector was run with distinct hash seeds and time zones and a PATH with no binutils. GNU objdump 2.42 was used only for human inspection, and none of its output is consumed by the collector or tests.

## Evidence

All addresses are linked ELF virtual addresses (VAs), not runtime addresses. `functions.tsv` records FDE ends, file offsets and body hashes. An FDE extent is an unwind-described range, not proof of a complete function census. `instructions.tsv` partitions the five selected extents, `transfers.tsv` lists their transfers, and `witnesses.tsv` pins the selected operands and sites. A target in an instruction row can be a RIP-relative memory address rather than a control-transfer destination.

| Selected FDE | Bounded role inferred from bytes |
| --- | --- |
| `0x143c510` | Index a four-entry table, copy selected optional fields, and update guarded state |
| `0x143eab0`, `0x1437d90` | Two vtable callbacks with the same initializer and copy pattern |
| `0x145d111` | Conditional auxiliary Once dispatch called by the entry |
| `0x143fa70` | Cleanup of two optional string-like values on entry unwind routes |

### Selection and publication

The four signed table slots begin at `0x2193f8` and contain offsets relative to that same base. `selector.tsv` extracts each slot and destination; `relocations.tsv` independently binds the four prior name descriptors. The pairing of the input index with those names relies on the previously documented four-name reader and is a conditional interpretation, not a new claim about every caller.

| Input / prior name | Table destination | Selected config offset |
| --- | --- | --- |
| 0 / Local | `0x143cdc7` | None; local epilogue |
| 1 / Sandbox | `0x143c562` | `+0x100` |
| 2 / Testnet | `0x143c589` | `+0xe8` |
| 3 / Mainnet | `0x143c5d8` | `+0xd0` |

After the initial lazy-state guard, index 0 jumps to the epilogue without a local visit to the state-write site. For indices 1–3, the entry loads relocation slot `0x576eb70`, whose addend is object `0x577a898`, checks its Once word at `+0x268`, and compares the selected field against the signed-minimum sentinel. Non-sentinel fields supply pointer/length values and take allocation and copy paths; zero lengths take separate local paths. The Testnet and Mainnet arms also revisit the `+0xd0` field at `0x143c70d`. The exact meaning, contents and validity of the incoming fields remain external assumptions.

A prior configuration-file packet binds the initializer at `0x13d28e0` and its directory-rooted template; a separate map packet binds this same object to a configuration lookup. Here the RELA record at object `0x577a898` points to that prior initializer. The entry's vtable at `0x5669fe0` has relative relocation slots `+0x18` and `+0x20` for the two selected callbacks. Both callbacks clear their supplied context slot, test the obtained object pointer and state byte, and, on their normal initializer return, copy `0x268` bytes from a stack result to the object. The copy is not asserted atomic. This bridges the prior initializer boundary to the selected consumer without reselecting the earlier functions.

At `0x143c93f` the entry uses a locked compare-exchange on `0x577ad08`; contention takes a separate helper path. A sentinel at `0x577ad10` selects a factory call through `0x577acf0` followed by a `0x118`-byte copy. At `0x143c97e` it writes byte 1 at `0x577ae20`. Following an external state helper and formatter, it replaces selected three-word regions at `0x577ad10`, `0x577ada0` and `0x577adb8`. A later scalar loop compares input bytes with `0x20` and selects `0x5f` before writing a separate value at `0x577ad28`; vector paths are present but their complete transformation is not modeled here. Prior contents have conditional cleanup calls. Normal exit unlocks through the compare-exchange at `0x143cdb3`, with a distinct contended-release helper route.

The formatter receives the complete 24-byte template at `0x1e37d4`, whose literal portions include ` chain=` and ` ips=[`; `data.tsv` gives the bytes. These literals support the alert-context interpretation but do not establish actual host addresses or a rendered value.

### Local failure and cleanup boundaries

The conditional at `0x143cb09` bypasses the check unless the byte at `0x577ae20` equals 1; when it does, a set low bit in `0x577ae21` takes the branch to `0x143ce17`; that site passes the 61-byte assertion diagnostic in `data.tsv` and then reaches a trap if its external helper returns. Allocation failures have separate call sites `0x143ce93`, `0x143cea3`, `0x143ceb4`, `0x143cec4` and `0x143ced2`; the selected local sequence reaches `ud2` if the external failure calls return. Their internal behavior is not inferred.

Each callback has distinct null-pointer and state-byte-one branches, recorded in `callbacks.tsv`. A null branch calls one external helper and then falls through to the state-failure helper if the first returns; the following byte is a breakpoint at the exclusive FDE end if the latter returns. The entry's landing pads call cleanup `0x143fa70` on selected temporary pairs before the external unwind continuation. Allocation, deallocation, formatting, panic and synchronization internals are boundaries.

`cfg.tsv` records seven restricted graph propositions, including that the index-0 epilogue cannot reach the flag write in the local graph and that each of the other table destinations can reach it. This graph considers both conditional edges, assumes calls return and stops at indirect jumps; reachability is not proof of a feasible runtime input and the graph does not model exception edges.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo manifests, dependency locks, compiler/linker settings, captured-runtime tests and raw or normalized comparison are not yet available. There are no comparison masks. The complete helper, dynamic call-target, relocation, vtable/data and whole-ELF closures remain separate gaps.

## Results and limitations

The deterministic output covers five selected FDEs, 3,153 bytes, 694 admitted instructions, 174 transfers, 59 selected witnesses, 11 relocation records and seven restricted CFG queries. The focused suite passed 19 tests with no skips, including corrupted identity, code, table, descriptor, template and relocation controls; out-of-range, NOBITS, ambiguous-section and malformed-instruction controls; and two independently generated output trees. Runs with different hash seeds and time zones and no binutils on PATH produced identical output. Artifact verification, catalogue checking and inventory/literal reproduction passed.

The prior `NvTestnet` default and `/static_config`/`/cham` entries are context, not newly decoded here; the packet does not show that a particular AWS-name byte produces any particular input index. It does not establish all indirect targets, full error-object lifetimes, concurrent interleavings, input indices outside 0–3, actual alert delivery or the entire configuration component. No node or visor execution occurred and no component gate is advanced. Next question: follow an unowned caller's network-byte construction and prove its relationship, if any, to the previously established AWS-name default.
