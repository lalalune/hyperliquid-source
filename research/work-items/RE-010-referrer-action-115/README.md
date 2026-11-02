# RE-010: Trace the node 115 ModifyReferrer action

This packet makes it possible to reconstruct the selected `VoteGlobalAction::ModifyReferrer` arm as an internal tag `0x37` dispatch with distinct admission, referral-code collision, insertion, and replacement decisions, instead of treating the agent-created registration handler file as one original binary function.

- Component ID: `action-dispatch`, task `RE-010`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a locator, with no source copied.
- Claim status: observations are the recorded ELF bytes, selected table and relocation records, and their decoded branch operands; roles and logical field names are inferences. Runtime reachability and unvisited alternatives remain unresolved.
- Scope included and excluded: one nested governance action from its variant decoder and a conditional apply entry through selected status and state-write paths. This is not all exchange tags, all governance voting rules, full parser semantics, allocation/unwind closure, or an implementation.

## Reproduce

Run from the repository root on Linux x86-64. The recorded run used Python 3.12.3 and the standard library. The generator first verifies the complete input digest, reads the ELF as data, imports the repository's shared ELF/unwind parsers, checks selected bytes, and writes no absolute paths or timestamps. It does not start any external program or execute either captured artifact.

```sh
python3 tools/artifacts.py verify
python3 tools/node115_referrer_action.py --out research/work-items/RE-010-referrer-action-115
python3 -m unittest tests.test_node115_referrer_action
python3 tools/catalogue.py --check
(cd research/work-items/RE-010-referrer-action-115 && sha256sum -c MANIFEST.sha256)
```

For a determinism check, replace `<tmp-dir>` with an existing directory outside the evidence folder and compare these two fresh outputs:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/node115_referrer_action.py --out <tmp-dir>/one
PYTHONHASHSEED=8675309 TZ=Pacific/Honolulu python3 tools/node115_referrer_action.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The generated files are `functions.tsv`, `windows.tsv`, `branches.tsv`, `switches.tsv`, `name-neighbors.tsv`, `relocations.tsv`, `literals.tsv`, `constants.tsv`, `calls.tsv`, eleven `*-vectors.tsv` files, and `summary.json`; `MANIFEST.sha256` also covers this README. The vector files are synthetic bounded models, not captured node execution. All target-derived addresses, lengths, immediates, table entries, relocation records, raw windows, and hashes are extracted from the checked ELF. All windows are unmasked; no binary-matching denominator is asserted.

## Evidence

### Coordinates and boundaries

Addresses below are ELF virtual addresses and ranges are half-open. `functions.tsv` gives matching file offsets, `.eh_frame` FDE/CIE coordinates, lengths, and full-range hashes. The common parser reads each selected FDE's actual range, and the `.eh_frame_hdr` record is checked against it. An FDE is evidence of this unwind range, not proof that all possible functions or paths are catalogued. The selected windows and edges do not constitute a complete CFG.

| Role inferred from selected bytes | #115 FDE range or interior site | Established connection |
| --- | --- | --- |
| One-byte variant-name matcher | `0x287e450..0x287ec7f` | `K` selects a table arm producing ordinal `0x23`. |
| Name adapter and enum envelope | `0x1df0720..0x1df08a1`; `0x2943460..0x2944e93` | Adapter calls the matcher; envelope table ordinal `0x23` reaches `0x2943c20`, which calls the visitor. |
| Three-field visitor | `0x1df5340..0x1df6121` | Map and sequence success write tag `0x37`; diagnostic metadata identifies `VoteGlobalAction::ModifyReferrer`. |
| Serializer and clone | `0x28e7450..0x28e9911`; `0x2936420..0x2937647` | Independently use tag `0x37`, ordinal `0x23`, literal `K`, and the same selected payload offsets. |
| Conditional action entry | `0x2bf00f0..0x2bf1e87` | Input tag `0x37` takes the general vote-processing route; a returned tag `0x37` selects interior arm `0x2bf15bf` and then `0x28cd7a0`. |
| Vote-processing helpers | `0x2699750..0x2699937`; `0x28b02b0..0x28b1aa9` | The first calls the second, which clones the supplied action and conditionally writes a selected tag to its output. |
| Two-stage vote predicate | `0x28a9b70..0x28a9da1` | The first subcheck at `0x36c7f70` must return nonzero before the second, relocation-bound subcheck at `0x14cf1d0` is called. |
| Governance apply | `0x28cd7a0..0x28d8ac4`; arm `0x28ce583` | Tag `0x37` selects an interior arm, validates fields, and calls the shared core with flag 1. |
| Registration wrapper | `0x285c730..0x285c7dd` | Checks code length and calls the same core with flag 0 and a zero word. |
| Shared core and selected helpers | `0x3c193d0..0x3c1a24b`, with entry helpers at `0x3ccb770` and `0x3cc9c90` | Normal logical collision, insertion, and replacement paths; separate selected compact-insert and tree-removal FDEs are recorded. |

The table arm at `0x28ce583` is **inside** the governance apply FDE, not an FDE start. The standalone wrapper and shared core have their own independently verified ranges. Consequently a reference-file split such as `l1/exchange/handlers/15_register_referrer.rs` cannot establish a one-file/one-function boundary for #115.

### Selector and layout

The matcher subtracts `0x41` from a one-byte name and reads signed table entries relative to `0x5f9f68`. The `K` entry at VA and file offset `0x5f9f90` is `e4492802`, targeting `0x287e94c`, which writes ordinal `0x23`; neighboring `J` and `L` select `0x22` and `0x24`. The envelope entry at `0x5fe3d0`, bytes `dc583402`, reaches `0x2943c20` and its call at `0x2943c34` reaches the visitor. The visitor's diagnostic metadata uses a relative relocation to the exact string `struct variant VoteGlobalAction::ModifyReferrer with 3 elements`; a separate expectation formatter supplies the shorter type name. The serializer independently associates `VoteGlobalAction`, `K`, and field names `c`, `n`, `u` with ordinal `0x23`.

For map input, after assuming each individual field decoder and unknown-field skip succeeds, the selected visitor requires `c` and `u`, permits `n` to be absent, and sends a repeated `c`, `n`, or `u` to its duplicate-field error path. Missing `c` is tested before missing `u`. A `0x86` error carrier is separate from the success tag. The payload's inferred code string starts at action `+0x18`, its length word is `+0x28`, the option-like tag and word are `+0x08` and `+0x10`, and a 20-byte user key is at `+0x30`. The serializer's argument addresses and the apply arm's loads independently support these offsets. The underlying field type names, string encoding, and full parser/error behavior are not established here.

### Parent, conditional vote return, and apply

The parent first compares a prior callee's 16-bit status with `0x1a2`. If it differs and the separately computed byte flag is zero, the parent emits `0x95`; otherwise it proceeds. The predicate and the flag's business meaning are untraced. The selected input tag `0x37` normalizes to `0x23` at `0x2bf0223` and avoids the two low-range special cases, so the parent passes a `0xf0`-byte copy to `0x2699750` at `0x2bf0323`. The selected copy calls use slot `0x64df508`, whose ELF dynamic relocation names `memcpy`; actual runtime binding is not measured.

`0x2699750` calls `0x28b02b0`, which clones its input at `0x28b04a2`. On the selected later path, a prior flag must be zero and the result byte of the call at `0x28b1525` nonzero; otherwise control returns to a scan. At `0x28b1588` the current action copy is passed through the imported copy slot; at `0x28b1722` its first word is loaded and, if it is not `0x86`, is written to the result at `0x28b17c2`. The helper and parent then copy the selected result. This proves a **conditional** tag handoff, not when the vote predicate succeeds or that every input is selected. Nor does it prove the transfer from the independent envelope decoder to this parent's input.

The predicate at `0x28a9b70` constructs a first collection iterator and calls `0x36c7f70` at `0x28a9c5b`. A zero low byte immediately returns zero. Otherwise it constructs a second iterator and calls through slot `0x64e0160`; its `R_X86_64_RELATIVE` addend is `0x14cf1d0`, whose result is forwarded to the caller. Within the first subcheck, selected missing-root, compact-lookup-miss, and out-of-range branches converge at `0x36c80a3`, pass status `0x9b` to another helper, and return zero if that helper returns normally. This establishes short-circuit order, but neither subcheck's full criteria or the runtime relocation binding.

When the returned tag is `0x37`, parent table `0x60a558` selects `0x2bf15bf`, which rebuilds a tag `0x37` object and calls `0x28cd7a0` at `0x2bf0528`. In the latter FDE, `(tag - 0x14) = 0x23` selects table `0x5fc024`, entry `0x5fc0b0` (`5f252d02`), and arm `0x28ce583`. The arm calls through slot `0x64e6a38` at `0x28d243d`; its ELF `R_X86_64_RELATIVE` addend is `0x3c193d0`. The slot's runtime resolution is not observed.

| Ordered selected apply decision | Observation |
| --- | --- |
| Code length exceeds 100 | Return status `0x158`; this test precedes the number test. |
| Option-like tag equals zero | Ignore the payload word and pass zero to the core. |
| Tag is nonzero and word is at least `0x0ccccccccccccccc` | Return `0x154`, including the word. |
| Tag is nonzero and word is below that bound | Forward the word; pass stack flag 1 to the core. |
| Core returns `0x1a2` | The apply routine takes its selected success branch; other returned statuses are copied to an error result. |

No validity claim is made for every nonzero option representation. The arm operates on unsigned machine words. The separate flag-0 wrapper rejects length 101 or greater before invoking the core: it stores inner status `0x158` at output `+0x10` and outer tag `0x0f` at output `+0`; core success instead leads to outer tag `0x0e`.

### Core decisions and selected writes

`0x3c193d0` uses flag 1 for the selected governance arm and flag 0 for the registration wrapper. The table describes normal logical results if lookups, allocations, and writes return normally; status names are not inferred from another release.

| Mode and ordered condition | Result or selected update |
| --- | --- |
| Flag 1; length greater than 100 | Core status `0xa4`; the selected apply arm normally rejects this earlier as `0x158`. |
| Flag 0; user lookup fails, or its saturated sum is below 1,000,000 | `0xa9`; the wrapper's prior length guard takes precedence when both fail. |
| Flag 0; existing profile | `0xa8`. |
| Flag 1; profile exists and the desired code belongs to a different 20-byte key | `0xa7`. |
| Flag 1; profile exists and desired code is absent or belongs to that key | Replacement path: a selected tree representation removes the old code via `0x39023e0`, then entry helper `0x3cc9c90` is used for the new code. The observed profile stores replace its three string words, clear `+0x40`, and store the forwarded word at `+0x48`. |
| Profile absent; desired code already exists, even for the same key | `0xa7`. |
| Profile absent and code absent | Selected compact path inserts profile then code through `0x4548960` and `0x45479a0`; normal success is `0x1a2`. The selected compact record strides are `0x68` and `0x30`. |

The flag-0 sum checks carry; on overflow it calls a separate callback and clamps the arithmetic result to `2^64 - 1`. A later nonzero contribution can overflow again. These arithmetic decisions are bounded models; the traversal and callback are not emulated.

Both entry helpers first test whether the container's first word is `0x8000000000000000` and its count is below 32. In that case they clear representation fields and begin rebuilding before the final lookup result. Thus a later logical rejection does **not** prove that the underlying representation was untouched. Other representation branches, allocation failures, panic/unwind, ownership cleanup, and transaction rollback remain open.

### Historical lead, kept release-specific

The historical report at repository commit `6cdeb7bc` for #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`) discussed wrapper `0x27e30a0`, core `0x3744eb0`, and an unidentified arm inside FDE `0x2355f40`. That report explicitly left its selector unresolved. It supplied the question only: the #115 selector, FDE ranges, branch destinations, relocation, field offsets, and status words above were independently read from the #115 ELF using the generator and negative controls. This packet does not assert address, byte, or full behavioral equivalence between releases.

## Implementation and comparison

Independent Rust path: not yet implemented. Cargo dependencies, compiler/linker flags, two-build comparisons, masks, relocation and helper closure, and whole-ELF equivalence: not yet implemented/measured. The instruction evaluators interpret only the documented scalar gate instructions and use abstract lookup outcomes; the remaining vector files are models, not execution of the target or a reconstruction. No executable target fixture, networking, keys, or chain access is used.

## Results and limitations

The generated `summary.json` reports 21 selected FDEs, 92 pinned raw windows, 61 selected conditional branches, six selected table entries, 25 selected calls, and five selected relocations. These are selection counts, not function coverage or matching rates. The bounded output contains 140 apply-instruction vectors, six wrapper-instruction vectors, 18 mode-1 instruction decisions with lookup stubs, nine parent tag decisions, four parent admission decisions, eight vote-result gate decisions, four two-stage-predicate decisions, 24 representation guards, 341 map-presence models, 288 core logical models, and eight sum models. The 61 targeted unit tests passed with no skips; corrupted bytes, digest, branches, relocation/symbol data, out-of-range addresses, and boundary values are negative controls.

Full voting semantics, the decoder-to-parent transfer, alternate storage representations, error cleanup, and complete action dispatch remain unresolved. The `action-dispatch` gate stays 0/4. Next question: identify the caller and the two subchecks' criteria feeding the selected vote return, then validate the resulting state transition against a separately authored Rust implementation without running the captured node.
