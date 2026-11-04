# RE-021: node 115 scaled precompile route and frame state

The node 115 reconstruction can now distinguish the conditional tenfold-gas address-09 route from the ordinary registry route, including its activation inputs, alternate routing, frame checkpoint and failure boundaries.

- Component ID: `evm`; RE-021 is a bounded extension of RE-011 rather than a row in `docs/TASKS.md`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` is an unlicensed lead, not copied source. The #94 report is historical material in repository history.
- Claim status: observed file bytes, selected FDE intervals, relocations, instruction shapes and encoded call-site tables; inferred field roles, conditional dataflow, arithmetic and state transitions; actual fork inputs, runtime aliases and full execution remain unresolved.
- Scope included and excluded: a selected upstream configuration-to-alternate-frame-to-scaled-address-09 route, its private/ordinary alternatives, frame checkpoint and selected ordinary/exceptional exits. The value-transition helper is an external boundary; the callback body, generic registry and rollback helper are external boundaries already covered by open PR 2049. Neither their FDE bodies nor their previous evidence are resubmitted. All other EVM routes, full provider initialization, host/database effects, output equivalence and complete private-fork boundaries are excluded.

## Reproduce

From the repository root with Python 3.12 and the authenticated node #115 artifact present:

```sh
python3 tools/evm_scaled_precompile115.py --out research/work-items/RE-021-scaled-precompile-route-115
python3 -m unittest tests.test_evm_scaled_precompile115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For a separate repeatability check, replace `<tmp-dir>` with an existing writable directory:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/evm_scaled_precompile115.py --out <tmp-dir>/one
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/evm_scaled_precompile115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The generator verifies the full input SHA-256 before interpreting the ELF. It uses the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it launches no external program and never executes the node or its code. It excludes SHT_NOBITS from reads of file bytes. Python 3.12.3 was used. GNU objdump 2.42 was used only for manual instruction interpretation; its output is not parsed or copied into any generated file or test. The generator writes the machine-readable files and leaves this README and MANIFEST untouched. `MANIFEST.sha256` covers every other file in this directory.

## Evidence

All addresses below are ELF virtual addresses (VAs), before any load bias. Relocation addends are also ELF VAs. Generated records include file offsets, section names, byte predicates, relocation bytes, FDE/CIE bytes and full selected FDE windows. For example the address-09 scaled record at VA `0x6492ff8` starts at file offset `0x6490ff8`. FDE ends are exclusive and are unwind ranges, not independent proof of source-level function boundaries. The reported instruction windows and direct edges are selected for this question, not a complete disassembly or CFG.

### Selected FDE map

| Inferred role | Start VA | End VA, exclusive |
| --- | --- | --- |
| Upstream context and frame driver | `0x2962aa0` | `0x296754d` |
| Alternate frame | `0x29837a0` | `0x298632d` |
| Upstream context assembly | `0x2a07040` | `0x2a098a7` |
| Alternate precompile routing | `0x2a6ab20` | `0x2a6b79d` |
| Private-key dispatcher | `0x38be030` | `0x38be494` |
| Provider constructor | `0x38be800` | `0x38bebe6` |
| Address enumeration switch | `0x4200a50` | `0x4200d89` |
| Activation flag construction | `0x433dc40` | `0x433e79c` |
| Scaled-callback selector | `0x46a0eb0` | `0x46a0fa1` |

The selected route is `0x2a07040 -> 0x433dc40` and `0x2962aa0 -> 0x38be800 -> 0x29837a0 -> 0x2a6ab20 -> 0x46a0eb0`. The provider constructor and scaled selector are reached through authenticated relative-relocation slots, not direct call displacements. The frame can first call a separate state-transition helper, treated here as an external boundary. The scaled selector returns a record-resolved callback rather than directly calling it. `edges.tsv` and `rip-references.tsv` contain the particular call sites; `relocations.json` contains their raw ELF RELA entries.

### Activation and copied configuration

At `0x2a0713c`, the upstream function passes entry argument 3 plus `0x1c78` as the fourth argument to the constructor reached at `0x2a0715e`. Its slot `0x64e6e10` relocates to `0x433dc40`. Within that constructor, the selected normal path loads a 64-bit word from this subobject +`0x1d60`, rejects all-ones at `0x433de33`, and increments it. It checks a 32-bit tag at +`0x1eb8`; when that tag equals 1, the unsigned comparisons at `0x433e5f3` derive whether the incremented word is at least the 64-bit field at +`0x1ec0`. Otherwise it writes zero. The inferred rule on this path is:

```text
counter == 2^64 - 1  ->  separate failure helper
flag = (tag == 1) and (counter + 1 >= threshold)
```

The counter is an input to the observed computation; this packet does not claim it is written back. The output byte at constructor result +`0x200` is copied by `0x2a07040` into driver argument 2 +`0x58`. The driver advances that argument by 8 before calling `0x38be800`; the provider copies its input +`0x50` to provider +`0x88`. The frame later passes context +`0x3e0` as the provider to `0x2a6ab20`, which tests provider +`0x88`. Thus the same byte is frame context +`0x468` in the selected stack layout. `activation-lineage.json` extracts and cross-checks these offsets against the pinned instruction bytes.

This is conditional normal-return dataflow: it assumes relocation, helper returns, no intervening alias mutation and the selected frame/constructor branches. It does not establish that a live node has tag 1, a particular threshold, or this provider configuration. Names such as counter, threshold and activation are inferred from use.

Independently of that flag, the driver forwards the byte at its fourth argument +`0x148` to the provider constructor. The constructor indexes the table at `0x7a1784` and uses the resulting byte for 96-byte-spaced slots based at `0x64fe070`; a nonzero word at slot +`0x58` takes the earlier once-adapter boundary. For the 15 inputs inspected, the table is `0,0,0,0,1,1,2,3,3,3,3,4,5,6,6`. This fixed inspection range is not a validated domain or an identified live fork. The constructor obtains an initial set through an external helper, chooses a reserve amount of 21 or 11 depending on a returned field, and takes a separate growth helper if capacity is insufficient; both normal continuations proceed to the 21 key-copy calls. Those reserve numbers do not establish runtime membership or disable individual copies.

### Selector, alternatives and gas arithmetic

When provider +`0x88` is nonzero, `0x2a6ab20` calls `0x46a0eb0`; a zero flag or selector miss enters the enumeration/registry fallback. The selector tests all 20 key bytes and returns the callback relocation and divisor from one of these 40-byte records:

| Last key byte, with preceding 19 zero bytes | Callback addend VA | Divisor |
| --- | --- | ---: |
| `01` | `0x5c3b530` | 5 |
| `05` | `0x5c0b080` | 10 |
| `06` | `0x46e8790` | 10 |
| `07` | `0x46e7fe0` | 10 |
| `08` | `0x46e87a0` | 10 |
| `09` | `0x5c16650` | 10 |
| `0a` | `0x5c3afb0` | 40 |

`scaled-records.json` includes the independent key tests, record bytes, selector branch targets, callback slot and addend. For key 09 the callback slot is `0x6493010`; this is a distinct #115 record from the ordinary registry record described in PR 2049. The call at `0x2a6b07d` receives unsigned gas divided by the divisor, using a 32-bit division only when both operands fit, otherwise a 64-bit division. When the callback result's first word is nonzero, `0x2a6b0a7` multiplies the returned cost by the divisor and the overflow branch at `0x2a6b6e6` substitutes `2^64-1`. A zero first word bypasses multiplication.

PR 2049 independently analyzes the #115 callback at `0x5c16650`: its length, rounds/gas and final-flag checks occur in that order, and the successful cost is the 32-bit big-endian rounds value. Taking those callback semantics as a dependency, a valid address-09 scaled call requires `gas // 10 >= rounds`, and successful cost is `10 * rounds`; the maximum 32-bit rounds value cannot overflow that multiplication. For example 12 rounds requires at least 120 gas along this route. These are conditional static deductions, not captured execution or a claim that the normal registry is present. An ordinary registry hit has its own previously documented adapter and unscaled input, subject to registry initialization and no subsequent mutation.

The other fallback calls `0x4200a50` for 30 enumerated full keys. Only indices 6 through 26 pass the caller's private-index check: their suffixes, in order, are `0800`, `0813`, `0801` through `0812`, and `0814`. The provider constructor copies the same 21 keys from 32-byte records, and the separate dispatcher `0x38be030` compares the same keys and resolves each corresponding callback. The generator independently extracts all three lists and fails if their order differs. For the first dispatcher key, it also checks the intervening stores between the comparison and equality branch; those stores preserve the comparison flags. Its `private-records.json` preserves callback addends without asserting their implementations. The dispatcher also searches a tree-shaped structure with 20-byte `memcmp`: an equal key writes zero and `0x8000000000000001` to result fields and bypasses the record callback, while an empty tree or exhausted search reaches the callback. The tree's source-level role is unresolved. None of the 30 enumerated keys is the 20-byte address 09, so with the scaled route disabled this address reaches the prior ordinary lookup boundary `0x2a6c360`, rather than this private dispatch. A registry miss remains possible.

Before a scaled callback, a nonzero direct-input field takes the direct slice. Otherwise the selected path increments a counter associated with a context buffer, checks range subtraction and bounds, and obtains a borrowed slice. A counter at least `2^63-1` reaches a separate failure helper. A bad range restores the increment and passes pointer 1 with length 0; the prior #115 callback analysis predicts a length error for address 09. On a valid borrowed slice the normal path releases the counter. This does not establish the lifetime semantics of every buffer or exceptional path.

### Frame checkpoint and exceptional exits

For the selected frame branch, the depth-shaped argument is accepted below `0x401`; the other branch produces status `0x11`. The frame snapshots context +`0x280`, +`0x298`, +`0x2b0`, checks context +`0x388` against all-ones, then increments it. If the frame variant dword equals 1 it skips an external state-transition helper; otherwise it supplies 20-byte fields from frame +`0xb8` and +`0xa4`, and a 32-byte field from +`0x08`, with state at context +`0x270`. The lookup key used later is at frame +`0x90`; this evidence does not assume that these keys are equal. The helper's internals and eventual state effects are outside this packet.

The frame calls the previously analyzed rollback boundary for helper returns other than 3; return bytes 0 and 1 map to frame bytes `0x12` and `0x30`, respectively. Later, a converted frame status at least 5 reaches another call of the rollback boundary at `0x2984aa2`; lower status decrements context +`0x388` with saturation at zero. The rollback implementation is a PR 2049 dependency and is not reanalyzed here. Frame status and cleanup conclusions assume normal returns from the external helpers.

The six selected LSDAs yield the call-site records in `exception-sites.tsv`. In the alternate router, the table covers the indirect callback instruction at `0x2a6b07d` and identifies landing pad `0x2a6b73f`; the latter conditionally decrements the borrowed counter before reaching the `_Unwind_Resume` boundary. The selected PLT jump and its symbol-bearing relocation are extracted directly from the ELF. The tool checks the encoded ranges against the selected FDE and retains action indices but does not decode action chains or catch types. Other landing pads, helper exceptions, external callbacks and final cleanup effects remain unresolved.

### Cross-release provenance

The historical #94 report identifies a node with SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, an address-09 object/callback slot at `0x574f0b0`, its key at `0x574f0c0`, wrapper `0x4e9d2a0` and compression candidate `0x4e9a8a0`. A subsequent #94 runtime report identifies the start of the enclosing 48-byte copied record at `0x574f0a8`, eight bytes before that slot. That artifact is absent here; the reports and their pending captured-execution review were not rerun. The #115 record key, callback relocation and caller divisor are independently extracted from the authenticated #115 bytes and compared to the separately analyzed #115 wrapper. This supports the address-09 identity as an inference, not a reused #94 layout, byte-equivalence claim or a fresh #94 observation.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency closure, compiler/linker settings, two-build comparison, normalized binary matching, masks, complete helper/data/relocation closure, differential node execution and whole-ELF equivalence: **not yet implemented or measured**.

Synthetic models cover the selected activation decision, address routing and gas arithmetic. Their keys and expectations are synthetic; they do not execute captured code or prove runtime behavior. The focused suite has 35 passing tests and zero skips. Controls cover incorrect target hashes, absent/duplicate FDEs or relocations, altered opcodes and branch destinations, malformed exception tables, SHT_NOBITS/ambiguous/cross-boundary reads, altered selector keys or divisors, mismatched constructor copies, private-dispatch and exception-cleanup branches, all 160 individual address bits, gas/error boundaries and activation overflow. Generated files are compared byte for byte with the saved evidence.

## Results and limitations

`summary.json` records nine selected FDE intervals containing 49,902 bytes, 75 byte predicates, 59 direct edges, 10 RIP references, 34 relative and three symbol relocations, seven scaled records, six LSDA headers with 297 encoded call sites, 30 enumerated keys, 21 accepted private keys and constructor copies, and 15 inspected mode bytes. These are selected evidence counts, not total function coverage, a matched-window denominator or component completion percentage.

The `evm` component remains 0/4. Its first task requires identifying the private fork boundaries and state-transition inputs across a broader scope than this conditional path; no component gate or generated catalogue is changed. In particular, runtime activation values, the complete fork configuration, callbacks for the 21 private keys, alias safety, host/database effects, every error and unwind action, the external state-transition helper, complete compression behavior and a #115 Rust reconstruction remain open.

Next question: bind an authenticated fork-configuration input and the 21 private callback implementations to this provider, then determine their host state effects and exception cleanup without assuming live runtime values.
