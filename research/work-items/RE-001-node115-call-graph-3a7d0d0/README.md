# RE-001: direct call map for node #115 FDE `0x3a7d0d0..0x3a7d7fc`

- Component ID: `foundation` allocation only; ownership remains unresolved
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Question: what direct incoming and outgoing call edges can be bound to this one FDE and to other FDE extents?
- Claim status: observed instructions, relocation addends and unwind extents; function names and semantics unresolved

This packet follows the next-step recommendation on the bounded FDE census in [PR #5064](https://github.com/lalalune/hyperliquid-source/pull/5064). It re-derives the selected body and every edge directly from the signed #115 target; it does not depend on the other packet being merged.

## Findings

| Relationship | Result |
| --- | --- |
| Selected function-map extent | FDE `0x3a7d0d0..0x3a7d7fc`, 412 decoded instructions, body SHA-256 `5ec1da22be4a00c4ace34d761c9a9ddd66f505f62cf8e7abcd2e1ee40b6f8dae` |
| Direct incoming calls | 2 raw `E8 rel32` matches across `.text`; both decode at instruction boundaries inside distinct FDEs |
| Direct outgoing calls | 28 call instructions to 14 distinct addresses; 13 destinations lie in recorded FDEs and the remaining destination is the `.plt` entry `0x63f0a50 <_Unwind_Resume@plt>` |
| RIP-relative indirect outgoing calls | 12 sites use 4 pointer slots; all four have `R_X86_64_RELATIVE` relocations whose addends fall in recorded FDEs |
| Other outgoing indirect forms | 0 |
| Near-target control | Scanning for direct calls to `0x3a7d0d1` found no raw candidates |

`calls.json` stores every site, instruction byte sequence, target label/slot, relocation addend, FDE range, and body hash. `fdes.readelf.txt`, `relocations.readelf.txt`, `call-sites.objdump.txt`, `unwind-resume-plt.objdump.txt`, and `unwind-resume-jump-slot.readelf.txt` retain the corresponding raw tool output. The one direct destination outside recorded FDEs is verified inside `.plt`, labeled `_Unwind_Resume@plt`, and linked through its RIP-relative GOT slot to the `R_X86_64_JUMP_SLOT` symbol `_Unwind_Resume@GCC_3.0`; runtime library resolution remains outside this static map.

## Reproduce

Use Python 3.14.3, GNU binutils 2.47.20260726 (`readelf` and `objdump`), and the pinned target:

```sh
python3 -B research/work-items/RE-001-node115-call-graph-3a7d0d0/verify.py
```

Expected output:

```text
verified incoming=2 direct=28 rip-relative=12 other-indirect=0 external-plt=1
```

To regenerate the target-derived files and packet manifest before review, run `python3 -B research/work-items/RE-001-node115-call-graph-3a7d0d0/verify.py --write`, then run the default verification command. The verifier hashes the full target, parses all FDEs and relocations, checks that FDE ownership is unambiguous, scans every `.text` byte for direct-call candidates to the selected address and its one-byte near miss, and verifies candidate instruction boundaries with objdump. It never executes or copies the target.

## Why this map matters to RE-001

The packet binds two direct caller FDEs, 13 distinct direct targets with FDEs, four relocated indirect targets with FDEs, and one local exception-runtime PLT stub to the selected body. These exact neighboring ranges are concrete inputs for later ownership and semantic checks; this result does not yet assign the selected body or its callers to a node component. Keeping `foundation` as an allocation label avoids turning call proximity into a component claim.

## Limits

The incoming scan covers direct relative `E8` calls, including up to ten legal x86 instruction-prefix bytes, only; it does not prove that no indirect caller exists. Outgoing indirect edges are resolved only when the call uses a RIP-relative slot with a matching `R_X86_64_RELATIVE` relocation. The `_Unwind_Resume@plt` and `_Unwind_Resume@GCC_3.0` labels identify the local PLT stub and its dynamic relocation; the runtime library implementation, source semantics, ABI, behavior, and component ownership are not inferred. The `foundation` label is only the existing work-allocation category. No reconstruction gate or completion percentage is claimed.

This is static analysis of one target function and its observed call edges. All target addresses and hashes use the authenticated ELF's own coordinate system. The captured node was never executed, emulated, or copied.
