# RE-001: the default context does not zero its opaque state

- Component: foundation; bounded question: what does `0x143f520` actually
  initialize, and can its opaque regions be represented by all-zero arrays?
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference: `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`,
  `base/production.rs:78-92`, used as an unverified lead, not copied implementation.
- Status: observed instruction/data facts; inferred name only. No progress gate.

## Reproduce

From the repository root, CPython 3.12.14 on Windows:

```sh
python tools/production_default_static.py --out work/production-default-94.json
python -m unittest discover -s tests -p test_production_default_static.py -v
python research/work-items/RE-001-production-default-context-94/export_disassembly.py
```

The verifier and tests use the standard library. Only the last, optional raw
disassembly export needs Capstone **5.0.6**, x86-64 Intel syntax. The Windows
wheel used here was `capstone-5.0.6-py3-none-win_amd64.whl`, SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
It was downloaded from PyPI, its digest checked and installed in a workspace
environment without source build or lifecycle hooks. No captured binary ran.

`records.json` is reproducible UTF-8/LF output. `window.capstone.txt` retains all
336 bytes as 68 decoded instructions plus original FDE/CIE records. Instruction
lengths consume the entire FDE range without gaps. The existing independent
`evm_amount_scale.Fdes.range_of` reader also returned this same interval during
investigation. No GNU-binutils or Ghidra cross-check was available here.

## Original evidence

All addresses are unrelocated ELF VAs; runtime pointers gain the load bias.
FDE `0xfcef74`, CIE `0xfbdc2c` describe `[0x143f520,0x143f670)`. Body SHA-256:
`77c2e3d7ef4fea21b9c49db48437215f2fc7d3f657e4fc9418bd9b2f706d3e1f`.

| Observed site | Established operation |
| --- | --- |
| `0x143f52c`, `0x143f531` | Pass 20 to the indirect callee at slot `0x576dfd8`; test its returned RAX for zero. Allocation interpretation remains inference. |
| `0x143f543..0x143f554` | Copy the first 16 bytes at `0x21964c` and the 4-byte tail immediate into the returned buffer: exactly `N/A (non-production)`. |
| `0x143f563` | Store a zero word at output `+0x110`, covering two bytes. Names of the two flags are inferred, not recovered types. |
| `0x143f57f..0x143f597` | Materialize `0x8000000000000000`; store qwords at output `+0x90` and `+0xa8`. These are not zero. |
| `0x143f5a1..0x143f5e3` | Copy two 16-byte chunks at `0x566a228`/`0x566a238` into `+0xc0/+0xd0`, then duplicate them at `+0xe0/+0xf0`. |
| RELATIVE slot `0x566a228` | Its on-disk qword is zero, but relocation addend is `0x202e90`. Each 32-byte copy therefore begins with `load_bias+0x202e90`, not zero. |
| `0x143f554..0x143f563` | Pass the Location at `0x566a248` to helper `0x13cc980`. Its relocated path is `base/src/crit_msg.rs`, line 585, column 18; the opaque helper output is copied from the stack to `+0x30..+0x90`. |
| RELATIVE slot `0x577acf0` | Contains a loader binding to this initializer's entry, `0x143f520`. This is a pointer reference, not proof of a concrete caller. |

The helper entry is supporting ABI evidence only; its tracker initialization
behavior was separately studied in the existing RE-001 file-tracker packet.
The critical-message admission PR #148 explicitly excludes defaults and opaque
state layouts; its entry/three-gate question is not redone here.

The all-zero placeholders for offsets 144 and 192 in the reference constructor
disagree with both the observed sign-bit sentinel stores and relocated data.
No source layout or `Option`/collection type can be inferred solely from those
sentinels. Preserve inactive/unknown bytes rather than assigning an all-zero
representation. This packet leaves the unlicensed reference and all imports intact.

## Comparison and controls

There is no reconstructed Rust component, build or equivalence result.
The six target-backed tests check the pinned record and exercise corruptions of
the actual sentinel immediate, destination offset, flag word, literal, FDE length,
static data relocation, initializer pointer and call-slot binding. Zeroing the
sentinel is an explicit negative control for the reference's placeholder model.
The identity gate rejects a changed capture before structural observation.

Eight original direct/slot call bindings, including cleanup paths, are retained
in `records.json`. Their target bodies are not closed or assigned invented
semantics. The minimum observed written output span is 274 bytes, not a proof
of a complete Rust struct size. Original pointer/offset values are unmasked.

## Validation and remaining gaps

`controls.txt` records six passing focused tests. Required repository checks were
invoked through the Makefile's Python commands because GNU make is unavailable.
Full suite: 363 tests in 110.424 seconds; 7 failures, 16 errors, 21 skips.
All six new controls pass. The full suite does not pass: failures include
Windows text-output/path expectations, missing GNU tools and temporary-directory
cleanup. The previous independent branch showed the same failure/error/skip
counts, but this is not an independent baseline proof for each failure.

Doctor reports unavailable native prerequisites. All eight artifact size/SHA-256
checks pass, but GPG is absent, so signature verification does not pass. Imports
verification fails on the Windows reference checkout; reserved `node/aux.rs`
cannot be materialized and hydrated LFS inputs remain unstaged. Catalogue check
fails on native backslash paths. `tools/reproduce.py` was attempted and stops at
the missing-GPG artifact verification step; no imported interpretation was regenerated
or overwritten. Hosted CI and Linux/macOS runs were not measured.

No target execution, node build, parser/filesystem behavior, complete caller or
helper closure, full object layout, flag naming, runtime equivalence or milestone
completion is claimed. Next question: trace the initializer-pointer consumer and
the consumers of the two sentinel slots before assigning recovered Rust types.
