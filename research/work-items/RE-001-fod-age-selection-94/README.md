# RE-001: FodName age fallback and minimum selection

- Component: foundation / filesystem age support. Question: which helper
  outcomes select own-path fallback and how are successful age words reduced?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as an unlicensed lead.
- Status: observed fallback/callback/result/flag operations and conditional
  successful-result models. Actual filesystem and clock behavior unresolved.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/fod_age_static.py --out work/fod-age-94.json
python -m unittest discover -s tests -p test_fod_age_static.py -v
python research/work-items/RE-001-fod-age-selection-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
No captured code, directory enumeration, stat, process or network action executes.

Retained complete FDE `[0x13d1b00,0x13d2134)`: **1,588 bytes / 360
instructions**, contiguous complete byte consumption, raw FDE/CIE and body hash
`a55a97006d67253f946e76591466f5237c15b0268c2d34941f25165a087bacb1`.
Selected observations are instruction starts. Addresses are ELF VAs; `.text`
offsets are VA minus `0x1000`. No masks or substitutions.

## Own-path fallback and callback observations

The entry compares its input dword with 1. Other words go directly to the
own-path helper through slot `0x576eae0 -> 0x144fe90`. Word 1 first calls the
enumeration candidate `0x576ead8 -> 0x144bfd0`. Its three returned words are
loaded from stack +0x80/+0x88/+0x90. The first and third are tested for zero:
either zero selects an own-path helper fallback; both nonzero select the entry
traversal/reduction path. These are raw helper-result predicates, not a portable
BTreeSet or enum layout. Other raw input words are not declared valid FodName
variants merely because the branch treats them alike.

The reference's file/directory age interpretation is supported by captured
`base/src/fodname.rs` Locations 31:34, 34:17, 43:46 and 38:42, resolved through
four RELATIVE pointers. Those contexts do not close enumeration, filtering,
ordering, symlink behavior or the tree traversal representation.

On the nonempty path, the first successful age result seeds XMM2. Subsequent
calls use the same bound helper; a dword result tag of 1 selects error handling.
Successful binary64 payloads are loaded from stack +0x20. The model assumes
these calls return successfully and models their supplied bit sequence only.
It does not read real path metadata or assert a unit/clock contract for the helper.

## Minimum and exceptional comparison

At `0x13d1ede`, UCOMISD compares accumulator with current age. CMPLESD plus
ANDPD/ANDNPD/ORPD then selects accumulator bits for ordered `acc <= current`,
otherwise current bits. These SSE mask operations preserve integer RFLAGS.
The subsequent JNP therefore still tests the unordered flag from UCOMISD:
ordered values continue; unordered values enter a panic path bound to captured
`base/src/duration.rs:58:33` and callee `0x157a9f0`.

For ordered values this is a first-tie-preserving minimum. Positive and negative
zero compare equal, so their first bit representation survives. A singleton
result has no pair comparison and retains its original bits, including a raw
NaN. Compared NaNs select the panic path **assuming masked FP invalid
exceptions**; CMPLESD itself can raise invalid. Runtime MXCSR and reachable NaN
ages are not established. No externally reachable failure claim is made.

The reference uses `if age < youngest_age` and omits the explicit unordered
failure. This packet records the captured behavior without copying its code
or claiming complete filesystem-age equivalence.

## Controls and required checks

Six focused methods pass. **64** declared tag/root/count combinations cover
fallback selection. **1,110** successful-result bit vectors (ten patterns,
lengths 1..3) agree with an independent ordered-minimum/exception form. Additional
signed-zero and singleton payload probes check bit preservation. These are
conditional models, not executed directory or timestamp populations.

Actual-capture mutations cover tag/root/count and error tests, comparison/mask/
parity operations, callback relocations, all five source records, FDE and
identity. Make is absent; required Makefile Python commands were run directly. Full suite:
**363 tests in 106.825 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. This independent main-based branch excludes unmerged #227. Doctor
reports missing native prerequisites. Eight artifact size/digest checks pass
before missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. Those failures are not marked passed.

No actual filesystem/clock operation, enumeration/tree/error/drop closure,
portable Rust type, native build/equivalence, imported change, hosted CI or
progress gate. Next question: close enumeration and age callbacks before
reconstructing filesystem semantics and time units end to end.
