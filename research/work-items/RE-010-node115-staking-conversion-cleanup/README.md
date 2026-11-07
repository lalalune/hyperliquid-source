# RE-010: node 115 staking-map conversion cleanup

Partial progress for [#3928](https://github.com/lalalune/hyperliquid-source/issues/3928).
This maps two exception-cleanup paths inside the relationship writer and binds
them to the native exception table. It leaves all full-component gates false.

## Target and prior boundary

Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Original node #115 Linux
x86-64 ELF: 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Coordinates are ELF virtual addresses.

`RE-010-link-staking-path-115` / [#2126](https://github.com/lalalune/hyperliquid-source/pull/2126)
owns the selected normal finalize path and its two relationship writes through
`0x3ce1080`. It explicitly leaves exceptional behavior unresolved. The new
question is narrower than pairwise atomicity: which writer instructions have
local landing pads, and what owner fields do those pads publish before resuming
the exception? The original normal write order is retained only as context.

## Exact exception-table association

The writer FDE is `0x3ce1080..0x3ce15ad`, with LSDA pointer `0x3001e8`.
Its header omits LPStart and the type table, uses ULEB128 call-site encoding,
and declares 29 bytes of call-site records. Including that header, the retained
table occupies 33 bytes and decodes to five rows:

| Protected instruction range (end exclusive) | Local landing pad | Action field |
|---|---|---|
| `0x3ce1080..0x3ce11c0` | none | 0 |
| `0x3ce11c0..0x3ce11cb` | `0x3ce158e` | 0 |
| `0x3ce11cb..0x3ce13a0` | none | 0 |
| `0x3ce13a0..0x3ce13ab` | `0x3ce156b` | 0 |
| `0x3ce13ab..0x3ce15ad` | none | 0 |

Both protected ranges contain a call to `0x3909130`, at `0x3ce11c6` and
`0x3ce13a6`. The bounded decoder was independently cross-checked against the
repository's `tools/abci_linked_commit115.py:parse_lsda`, which produced all
five rows identically. It is deliberately not a general LSDA implementation.

An action field of zero means there is no associated action record; that alone
does not establish a catch or cleanup behavior. The interpretation below also
uses the landing-pad instructions and the resolved unwinder import. See
[Itanium exception handling tables, §7.3.2](https://itanium-cxx-abi.github.io/cxx-abi/exceptions.pdf)
for the call-site field convention.

## Published representation on the two cleanup paths

The observed tree-to-flat selection combines the tree sentinel and live length
below 32. It clears the owner's root/length fields and invokes `0x3dc74f0` at
`0x3ce1145`. After that helper returns, the newly computed flat descriptor is
retained in R15, R14 and RBX. A subsequent loop calls `0x3909130`. Its normal
exit at `0x3ce11d6..0x3ce11ed` publishes four owner qwords:

```text
owner[+0x00] = R15
owner[+0x08] = R14
owner[+0x10] = 0
owner[+0x18] = RBX
```

The corresponding landing pad `0x3ce158e` writes exactly these same values to
the same fields, then passes the active exception pointer to the resume target.
These are the descriptor values computed before the conversion loop, not an
inferred restoration of the earlier contents.

The other selection combines a missing-key result with live length at least
64. It snapshots the prior flat descriptor, clears the current owner and calls
`0x3892d40` at `0x3ce126a`. On the relevant later conversion loop, normal
publication at `0x3ce13b3..0x3ce13ce` writes the tree sentinel at owner+0,
the returned first 16 bytes from stack+0xc0 at owner+8, and the returned qword
from stack+0xd0 at owner+0x18. Landing pad `0x3ce156b` performs those same
publications before resuming the active exception. The underlying conversion,
lookup and iterator helper implementations are not reconstructed here.

The resume calls at `0x3ce1589` and `0x3ce15a8` target PLT entry `0x63f0a50`.
That entry jumps through `0x64ee178`; the `.rela.plt` record at `0x16a8c8`
has type 7 and symbol index 6, whose dynamic symbol name is `_Unwind_Resume`.
The verifier resolves that name and slot independently of the disassembly
label. No native unwind is invoked during verification.

## Boundaries

This establishes two local conversion-cleanup/publication paths. The conversion
constructor calls themselves are in ranges with no local landing pad in this
table. The surrounding finalize FDE `0x469fe90..0x46a02ea` has no LSDA pointer;
that observation does not describe outer callers' exception handling. Pairwise
link rollback, authorization, persistence, process survival, allocator behavior
and full tree-rebalancing correctness remain outside the packet. No failure
of those wider properties is asserted.

## Reproduction

`records.json` retains **5 instruction windows / 944 bytes / 198 instructions**,
supplemented by checks of the 33-byte LSDA, 6-byte PLT jump and 24-byte
relocation binding as explicit data facts. Enclosing FDE/LSDA associations are checked as well.
The 50 fact checks and 14 controls cover thresholds, new-descriptor capture,
normal/cleanup field correspondence, protected ranges, landing pads, action
selection and the unwind import. Altered inputs must fail fact checks while
global digest/window rejection is bypassed inside each control.

Use an existing Python environment with Capstone **5.0.7** and the hydrated
artifact (observed Python **3.14.7**):

```sh
python3 research/work-items/RE-010-node115-staking-conversion-cleanup/verify.py
```

Expected: 5 windows, 944 bytes, 198 instructions, 50 facts and 14 rejected
corruptions. `verification.json` retains the observed result. `--target PATH`
requires the pinned digest. Existing registry-row-labels ELF/FDE parsing is
reused; nothing is downloaded. Interpretation and tooling are independently
authored, imported rights are unchanged, and no captured instructions were
executed or emulated.
