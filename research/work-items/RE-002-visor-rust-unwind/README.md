# RE-002: does visor have a first-party Rust-associated unwind cleanup owner?

- Component: build provenance / visor; one bounded RE-002 question, no gate.
- Captured visor SHA-256:
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
  8,305,392 bytes. No node #94/#115 address or build-flag claim.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
  No unlicensed inferred source was read or copied for this packet.
- Observed: FDE/LSDA/source-location/RELA relationships, selected instructions,
  helper diagnostic and external resume binding. Inferred: Rust-associated
  cold error roles. Unresolved: actual exception execution, full personality
  semantics, final panic handler and per-crate compiler flags.

The [existing provenance packet](../RE-002-build-provenance/README.md) leaves
visor's panic strategy unknown and specifically asks for LSDA owners mapped
to Rust functions. Exception-section size alone cannot provide that link.
This packet supplies one concrete owner: a `base/src/liner.rs:17`-associated
window whose two cold error calls are protected by an action-zero cleanup
interval. Its landing pad preserves the exception, conditionally calls an
opaque helper, then binds the preserved exception to `_Unwind_Resume`.

This is a static ownership result. It does **not** change the earlier unknown
into a binary-wide `-C panic=unwind` conclusion. The Rust Reference distinguishes
crate panic strategy from the linked panic handler; retained cleanup metadata
does not establish which handler runs or the outcome of every panic.

## Reproduce

Materialize the repository's pinned LFS inputs and submodules first. Requires
Python 3, GNU binutils (`objdump`, `readelf`) and LLVM `llvm-objdump`. This run
used macOS15.7.7 arm64, Python3.12.10, GNU2.47.20260726 and AppleLLVM17.
`observed/toolchain.json` records exact provider versions. No package installation,
captured execution, network protocol, chain/signing or paid dataset is involved.

```sh
make doctor verify test catalogue-check reproduce
python3 tools/visor_rust_unwind.py --output work/visor-rust-unwind-repeat
python3 -m unittest discover -s tests -p test_visor_rust_unwind.py -v
python3 research/work-items/RE-002-visor-rust-unwind/verify.py
(cd research/work-items/RE-002-visor-rust-unwind && shasum -a256 -c MANIFEST.sha256)
```

On this Mac, GNU binutils is first in PATH and
`LLVM_OBJDUMP=/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`.
The collector authenticates the entire visor, reads it once and gives both
native decoders the same owned temporary snapshot with mode0400. It never
launches that snapshot. Raw native exports replace only that temporary input
pathname with `<authenticated-visor>`; no instruction/operand/byte masks or
prefix joins are applied. Both tools agree on every selected instruction
start and byte; GNU readelf independently agrees with all five FDE extents.
Other native versions can render assembly differently: verification compares
the facts and native bytes/boundaries, and claims exact raw-text equality only
with the recorded tool versions.

## Selected extents and error bindings

All addresses are linked ELF virtual addresses, half-open. File offsets and
FDE records are retained in `observed/ownership.json`. FDE extents plus complete
native decode do not prove original Rust function boundaries or all callers.

| Observed role | VA interval | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Source-associated owner | `0x3c7ef0..0x3c8056` | 358 | 83 |
| Option error wrapper | `0x49ab90..0x49aba9` | 25 | 6 |
| Formatted error wrapper | `0x49abb0..0x49ac02` | 82 | 19 |
| Literal-to-format bridge | `0x49ade0..0x49adf2` | 18 | 4 |
| Final format bridge | `0x49ae00..0x49ae2c` | 44 | 11 |

The authoritative instruction counts are in the machine-readable denominator;
the table above is checked against those records during preparation. Total
scope is **five windows, 527 bytes, 123 instructions and 12 calls**.

The owner LEAs at `0x3c7ff9` and `0x3c801f` reference Location-shaped records
`0x7af278` and `0x7af260`. Each has one `R_X86_64_RELATIVE` binding to the actual
17-byte `base/src/liner.rs` string, with line17 / columns84 and74 respectively.
The source association is independent of the reference tree's method names.

Calls at `0x3c8000` / `0x3c8030` bind through slots `0x7e4de0` / `0x7e4be0`
to the first two cold wrappers. The first wrapper explicitly passes the
Option/None unwrap diagnostic at `0x80229` with byte length43. It preserves
the supplied location argument and calls `0x49ade0` through slot `0x7e4c60`.
Both paths then converge on `0x49ae00` through slot `0x7e4c00`; that bridge
calls opaque target `0x66d060` through slot `0x7e6b78`. This is a bounded
call/data association, not a recovered source signature or panic implementation.

## Cleanup-only LSDA

The owner's FDE names LSDA `0x1eded0`. Its header bytes are `ff ff 01`:
omitted explicit landing-pad base, omitted type table and ULEB call-site
encoding. Its declared call-site payload is15 bytes. The next LSDA pointer,
`0x1edee4`, is only an upper bound; the declared table ends at `0x1edee3`.
The last byte before that bound is not claimed as part of an LSDA object.

| Protected instruction interval | Landing pad | Action |
| --- | --- | ---: |
| `0x3c7ef0..0x3c7f5d` | none | 0 |
| `0x3c7f5d..0x3c8036` | `0x3c8038` | 0 |
| `0x3c8036..0x3c8056` | none | 0 |

All endpoints/pads are native instruction starts or the owned end, without
overlap. All eight owner calls have a table entry under return-PC-minus-one
lookup; four select the cleanup pad, including both source-associated error
calls. This does not claim those calls actually unwind on any input.

At the pad, `rax` is saved in `r15`; when `rbx` is nonzero, the code supplies
`r14`, `rbx`, zero to helper slot `0x7e4b80` (target `0x714530`, opaque here).
It then moves preserved `r15` into `rdi`. The call at `0x3c8051` reaches PLT
`0x7a6820`; its actual RIP-jump slot has one `R_X86_64_JUMP_SLOT` binding to
`_Unwind_Resume`. This establishes the encoded handoff, not runtime unwinder
success or allocator semantics. The cleanup helper call/resume themselves are
in the final interval with no further landing pad.

The selected CIE is `zPLR`, using pcrel/sdata4 FDE and LSDA pointers and an
indirect pcrel/sdata4 personality pointer. Slot `0x7e9468` has a local RELA
addend `0x696f30`, one actual FDE start. The personality body is deliberately
opaque and outside the 527-byte denominator.

The [Rust LSDA parser at the stamped compiler commit](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/personality/dwarf/eh.rs)
provides the encoding/action interpretation: a nonzero pad with action0 is a
cleanup and can apply to Rust or foreign exceptions. The
[Itanium base exception ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html)
defines the resume interface; neither reference proves this target executes
as a whole. See the [Rust panic-strategy distinction](https://doc.rust-lang.org/reference/panic.html#panic-strategy)
for why this local evidence does not recover the global build configuration.

## Controls, checks and limits

See `validation.json` for exact executed results. The unchanged main baseline
passes431 tests. Nine focused tests add15 real-ELF corruptions below the
whole-artifact identity gate: five LSDA edits, four Location/relocation edits,
two resume import/PLT edits and four instruction changes. Those four are
redecoded by **both** native providers before ownership checks reject them.
Thus their rejection is not merely a changed artifact digest or stale decode.
Separate wrong-identity controls test admission. A changed byte in unowned
upper-bound padding remains analyzable with the same call map and interval
rows, while the recorded digest and raw LSDA bytes change;
this does not admit that altered file through the normal identity gate.

All11 native exports and the ownership record reproduce on the recorded host.
GNU/LLVM decoding and readelf extent agreement are static observations, not
execution, emulation or Rust recompilation. Native parser helpers adapt the
project's MIT code in [PR266](https://github.com/lalalune/hyperliquid-source/pull/266)
at commit `65af927ba48ba9c84dff7fb7a2ab2168419b519f`; they do not depend on that
unmerged PR or copy unlicensed private-node source.

No all-caller closure, global Rust ABI/object layout, allocator/parser/runtime
semantics, installed exception behavior, recoverability, source reconstruction,
compiler-flag recovery, hosted CI/container/Rust build or component gate is
claimed. PR45's visor lifecycle ranges are untouched. Existing provenance,
imported evidence, submodule pins and generated progress stay unchanged.
Next question: bind the final panic-runtime target and its handler choice,
with separate runtime authorization before attempting any executed comparison.
