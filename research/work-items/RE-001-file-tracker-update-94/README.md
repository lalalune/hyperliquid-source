# RE-001: node #94 file-tracker polling and update decisions

- Component: `foundation`; one updater and its immediate call/data bindings.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  The unlicensed reference supplies leads only; no reference code is copied.
- Question: when does this updater poll, reject a modification, replace its
  stored value, retain a load error, or enter the metadata-error route?
- Status: static observations and explicitly inferred roles; no progress gate,
  reconstructed Rust implementation, target execution or equivalence claim.

This extends the committed [initializer packet](../RE-001-file-tracker-init-94/README.md).
Its fallback behavior cannot be assumed for polling: the updater has a distinct
metadata failure route. Open PR #148 studies the surrounding critical-message
helper and uses the updater call as supporting evidence; this packet studies
the updater body itself and retains only a short caller excerpt.

## Reproduce

Requires Python 3.10+, authenticated pinned inputs, GNU objdump/readelf and,
for the independent decoder check, an LLVM objdump. On the recorded macOS
host, the installed MinGW GNU tools support this ELF input; their executable
names do not change the target architecture. Tool versions and observed
validation results are in `validation.json`.

```sh
make doctor verify test catalogue-check reproduce
python3 tools/file_tracker_update_static.py --output work/file-tracker-update-94
python3 -m unittest discover -s tests -p test_file_tracker_update_static.py -v
```

The producer accepts explicit disassembler/readelf paths. Retained exports use
GNU Binutils 2.46.1 and Apple LLVM 21.0.0. Both decoders agree on every
instruction address and byte in the updater: **226 instructions / 931 bytes**.
The JSON and hex records are deterministic; tool banners/rendering can differ
on other versions. Only input pathnames in dump headers are replaced.

## Boundaries and attribution

All addresses below are linked ELF virtual addresses, without a runtime or
Ghidra rebase. The updater occupies `0x13cc5d0..0x13cc973` (half-open), file
offset `0x13cb5d0`, 931 bytes, body SHA-256
`049cd61d7abc8da8ebefc284f08f26d73242603c7880d695604afad0a1f4e8c2`.
GNU readelf and the repository FDE decoder independently agree on this extent.
The FDE, bounded disassembly and contiguous decoded instruction bytes support
this selected window; they do not establish a whole-node function census.

The diagnostic descriptor at `0x1df907` contains
`Error updating FileModTimeTracker for `, supporting the inferred updater role.
One validated direct call at `0x143defa` lies inside the independent FDE
`0x143d010..0x143e888`; its preceding LEAs pass global `0x577ad40` in RDI and
descriptor `0x566a278` in RSI. This is a selected caller, not an exhaustive
indirect-call or address-taken census.

## Observed decisions and stores

The first argument is retained in RBP. Offsets describe the observed storage;
they do not declare a recovered Rust struct or generic value type.

| Decision | Original instruction evidence | Consequence on the shown path |
| --- | --- | --- |
| Poll interval | `0x13cc5f3` tests DWORD `+0x38`; `0x13cc657` uses `ucomisd`, then `jbe 0x13cc77d` | A zero first word bypasses the interval helper. Otherwise the branch suppresses polling when its returned float is less than/equal to the configured float, including unordered comparisons. |
| Poll time | `0x13cc663..0x13cc672` stores 12 bytes at `+0x38` | These stores occur before the file predicate call at `0x13cc683`, including when that predicate subsequently returns zero. |
| Metadata failure | `0x13cc6a2` compares the returned DWORD tag with 1 | Tag 1 branches to `0x13cc8fb`, prepares the 43-byte `Result::unwrap()` error literal, calls slot `0x576e048` and ends in `ud2`; no initializer-style fallback is shown. |
| Newer modification | `0x13cc6b9..0x13cc6d5` compares DWORDs with `setg`, `seta`, then `ja` | First word is signed; the second and third are unsigned tie breakers. Equal or older triples return zero. |
| Load result | `0x13cc6f4` calls `0x144d470`; `0x13cc6f9..0x13cc703` compares zero with the first returned word and uses `jno` | The overflow case is the word `0x8000000000000000`, which enters the error route. Its full Rust Result/value ABI remains unresolved. |
| Load error | `0x13cc709..0x13cc77d` prepares the diagnostic, calls a helper, releases a previous error through an indirect call and writes `+0x48` | This path has no direct replacement stores to value `+0x18..+0x2f` or modification `+0x50..+0x5b`, and returns zero. |
| Load success | `0x13cc862..0x13cc8b5` installs 24 returned bytes at `+0x18`, copies three modification DWORDs to `+0x50/+0x54/+0x58`, clears `+0x48`, and sets BL to 1 | The ordinary epilogue returns one, including if the conditional call through slot `0x576e8b8` returns. |

Success first traverses/releases the old value using 40-byte outer and 24-byte
inner strides. Error replacement also invokes an old error's indirect drop
slot when nonzero. These ownership paths are retained in the disassembly;
their allocator/drop implementations and all unwind effects remain open.
Statements about unchanged fields describe the visible stores, not a guarantee
that opaque helpers cannot mutate shared state.

## Calls, data and remaining work

The retained RELA records bind the time-producing slot `0x576e8a0` to
`0x151cba0`, interval-helper slot `0x576e8c0` to `0x1447130`, predicate
`0x576e9e8` to `0x144a710`, metadata slot `0x576e9f0` to `0x144c930`,
diagnostic slot `0x576e978` to `0x143d010`, and error slot `0x576e048` to
`0x157aa10`. Names and time units are not recovered from those bindings alone.
In particular, the diagnostic helper also contains the selected incoming
updater call; reachability and reentrancy of that cycle are not established.
Record `0x5666f58` is vtable-shaped (relocated drop pointer, size 8, alignment
8), rather than a source Location.

Corruption controls alter the real interval branch, poll store, comparison
signedness, failure discriminators, replacement stores, call/data relocations
and FDE extent. They bypass the outer digest check only when testing a named
local obligation. Wrong-release and damaged-input controls exercise that outer
gate separately. These are static evidence checks, not runtime differentials.

No normalized operands, raw/normalized Rust-body matches, complete helper
closure, serializer/schema, full tracker protocol or whole ELF is claimed.
Imports, submodule pins and component gates stay unchanged. Next resolve the
time/load return layouts and the diagnostic-helper cycle before implementing
a compatible polling replacement.
