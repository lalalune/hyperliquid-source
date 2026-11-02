# RE-009: node115 checkpoint preparation and publication boundary

Question: how does the `db/src/db_home.rs`-associated body prepare the selected
database directory, and does its checkpoint-associated route share the same
preparation as its other mode?

Target: node115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Task: bounded RE-009/RE-001 storage lifecycle mapping. All component gates remain
false. This packet provides neither a reconstructed Rust database nor persistent
schema, restart, crash consistency, snapshot version compatibility or state-root
acceptance evidence.

## Measured code and denominator

All addresses are original ELF virtual addresses and ends are half-open FDE
extents, independently checked against a complete GNU native decode. These are
unwind-backed measured extents, not a complete function inventory.

| Role | Start | End | Bytes | Instructions |
| --- | --- | --- | ---: | ---: |
| db-home associated lifecycle | `0x44681e0` | `0x4468b62` | 2,434 | 513 |
| command preparation adapter | `0x15028f0` | `0x1502b78` | 648 | 149 |
| directory-shaped predicate | `0x1500a60` | `0x1500b83` | 291 | 65 |
| regular-file-shaped predicate | `0x1500d20` | `0x1500e43` | 291 | 65 |

Denominator: four full measured extents, **3,664 bytes / 792 instructions**.
There is no normalized comparison, source-build identity claim, target execution,
or instruction/whole-node completion percentage. The two predicates are included
to qualify this lifecycle's path tests, not offered as separate contributions.

`records.json` retains each body SHA-256, file offset, FDE/CIE/LSDA coordinates,
every decoded call, and every RIP-relative binding. Relocation slots retain their
actual info/addend. The producer refuses duplicate FDE starts and relocation
slots. Nine actual LEAs bind relocated Locations to `db/src/db_home.rs` lines
286, 291, 302, 309, 310 and 317. Source association does not recover the original
function name or public API.

## The adapter prepares cp arguments

Three literal LEAs in `0x15028f0` establish a command boundary without running a
command:

- `0x1502a05` selects address `0x465a0a`, length 2: `cp`.
- `0x15029f4` selects address `0x465a05`: `-R` for mode byte 0.
- `0x15029ed` selects address `0x465a07`: `-al` for mode byte 1.

At `0x15029fb..0x1502a04`, TEST AL / CMOVNE selects the latter pointer for a
nonzero byte; the length is the zero-extended byte plus 2. Consequently only the
caller-observed 0/1 values justify the two flag names above. Arbitrary nonzero
bytes are not normalized to 1 by this adapter. At `0x1502a0c..0x1502a33`, the
prepared vector holds the command pointer/length, flag pointer/length, then the
two original pointer/length pairs. Call `0x15b0450` consumes that preparation.
Its complete spawn/status behavior and the downstream host `cp` implementation
are unclosed. This is **command argument preparation evidence**, not proof of a
completed copy, hard-link, safe shell handling or filesystem effect.

Both calls from the lifecycle body (`0x4468379`, `0x44684dc`, plus the alternate
mode site `0x4468700`) dereference slot `0x64e0a18`, which has RELATIVE addend
`0x15028f0`. Each passes R8d=1. They therefore prepare `cp -al`, subject to normal
helper returns and valid input memory. No process is started by this analysis.

## The two lifecycle routes are different

The body saves incoming ECX in EBP. At `0x44682e6` it tests **BPL**, hence only
the low input byte, and JE `0x4468692` selects the zero route. It does not test
the entire incoming word. Prior to that split, it prepares a path, calls the
directory-shaped predicate through slot `0x64e0928`, and, when false, prepares
mode `0x1ff` plus byte 1 for helper `0x5c8f4c0`. A nonzero RAX from that helper
reaches the Location-associated failure sequence at `0x446897c`.

The nonzero route:

1. Prepares a path from context `+8`/`+16` and invokes the `cp -al` adapter at
   `0x4468379`; nonzero RAX branches to `0x446887c`, the line291 failure arm.
2. Selects an encoded literal record containing `/checkpoint` at `0x434739`.
   Call `0x1696b90` prepares another path. The predicate through `0x64e0950`
   controls JE/JNE at `0x44684b1..0x44684b4`.
3. A true predicate skips to `0x4468643`. A false predicate reaches a second
   `cp -al` adapter call at `0x44684dc` (line302), followed by another
   `0x1696b90` call and opaque helper `0x1505a50`.
4. In that latter route it formats `/lt_hashes.json` from literal record
   `0x44f3c9`, tests the result using the regular-file-shaped predicate, and
   invokes helper `0x1505de0` only on the true arm (`0x44685ae` falls through
   to the call at `0x446860a`). The zero arm skips directly to cleanup at
   `0x446862e`. Nonzero helper result takes the line310 failure arm.

The zero route at `0x4468692` prepares one context path and invokes the same
`cp -al` adapter once at `0x4468700`, then joins common code at `0x4468724`.
It does not traverse the `/checkpoint`/`/lt_hashes.json` preparation above.
Both normal routes then prepare another value and call `0x422f320`, passing
context+`0x18` and the line317 Location. At `0x44687c2..0x44687e2`, the body copies
48 bytes from an input pointer to its saved output pointer, then cleans up and
returns. The named context fields, helper effects and 48-byte object type remain
unknown; this is a **common publication boundary**, not established database
commit, atomic rename, final durability or rollback closure.

The predicate bodies qualify a narrower fact than successful filesystem reads:
after their metadata-shaped helper's success route, they mask the mode word by
`0xf000` and compare with `0x4000` (directory-shaped) or `0x8000`
(regular-file-shaped). Their observed metadata error routes drop the error and
return false. The metadata helper and host filesystem are not executed; repeated
metadata calls and possible races are not converted into a safety finding.

## Reproduction and controls

Python 3.12.3; Capstone 5.0.7; GNU objdump 2.42; Linux x86-64 analysis environment.
With the materialized retained target and pinned Capstone on Python's path:

```sh
python3 tools/checkpoint_lifecycle_static.py --output work/checkpoint-lifecycle
python3 -m unittest discover -s tests -p test_checkpoint_lifecycle_static.py -v
python3 tools/verify_packets.py
git diff --check
```

The generator verifies the complete target identity **before creating output or
calling native tools**. Native objdump receives only a private byte-identical
file copy. Its full-body exported bytes must match the original capture exactly
using the existing independent export decoder. No captured program, command
adapter, emulator, network connection, signing key or public dataset is run.

Five focused tests pass. Controls alter actual captured operands: the adapter's
flag-length immediate, flag LEA displacement, lifecycle JE displacement,
regular-file type immediate, a caller's indirect-slot displacement and a real
source Location line. Each alters the corresponding recovered relation or
binding. Wrong/truncated/same-size-modified targets fail before output creation.
These counterfactuals test evidence sensitivity, not execution equivalence.

Limits: no independent Rust reconstruction or differential run; no downstream
command-spawn closure; no source-owned schema recovery; no catalog completion
credit. Generated project-wide catalog updates and the full repository gates
are handled with the integration commit, separately from these focused checks.
