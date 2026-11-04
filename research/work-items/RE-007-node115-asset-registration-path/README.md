# RE-007: map node115 indexed-entry registration, name-record push and 96-byte state append

- Component ID: RE-007 (oracle/per-index state), with the registry records it shares (`l1/src/perp_meta.rs`)
- Target release and full SHA-256: Linux x86-64 node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `05bc2de303c05525b71e7e257426e741bc66a390`; no source tree was copied
- Claim status: observations (below), inferences (separate section), unresolved items (separate section)
- Scope included: the four complete FDE extents listed next. Scope excluded: every callee outside them, the one direct caller, units and value semantics, and any Rust reconstruction

Independently authored static research; no inferred source was copied and the target was never executed or emulated.

- Complete FDE `[0x446bf60,0x446c1fa)`: 666 bytes / 152 instructions (entry, no LSDA).
- Complete FDE `[0x3c42130,0x3c4265d)`: 1325 bytes / 290 instructions (parameter checks, LSDA `0x2f8608`).
- Complete FDE `[0x3c42660,0x3c4287e)`: 542 bytes / 105 instructions (id decode).
- Complete FDE `[0x3d16b20,0x3d16b84)`: 100 bytes / 32 instructions (32-byte element push, LSDA `0x303f30`).

Export denominator: **2633 bytes / 579 instructions**. These are evidence extents,
not recovered or compiled-comparison coverage. No progress gate is requested.

## Question and local convention

When one indexed entry is registered, which checks run, what is written to the two
parallel vectors (32-byte name records and 96-byte state records) and how are the
entry id and the vector index related? The entry body and its three callees form ONE
outcome. `0x3c42130`, `0x3c42660` and `0x3d16b20` each have exactly one direct caller
(`0x446bf60`, `0x3c42130` and `0x3c42130`) among all `E8` calls in `.text`.

Register roles below are SysV ABI observations at instruction level; no original
public ABI, field names or units are recovered. The state object is the entry's RSI.
Vector headers are read as `{capacity, pointer, length}` because the push and
rollback code uses them in that order.

## Entry body `0x446bf60`

Arguments observed: RDI output, RSI state, RDX pointer to a 12-byte value (qword at +0,
dword at +8), RCX parameter block passed on as the validator's RDX, R8 a value compared
with 1, R9 a qword passed on as the third argument of `0x3cdfaa0`.

| Step | Instructions | Observation |
| --- | --- | --- |
| Validate | `0x446bf88` | `call 0x3c42130(out=rsp+0x10, state, RCX)` |
| Tag test | `0x446bf92` | result word at `[rsp+0x10]` is compared with `0x1a2`; any other value copies result bytes `+2..+0x6f` and the tag word to the output and returns |
| Ok payload | `0x446bf9d..0x446bfab` | R13 = `[rsp+0x18]`, R14 = `[rsp+0x20]` |
| Optional insert | `0x446bfad..0x446c0bc` | if qword `[state+0x378]` equals `0x8000000000000000` the whole step is skipped; otherwise an unsigned-key tree search of R13 starts at root `[state+0x4c8]` (height `[state+0x4d0]`, keys at node+0x10, length word at node+0x62, edges at node+0x68) and, when the key is absent, `call 0x3709480` runs with a local entry descriptor |
| Index | `0x446c0c1..0x446c0e2` | R12 = R13 modulo 10000 (multiply-high by `0x346dc5d63886594b`, shift 11, multiply by `0x2710`, subtract) |
| Index check | `0x446c0ea..0x446c0ff` | R12 is compared with qword `[state+0x158]`; unequal jumps to `0x446c1dc` |
| Mismatch route | `0x446c1dc..0x446c1fa` | `lea r9` the Location `0x646e428` (`l1/src/clearinghouse/oracle/oracle.rs:110:13`), pointers to both compared values, `call [0x64dfa18]`; the extent ends after that call |
| Grow | `0x446c0ff..0x446c111` | if R12 equals `[state+0x148]` (capacity) `call [0x64e6160]` |
| 96-byte append | `0x446c111..0x446c17d` | element address `[state+0x150] + R12*96`; see the table below; then `[state+0x158] = R12+1` |
| Map update | `0x446c17d..0x446c1ba` | only when R8 equals 1, `[state+0x378] != 0x8000000000000000` and `[state+0x408] != 0x8000000000000001`: `call 0x3cdfaa0(state+0x428, R13, original R9)`; the returned value is not used |
| Ok output | `0x446c1ba..0x446c1c7` | `[out+8] = R13`, `[out+0x10] = R14`, word `[out] = 0x1a2` |

The 96-byte element (offsets from the element base, all stores in `0x446c120..0x446c16f`):

| Offset | Value written |
| --- | --- |
| `+0x00`, `+0x08` | R14 |
| `+0x10` qword, `+0x18` dword | qword `[RDX]`, dword `[RDX+8]` |
| `+0x20`, `+0x28` | R14 |
| `+0x30` qword, `+0x38` dword | qword `[RDX]`, dword `[RDX+8]` (same source as `+0x10`) |
| `+0x40`, `+0x48` | R14 |
| `+0x50` qword, `+0x58` dword | rodata `0x7bd538` (`1a40f60000000000`) and `0x7bd540` (`00000000`) |

Bytes `+0x1c..+0x1f`, `+0x3c..+0x3f` and `+0x5c..+0x5f` are not written by this body.

## Validator `0x3c42130`

Parameter block (RDX, kept in RBX), observed offsets: a triple at +0, +8, +0x10 used as
`{capacity, pointer, length}` of a first string; a second triple at +0x18, +0x20, +0x28;
a dword at +0x30; bytes at +0x34 and +0x35. State (RSI) fields read: name-record vector
`{+0, +8, +0x10}`, qword `+0x50`, a membership container at `+0x30/+0x38/+0x40`.

Checks in program order and the result tag each writes (word at the output base):

| Order | Instructions | Condition | Tag and payload |
| --- | --- | --- | --- |
| 1 | `0x3c42157..0x3c4217c` | first string length is not below `0x65` (101) | `0x158`; observed length in `[out+0x18]`; first buffer freed through `[0x64df4a0]` when its capacity word is nonzero |
| 2 | `0x3c42181..0x3c42198` | name-record count `[state+0x10]` is above `0x270f` (9999) | `0x64`; count in `[out+8]` |
| 3 | `0x3c42209..0x3c42245` | an existing 32-byte record has the same length (`+0x10`) and `bcmp` of the bytes (import slot `0x64df9f8`) returns 0 | `0x3e`; the first string triple moved into `[out+8..+0x20)` |
| 4 | `0x3c4224a..0x3c4225c` | byte `[params+0x35]` is above 6 | `0x41` |
| 5 | `0x3c42261..0x3c4226b`, `0x3c423b1..0x3c42445` | dword `[params+0x30]` is `0x32` (50) or more and the membership test fails | `0x16a`; the dword in `[out+4]`. Container variant A (qword `[state+0x30]` not `0x8000000000000000`): the failing result is a nonzero return of `0x4556c50(state+0x30, &key)`. Variant B (qword equals `0x8000000000000000`): the key is not found in a tree rooted at `[state+0x38]` (u32 keys at node+0x2cc, length word at node+0x2f6, edges at node+0x2f8) |
| 6 | `0x3c4227f..0x3c42291`, `0x3c42423` | second string length `[params+0x28]` is `0x65` or more | `0x158`; no length is stored in this arm |
| 7 | `0x3c4229f..0x3c422af` | `call [0x64e4e60](out=rsp+0x40, second string pointer, length)` does not return tag `0x1a2` | the failing result is copied to the output (`0x3c42451`) |

If all checks pass, the first string and two bytes become one 32-byte name record,
built at `0x3c422bc..0x3c422f9` and pushed by `call 0x3d16b20`:

| Record offset | Value |
| --- | --- |
| `+0x00`, `+0x08`, `+0x10` | the first string triple (capacity, pointer, length) |
| `+0x18` | dword `[params+0x30]` |
| `+0x1c` | byte `[params+0x34]` |
| `+0x1d` | byte `[params+0x35]` |

`0x3d16b20` reads length `[vec+0x10]`, calls `[0x64e60f0]` when length equals capacity
`[vec]`, stores the 32 bytes at `[vec+8] + length*32` and writes `length+1`.

Id composition (`0x3c422f9..0x3c42393`): ID = `[state+0x50] * 10000 + old_length`, where the
multiplication saturates to `UINT64_MAX` on overflow (`mul`/`jo`) and the addition
saturates on carry (`cmovae`). The id must satisfy `ID / 10000 == [state+0x50]` and
`ID % 10000 < [state+0x10]` (the length after the push); otherwise the internal result
takes tag `0x64` with the id (`0x3c42512`). Then `call 0x3c42660(out=rsp+0xb0, ctx, ID)`
runs, where `ctx` holds the state pointer and the 16 payload bytes that `[0x64e4e60]`
returned at result offset +4.

On an Ok tag (`0x1a2`) from `0x3c42660`, 16 bytes at its output +8 are copied to
`[out+8]` and the word `[out]` is `0x1a2`. On any other result the name-record push is
rolled back (`0x3c425b3..0x3c425d6`): length is decremented, the removed record's buffer
is freed when its capacity word times 2 is nonzero, `call 0x3d08df0` consumes the inner
result, and the output word is `0x152`. In this extent that arm writes only the tag word.

## Id decode `0x3c42660`

Inputs: RDI output, RSI pointer to a context `{state, 16 bytes}`, RDX the id.

1. `0x3c42688..0x3c426b3`: `id / 10000` must equal `[state+0x50]` and `id % 10000` must be below `[state+0x10]`; otherwise `lea rdi` Location `0x64768a8` (`l1/src/perp_meta.rs:163:38`) and `call [0x64df830]`.
2. `0x3c426b3..0x3c426c8`: byte `A = [[state+8] + index*32 + 0x1d]`; `A >= 7` selects Location `0x6478258` (`l1/src/perp_meta.rs:287:28`) and `call [0x64df848]` (`0x3c42871`).
3. `0x3c426c8..0x3c426ea`: `call [0x64e6468](rsp+0x10, &16-byte context part, 2, 6 - A)`.
4. If the returned word is `0x1a2` and the returned qword `[rsp+0x18]` is nonzero, `[out+0x10]` is that qword, `[out+8]` is the id and `[out]` is `0x1a2`. Every other route reaches the shared tail with word `0xad`. The nonzero test and its zero arm are observed but not interpreted.

## Inferences (not observations)

- The entry output pair `(R13, R14)` is `(id, qword returned by the helper)`: `0x3c42660` stores the id and the helper qword at output +8 and +0x10, and the entry reads exactly those words. R14 is then stored six times in the 96-byte element.
- Because the entry requires `id % 10000 == [state+0x158]`, the 96-byte vector length tracks the name-record vector length as long as the registration path is the only appender. This is an inference about invariants; other writers of either vector were not measured.
- `6 - A` with `A <= 6` and the constant 2 is consistent with a decimals relation of the form "six minus a size-decimals byte", which matches the public Hyperliquid description of perpetual price precision. The source of the byte `[params+0x35]` was not traced, so this is a lead.
- The calls through `[0x64df4a0]`, `[0x64e6160]`, `[0x64e60f0]` and `[0x64dfa18]` are consistent with buffer free, vector growth and an equality-assertion panic respectively. Their targets (`0x635de30`, `0x43bbdb0`, `0x43bbe20`, `0x167bbb6`) are outside the measured windows and were not decoded.

## Unresolved

- Meaning of every helper outside the windows: `0x43099f0` (second-string parse), `0x421e9d0` (the `(payload, 2, 6-A)` computation), `0x3709480`, `0x3cdfaa0`, `0x3d08df0`, `0x3d57b80`, `0x4556c50`.
- Contents and field names of the 96-byte element beyond the store pattern; units of R14.
- Which fields the constant at `0x7bd538` initialises.
- The sole direct caller of the entry is `0x38b3f90` (call at `0x38b4206`, extent `[0x38b3f90,0x38b4546)`). It has no direct `E8` caller; its address is stored by a relative relocation in slot `0x64e7c38`. An ad-hoc scan (not retained in this packet) found nine `ff15`/`ff25` references to that slot in nine other extents, which are leads only.
- No Rust implementation, no function-window comparison, no gate.

## Reproduction and negative controls

Linux Python 3.14.4 and GNU binutils 2.46 (recorded in `tool-versions.json`); no target execution or emulation. The target is the Git LFS object `artifacts/node/115/hl-node`.

```sh
python3 research/work-items/RE-007-node115-asset-registration-path/collect.py --output work/registration-replay --check
python3 -m unittest tests.test_asset_registration_static -v
```

The collector authenticates the complete target (size and SHA-256) before any native command, compares the independent ELF/FDE/relocation parse with GNU `readelf -wf` and `readelf -rW`, exports the four extents with `objdump`, and checks 40 byte anchors, 3 source Locations (each bound by relocation, string bytes and a `lea` cross-reference) and the `bcmp` import slot. `records.json` is the retained machine-readable result and `MANIFEST.sha256` binds every file in this directory.

Negative controls (private `bytearray` copies only): one-bit corruption of the first, middle and last byte of every anchor is refused with `changed native anchor`; 18 claim bytes (limits 101, 9999, 6, 50, the `0x1a2`, `0x3e`, `0x41` and `0x152` tags, the modulus 10000, the strides 96 and 32, the flag value 1 and two state displacements) are verified against their documented original value and each counterfactual is refused; an altered target identity fails before any native tool or output; and all exported files regenerate byte-for-byte.

## Limitations and next step

Static evidence only. Anchors prove that the cited instruction bytes exist at the cited addresses in this exact binary; they do not prove source-level types, names or semantics. The register roles and the field offsets are instruction-level observations. The shared-state layout was not closed.

Next question: what do `0x43099f0` and `0x421e9d0` compute from the second string and the `(payload, 2, 6 - A)` triple, and which writer sets the byte at `[params+0x35]` before it reaches this path?
