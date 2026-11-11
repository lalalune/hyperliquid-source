# evm: family-3 Eip2930 eight-field payload

Component: `evm`. Recover the tag-1 payload writer `0x5b5fd50` selected by
the family-3 envelope. Its fixed eight-field layout differs from Legacy's
optional chain field and source offsets. Envelope selection, other payload
writers and nested value encodings are outside this packet's ownership.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
Actual FDE `0x5b5fd50..0x5b60147`, 1,015 bytes / 241 instructions.
Full body/FDE/CIE bytes, all calls and direct branches are retained.

## Observed layout and container

Entry RDI=output, RSI=payload B (enum+0x10 at the parent), RDX=buffer.
Descriptor capacity/storage/length/mode are +0/+8/+0x10/+0x1b.
The header is low-byte `((mode XOR 1)<<4) OR 0x88` at `0x5b5fd67..0x5b5fd88`:
mode 0 gives array-8 0x98, mode 1 map-8 0x88, mode 2 0xb8.
Unlike Legacy, the chain field is unconditional and no presence test adjusts
the cardinality.

| Order | Key | Source / nested call |
| --- | --- | --- |
| 1 | chainId | qword B+0x50, stack temporary address to `0x4fb2950` |
| 2 | nonce | qword B+0x58, stack temporary address to `0x4fb2950` |
| 3 | gasPrice | address B+0x40 to `0x4f000d0` |
| 4 | gas | qword B+0x60, stack temporary address to `0x4fb2950` |
| 5 | to | tag B+0x80 == 1: address B+0x81 to `0x4e2e020`; otherwise `0x52f0170` |
| 6 | value | B in R8, key length 5 to `0x5b69430` |
| 7 | accessList | address B+0x68 in RDX to `0x5b691e0` |
| 8 | input | address B+0x20 in R8, key length 5 to `0x5b69050` |

The first three keys are inline literals gated on mode exactly 1. The gas key
uses `0x57cf5d0` with pool pointer 0x93e4a1, length 3, also only in mode 1.
The to key uses pool 0x93e4a4, length 2, for any nonzero mode. Value and input
key pointers are 0x93e4a6 and 0x93e4ab; their mode policies are delegated.
Only the exact wired lengths are key claims; exported 32-byte pool windows
retain surrounding context without assigning all adjacent bytes to a field.

The accessList name has a separate bounded callee-prefix witness:
`0x5b691e8..0x5b6922f` tests mode exactly 1 and writes aa followed by the
ten bytes `accessList` using imm64 `0x694c737365636361` and imm16 `0x7473`.
That prefix is pinned as context data, not a newly owned complete function.
The access-list array serializer and its contents remain opaque.

Destination tag selection is an exact-one test. Nonzero tags other than 1
take the alternate writer; no general nonzero/address equivalence is claimed.
Source offsets are observations; inferred numeric/address/Rust types are not
needed to state this wiring.

## Result paths and boundaries

R12 holds 0x8000000000000004. Each nested writer's full stack qword must
equal it before continuing. All-field completion writes only that output
discriminator; a differing result copies all three stack words to output and
skips remaining fields. Separate key-writer calls use RAX=2 for continuation;
another RAX packages RAX/RDX under 0x8000000000000000 before the copy exit.
The two copy blocks are retained rather than interpreted as different Rust
types. Allocation paths call `0x5963a10`, reload the descriptor and rejoin
the corresponding marker/name store; its internals are out of scope.

## Reproduce and limits

```sh
python3 research/work-items/evm-family3-eip2930-payload-115/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. `--write` regenerates exports.
Full SHA, actual FDE, complete decoding, instruction/constant pins and internal
branch destinations are checked. Eleven operative mutations, including an
accessList literal byte, reject below the full-image SHA guard. Independent
conditional checks cover all 256 modes and all 256 destination tags (65,536
cases), plus full-width result-discriminator representatives. These are scalar
models, not captured-instruction execution or interpretation.

Assumptions: valid buffer/payload pointers and capacity invariants, stable
nonaliasing objects and normal helper returns. Nested numeric/address/access
list/bytes encodings, delegated key policies, allocator failure behavior,
exceptional paths and full component acceptance remain unknown. No gates change.

Next question: recover the dynamic-fee payload's additional fee fields and
their actual source offsets; do not assume this eight-field struct is reused.
