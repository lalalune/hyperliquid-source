# evm: family-3 Legacy payload field selection and failure propagation

Component: `evm`. Recover `0x5b5ecf0`, the tag-0 payload target of the
family-3 envelope at `0x5b69bb0`. The envelope dispatch and other transaction
families are boundary context. This packet owns the local Legacy field
selection, argument wiring, container cardinality and failure exits.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
Actual FDE `0x5b5ecf0..0x5b5f181`: 1,169 bytes / 284 instructions.
Complete raw bytes, FDE/CIE records, calls and direct branches are exported.

## Observed container and field layout

Entry RDI is output, RSI is payload B, RDX is buffer descriptor. The envelope
passes enum+0x10 as B. All offsets below are payload-relative, not enum-relative.
Buffer mode is byte +0x1b; capacity/storage/length are +0/+8/+0x10.

`cmp qword [B],1; mov edx,7; sbb edx,0` computes cardinality 6 when [B]=0,
otherwise 7. Nonzero mode calls container helper `0x57cdfd0`; mode zero calls
`0x57cee80`. Their stack result qword must equal 2 before any fields run.
Map/array names for these two helpers are inferred from the mode convention;
the observation here is their addresses, length argument and return test.

| Order | Key | Source / writer |
| --- | --- | --- |
| optional first | chainId | qword presence B+0; qword value B+8 via stack temporary to `0x4fb2950` |
| next | nonce | qword B+0x60 via stack temporary to `0x4fb2950` |
| next | gasPrice | address B+0x30 passed to `0x4f000d0` |
| next | gas | qword B+0x68 via stack temporary to `0x4fb2950` |
| next | to | byte B+0x70 selects address B+0x71 to `0x4e2e020` when exactly 1; otherwise `0x52f0170` with buffer |
| next | value | address B+0x40 in R8, key pointer 0x93e4a6, length 5, to `0x5b69430` |
| final | input | address B+0x10 in R8, key pointer 0x93e4ab, length 5, to `0x5b69050` |

Key byte evidence at 0x93e4a4 is `to`, followed by `value` and then `input`.
The last two fields' observed order is value before input. Nested serializers
are opaque; qword values and pointers here do not establish concrete Rust types.

The chain field is omitted completely when the full qword [B] is zero. If
nonzero, its key is emitted only when mode equals 1. On that key-writing path,
the code then tests the *low byte* of [B] against zero: low byte zero emits nil
0xc0 instead of calling the value writer. Other modes bypass this byte test
and call the writer. Thus [B]=256 is a useful noncanonical witness: cardinality
7 in every mode, nil in mode 1, value writer in mode 0/2. This is arithmetic
evidence, not a claim that such an Option representation is valid.

The inline chainId, nonce, gasPrice and gas keys require mode exactly 1.
The separately called `to` key writer `0x57cf5d0` requires any nonzero mode,
with key length 2. The mode policy of value/input is delegated to their
callees and remains outside this packet. Destination selection compares
exactly against 1, not against nonzero.

## Result representation

R12 starts at 0x8000000000000004. Every nested field writer result must match
that full stack discriminator before continuing. Otherwise the body copies
the three stack words to output and returns, without later fields. All-field
completion writes only the discriminator. Container-helper failure instead
uses discriminator 0x8000000000000000 and copies its two payload words.
The separate `to` key writer uses RAX=2 as its continuation marker; another
RAX repackages RAX/RDX under 0x8000000000000000 before the shared copy exit.
No semantic success/error enum names are assumed beyond these values.

Nine local growth calls target `0x5963a10`. They cover inline keys and the nil
byte with length/alignment setup, reload buffer fields, then rejoin stores.
Allocation/failure semantics of that helper are not recovered here.

## Reproduce and limits

```sh
python3 research/work-items/evm-family3-legacy-payload-115/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. `--write` regenerates exports.
Full-image SHA, actual FDE, complete decode, exact instruction/data pins and
internal branch targets are checked. Eleven operand/branch mutations must
reject with image SHA guard disabled. Independent conditional checks cover
256 modes, five chain-tag representatives and all 256 destination bytes:
327,680 cases. They check cardinality, omission/nil distinction and exact-one
destination selection. No captured instruction executes or is interpreted.

Assumptions: valid payload/buffer pointers, stable nonaliasing objects,
capacity invariants and normally returning helpers. Noncanonical chain tags
are witnesses only. Numeric/address/bytes encodings, external key policies,
allocator behavior, exceptional paths and full EVM acceptance remain open.
No progress gate changes.

Next question: recover the access-list payload's additional field and compare
its fixed cardinality with this optional-chain layout, retaining actual
source offsets rather than assuming a shared struct layout.
