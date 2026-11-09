# evm: family-3 Eip1559 dynamic-fee payload

Recover the tag-2 envelope target `0x5b5f6d0`, component `evm`.
Target: node #115 Linux x86-64, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Analysis base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; submission base
`0781ce04826eeefd89fe336cb8ea073be0c1de30`. This is a subordinate payload
packet extending the merged typed-envelope work item, not a new component gate.
Actual FDE `0x5b5f6d0..0x5b5fa92`, 962 bytes / 232 instructions.

Entry RDI=output, RSI=payload B (parent enum+0x10), RDX=buffer descriptor.
The descriptor's mode byte is +0x1b. Header computation at
`0x5b5f6e5..0x5b5f706` is low-byte `((mode XOR 1)<<4) OR 0x89`:
mode 0 gives array-9 0x99; mode 1 map-9 0x89; mode 2 gives 0xb9.
There is no optional-chain cardinality test as in Legacy.

| Order | Field / observed call | Payload source |
| --- | --- | --- |
| 1 | chainId, `0x4fb2950` | qword +0x60 via stack temporary |
| 2 | nonce, `0x4fb2950` | qword +0x68 via stack temporary |
| 3 | gas, `0x4fb2950` | qword +0x70 via stack temporary |
| 4 | maxFeePerGas, `0x4f000d0` | address +0x40 |
| 5 | maxPriorityFeePerGas, `0x4f000d0` | address +0x50 |
| 6 | delegated destination, `0x5b6ac70` | address +0x90 in RDX |
| 7 | value, `0x5b69430` | B in R8, key length 5 |
| 8 | accessList, `0x5b691e0` | address +0x78 in RDX |
| 9 | input, `0x5b69050` | address +0x20 in R8, key length 5 |

The first three inline keys require mode exactly 1. The fee keys call
`0x57cf5d0` only in mode 1, using pool 0x93e4b2 length 12 and 0x93e4be
length 20. Their byte strings are pinned in the exports, as are value/input
pool pointers and a bounded mode-one accessList key-writing prefix in the
callee. Surrounding pool bytes are context, not additional field claims.
The destination helper and delegated keys' complete policies remain opaque.
Numeric/address/Rust type names are inferred; source offsets and calls are
observations. No Eip2930 struct-layout reuse is assumed.

Every nested result must have full discriminator 0x8000000000000004 before
the next field runs. A differing result copies its three words to output;
all-field completion writes only the discriminator. Fee-key failure uses
RAX!=2 and packages RAX/RDX under discriminator 0x8000000000000000 before
the copy exit. Local buffer-growth paths call `0x5963a10`, reload descriptor
fields and rejoin stores. Allocation and nested encodings are not recovered.

Reproduce with Python, Capstone 5.0.6 and pyelftools 0.32:

```sh
python3 research/work-items/evm-family3-typed-envelope-115/payloads/eip1559/verify.py
```

`--write` regenerates exports. Full image SHA, FDE, complete decoding,
instruction/data pins and internal branch boundaries are checked. Eleven
operative mutations reject below the image SHA guard. Independent scalar
checks cover all 256 header-mode bytes and six full-width result classes.
They do not model the delegated destination or execute captured instructions.

Assumptions: valid stable nonaliasing pointers, buffer invariants and normal
helper returns. Source-type validity, nested encodings, delegated key policies,
allocation failures, unwinding and EVM acceptance remain open. No gates change.
Next question: recover the destination-field helper separately from this
caller's nine-field record, including its nil/address and mode rules.
