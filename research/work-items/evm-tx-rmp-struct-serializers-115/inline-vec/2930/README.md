# Family-a inline-Vec Eip2930 writer

Close this work item's explicitly excluded `0x2332ac0` caller, not its
already covered by-reference `0x2332eb0` body. Component `evm`.
Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
Actual FDE `0x2332ac0..0x2332ea1`: 993 bytes / 234 instructions.

Entry RDI=output, RSI=payload B, RDX=inline-Vec buffer. Mode is +0x1b,
not the sibling Serializer+0xb. Capacity/storage/length are +0/+8/+0x10.
Header is low-byte `((mode XOR 1)<<4) OR 0x88`: 0x98 for mode 0,
0x88 for mode 1, 0xb8 for mode 2. Chain is unconditional; field count is eight.

| Order | Field / observed delegate | Source |
| --- | --- | --- |
| 1 | chainId / 0x29feb10 | qword +0x50 via stack temporary |
| 2 | nonce / 0x29feb10 | qword +0x58 via stack temporary |
| 3 | gasPrice / 0x2967e20 | address +0x40 |
| 4 | gas / 0x29feb10 | qword +0x60 via stack temporary |
| 5 | to / 0x26e5590 | address +0x80 |
| 6 | value / 0x233aff0 | B in R8, key length 5 |
| 7 | delegated collection / 0x233b630 | address +0x68 |
| 8 | input / 0x233b960 | address +0x20 in R8, key length 5 |

Access-list interpretation of field seven is inference from its record
position; its schema remains opaque. The three inline keys and separately
called gas/to keys all require mode exactly 1. Gas/to use 0x25e8bf0 with
pool 0x5eab49 length 3 and 0x5eab4c length 2. This to-key gate differs from
the family3 Eip2930 writer's nonzero gate. Value/input key policy is delegated.
Pool bytes and exact wired lengths are retained without claiming adjacent
pool data as extra fields.

Each nested stack result must equal 0x8000000000000004 before the next
field; other results copy all three words. Full completion writes only that
discriminator. Separate key results require RAX=2 and otherwise package
RAX/RDX under 0x8000000000000000. Inline growth calls use 0x231e050,
reload descriptor fields and rejoin stores; allocator/nested behavior is open.

```sh
python3 research/work-items/evm-tx-rmp-struct-serializers-115/inline-vec/2930/verify.py
```

Python, Capstone 5.0.6, pyelftools 0.32. Full SHA/FDE, complete decode,
instruction/data pins and branches checked. Ten operative mutations reject
below image SHA guard; independent header checks cover all 256 modes. Full
raw/FDE/CIE/call/branch/pool exports retained. No captured execution/interpreter.
Valid stable nonaliasing storage, capacity invariants and normal helper returns
are assumptions. Nested encoding, allocation/unwind behavior and full native
suite remain unqualified. No gates change. Next: close the separately excluded
dynamic-fee inline writer without transplanting this layout's field offsets.
