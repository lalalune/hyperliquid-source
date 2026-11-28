# RE-006: auxiliary-map sibling transfer in both directions

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations and interpretations only. No captured code is executed or emulated; no component gate is claimed.

## Question and prior work

[#7860](https://github.com/lalalune/hyperliquid-source/pull/7860) maps the auxiliary-map leaf underflow decision; [#7883](https://github.com/lalalune/hyperliquid-source/pull/7883) traces the lower-occupancy merge case. What do the two higher-occupancy sibling-transfer callees do to counts and parent separator lanes? #7733 covers a different quantity-tree layout; this packet binds the auxiliary map's 16-byte-stride key lanes and 8-byte value column to both selected directions.

## Static observations and interpretation

The caller at `0x4d20da9` passes transfer count 1 to `0x4c93920`; the alternate caller at `0x4d20dd9` passes count 1 to `0x4c9c8d0`. The preceding sibling-selection and occupancy gates are documented in #7860 and are not re-proved as complete control flow here.

In the first callee, the node at descriptor `+0x28` is the recipient and the node at `+0x18` the donor. The code checks recipient count plus requested amount is below 12 and donor subtraction does not borrow, then stores the increased recipient count and decreased donor count. It shifts the recipient's 16-byte key slots and 8-byte value slots, and copies selected donor suffixes. At the parent separator selected through descriptor `+0/+0x10`, it swaps a donor qword/dword key pair and qword value into the parent and writes the previous parent pair/value into the recipient. The retained window ends at that exchange; later child handling and errors are outside scope.

In the second callee, the roles of descriptor `+0x18` and `+0x28` are reversed for the count update. It checks the analogous recipient capacity and donor subtraction, saves the donor boundary key/value, places them into the parent separator, and writes the previous separator qword/dword pair and qword value into the recipient. It then copies and shifts portions of the 16-byte key and 8-byte value columns. Selected direct and register-held calls resolve to ELF dynamic slots for `memmove` and `memcpy`; this verifies the relocation and symbol names, not runtime library binding or behavior for malformed overlap.

`records.json` retains 694 bytes / 154 instructions in four windows of the caller and both callee FDEs. Seventy static instruction, address and relocation facts and 29 in-memory opcode/operand or relocation mutations bind the selected counts, copies and separator exchanges to the authenticated ELF. These are static checks, not target runtime tests. `offline-log.json` contains the actual verifier result.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-aux-sibling-transfer/verify.py
(cd research/work-items/RE-006-node115-book-aux-sibling-transfer && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the full target and decodes each selected window from its FDE start. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

Only the selected portions of both callees and two caller windows are covered. Valid tree structure, requested counts, indices, normal copy calls and ABI behavior are premises. Remaining child pointer updates, error and unwind paths, the caller's later cursor/flag processing and complete B-tree correctness remain unresolved. Next, bind the selected callees' child-edge transfers and parent/index repairs without treating the full map gate as complete.
