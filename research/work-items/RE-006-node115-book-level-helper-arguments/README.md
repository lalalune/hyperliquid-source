# RE-006: book-level helper argument origins in insert and removal

- Component: order book, issue #3915; Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `2da45cb0a761cff6b478e40421699857d87a94df`; addresses are ELF virtual addresses.
- Selected static observations and dataflow interpretations only. No captured code is executed or emulated; no component gate is claimed.

## Question and prior work

[#7873](https://github.com/lalalune/hyperliquid-source/pull/7873) binds the shared level helper `0x518e690` to a 12-byte context and floating argument but leaves their caller origins open. What does one removal caller supply, and does one insertion caller use the same helper interface? Existing `RE-006-node115-book-level-removal` and `RE-006-node115-book-ring-append` establish the two calls and level/slab context; this packet adds the selected argument provenance, without asserting a higher-level structure type or units.

## Static observations and interpretation

At removal owner `0x58e1400`, `0x58e141b` saves its incoming fourth integer argument `rcx` in `r13`. On the selected tree lookup or flat lookup paths, the code reaches `0x58e1a27` with that pointer: it copies the qword at pointer `+0x60` and dword at `+0x68` into adjacent stack fields and passes their address as `rsi`; it loads a binary64 from pointer `+0x15c8` into `xmm0`. It passes the selected level and `book+0x80` slab in `rdi/rdx`, then calls `0x518e690`. The verifier checks the two relevant decoded path regions for direct writes to `r13`, excluding the separate intervening branch `0x58e163d..0x58e19d3`; the conclusion is limited to the selected paths and assumes calls obey the normal SysV callee-saved convention. It does not establish who constructs the incoming pointer or fields.

In insertion owner `0x5911890`, the original `xmm0` is saved at stack `+8`; after a nonnegative field check, its incoming third integer argument `rdx` is retained in `r15`. The selected instructions pass `r15` as the helper's context pointer, reload `xmm0` from stack `+8`, and pass the lookup result and `book+0x80` slab before the same call. The verifier checks for direct `r15` writes between its assignment and that call. It does not prove that the insertion pointer equals the removal copy, that intervening callees cannot write through aliases, or that these caller arguments have a particular semantic type. The helper's entry saves `xmm0` and retains `rsi`, matching the inputs studied in #7873.

`records.json` retains 261 bytes / 61 instructions across four windows of the two caller FDEs and the helper FDE. Twenty-six static instruction facts, 19 in-memory opcode/operand mutations and three selected-region register-preservation checks bind the described moves and calls to the authenticated ELF. These checks do not execute the target, enumerate all control-flow paths or verify external callees. `offline-log.json` is the actual verifier result.

## Reproduce

From the repository root with Python 3.11, Capstone 5.0.6 and the pinned ELF:

```sh
PYTHONPATH=tools python3 research/work-items/RE-006-node115-book-level-helper-arguments/verify.py
(cd research/work-items/RE-006-node115-book-level-helper-arguments && shasum -a 256 -c MANIFEST.sha256)
```

The verifier adapts the project's MIT-authored `RE-006-node115-book-level-removal` verification structure and ELF/FDE support. It authenticates the full target and decodes selected windows from FDE starts. Mutation controls bypass the digest only for altered in-memory views.

## Limits and next question

Only the stated caller paths and selected regions are covered. Caller ownership, indirect aliases, other paths and instances, pointer lifetime, context producer, field types and units, float edge cases, concurrency, unwind and end-to-end order semantics remain unresolved. Next, trace the source of the removal owner's fourth argument and its `+0x60/+0x68/+0x15c8` fields at a validated upstream call site.
