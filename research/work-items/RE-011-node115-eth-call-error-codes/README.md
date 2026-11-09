# RE-011: eth-call result builder's selected error-code handoff

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Partial static evidence for [EVM JSON-RPC issue #3922](https://github.com/lalalune/hyperliquid-source/issues/3922). The [eth-call request packet](../RE-011-eth-call-path-115/README.md) connects the outer future to result builder `0x22d7030` but leaves its result translation open. This packet maps one eight-entry selector and its selected result handoff; it does not establish final JSON or wire behavior.

The caller at `0x2d092ad` supplies a stack output at `rsp+0x500` and an input record at `rsp+0x260`. In the builder, input dword `+0x10` unequal to 3 selects an arm which loads a dword index at input `+0x40`, sets an internal output tag to 1, and dispatches through eight signed relative entries at `0x5e9584`. The binary does not perform a bounds check at this point, so **index 0–7 is an explicit premise**, not a claim that malformed inputs are safe.

| Index | Dword selected for result `+0x14` |
| ---: | --- |
| 0 | `0xffff8044` (signed −32700) |
| 1 | `0xffff82f9` (signed −32007) |
| 2 | `0xffff80a8` (signed −32600) |
| 3 | `0xffff80a7` (signed −32601) |
| 4 | `0xffff82f7` (signed −32009) |
| 5 | `0xffff80a6` (signed −32602) |
| 6 | `0xffff80a5` (signed −32603) |
| 7 | input dword at `+0x44`, copied unchanged |

All eight selected cases join the common formatting path. If the helper at `0x260a4e0` returns zero, the following `0x5c55c30` helper produces a nonzero first result word, and ordinary helper/ABI assumptions hold, the builder writes tag 1 at output `+0x10` and the selected dword at `+0x14`. The outer caller loads these eight bytes from its local result and copies them to its own result `+0x10..+0x17`. This is an internal result handoff; the table alone does not prove a JSON-RPC response, symbolic enum names, concrete error messages, network delivery, or handling of all result variants.

## Reproduce

```sh
PYTHONPATH=tools python3 research/work-items/RE-011-node115-eth-call-error-codes/verify.py
```

The static verifier authenticates the target, two complete indexed FDEs and their partitions (543 and 822 instructions), 98 selected instruction records, 46 pinned instructions, 14 edges, eight table entries and the result-helper relocation; six instruction mutations are rejected. Capstone 5.0.7 is required. The selected table and helper-return conditions are the denominator; no node or component completion is implied. The previously mapped request, limiter and worker are credited as context. No captured instruction is executed or emulated; component gates remain false.
