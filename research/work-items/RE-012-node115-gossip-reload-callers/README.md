# RE-012: state-machine call paths into gossip reload

- Component `node-runtime`; bounded question under [issue #3927](https://github.com/lalalune/hyperliquid-source/issues/3927): how can two actual enclosing node #115 paths reach the previously mapped connection-side reload lock?
- Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`. Addresses are linked ELF VAs before load bias.
- Static ELF/disassembly only. No target process, captured-instruction evaluation, network traffic or full startup/gossip equivalence. No acceptance gate is requested.

## Connection to previous work

The [connection lock packet](../RE-001-node115-connection-gossip-reload-lock/README.md) maps the conditional lock and reload inside `0x5a628d0`; the [gossip reload packet](../RE-014-gossip-reload-115/README.md) maps the inner comparator. They identify the inner call but do not connect these two enclosing calls through their selected result-byte gates. The [greeting packet](../RE-017-abci-greeting-115/README.md) and [block-fill packet](../RE-005-node115-block-fill-writers/README.md) provide prior context for the large enclosing FDEs and `0x2ae0920`; their broader semantics are not re-claimed here.

## Selected paths

Both calls below use indirect slot `0x64e7318 -> 0x5a628d0`; the site coordinates are `0x2acd967` and `0x2ad1880`. On each selected local path, the outer function reads a pointer from its object `+0x2158`. If that pointed object's byte `+0x90` equals 4, it jumps to the continuation after the connection call. Otherwise it stores the pointer plus `0x78` at outer `+0x2210` and calls `0x2ae0920` with a stack result. It reads the result's first byte. Value `0x45` stores byte 4 at outer `+0x2204` and takes the indicated alternate branch. For other values it calls `0x2ac07c0`, then invokes the connection slot only if the saved result byte equals `0x44`; other values take another branch. The saved byte is held in a System V nonvolatile register across the call. These are raw tags and branch observations, not names for all states or proof that any branch runs.

The second enclosing path has an additional condition: when outer byte `+0x2206` equals 1 it calls slot `0x64e7348 -> 0x4fb98f0`; a zero low byte takes a separate branch before `0x2ae0920`. The first selected path has no corresponding call in the retained window. On the `0x44` call arm, both reload `rdi` from outer `+0x2210`, the integer arguments from `+0x2200/+0x2206`, and `rcx` from `+0x2158`. A return byte equal to 3 continues at the same address reached by the early `+0x90 == 4` branch; other return bytes take another branch. The meaning of return value 3 is not established.

If the earlier stored outer pointer fields remain unchanged across the intervening helpers, `rdi` is the pointed object's `+0x78` and `rcx` is the pointed object. On the connection function's path where `[rcx] != 0`, it reads the qword at `rdi+0x10` (thus pointed object `+0x88`) and tests that shared object's byte `+0x10`. If zero, it attempts the already documented atomic 0-to-8 acquisition at shared `+0x18`; success, or a normally returning slow path, reaches `0x57d2f80` with shared object `+0x20`. It then attempts the documented 8-to-0 release. The alternative `[rcx] == 0` enters other code and may later rejoin; this packet does not call it a permanent bypass. If the shared byte is nonzero, this selected lock/reload block is skipped.

All pointer joins depend on valid objects, stable outer fields, normal helper returns and the stated System V register convention. The complete state machines, the producer's variant names, dynamic scheduling, slow-path side effects, aliases, other callers and actual reload events remain open. This is not proof of an exhaustive caller census, service behavior or a real network transition.

## Reproduce and controls

Four complete indexed FDE hashes cover the two enclosing owners (16,080 and 16,391 bytes), connection caller (2,082 bytes) and inner reload owner (795 bytes). Their combined **35,348 bytes** are authenticated context, not 35,348 reconstructed bytes. The four GNU exports retain only the selected windows and remove trailing whitespace. The verifier decodes each complete FDE with Capstone to check that every selected span begins at an instruction boundary.

```sh
PYTHONPATH=tools python3 research/work-items/RE-012-node115-gossip-reload-callers/verify.py
(cd research/work-items/RE-012-node115-gossip-reload-callers && shasum -a 256 -c MANIFEST.sha256)
```

Python 3.14.5, Capstone 5.0.7 and GNU objdump 2.42 were used. The verifier authenticates the target and four FDE/body hashes, 75 byte spans, 13 direct or RIP-relative targets, five relative relocations and the `node/src/gossip_config.rs:103:32` Location. Four separate branch, lock and call byte mutations are rejected under the local pin checks, below the whole-body hash guards. No instruction is evaluated as target behavior. The inner lock's timeout and error contracts remain credited dependencies; the next question is to identify the producer and lifecycle of the pointed object's `+0x90`, `+0x88` and shared `+0x10` without inventing a type or universal ownership invariant.
