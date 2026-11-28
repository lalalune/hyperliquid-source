# RE-008: selected verify_peer socket-error propagation

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses below are unre-based ELF virtual addresses. [#5966](https://github.com/lalalune/hyperliquid-source/pull/5966) identifies the outer `verify_peer` result tag but leaves the inner `0x2b782e0` result-2 provenance open. [#2990](https://github.com/lalalune/hyperliquid-source/pull/2990) establishes the independent readiness/`SO_ERROR` completion routine. This packet connects those two observed boundaries on one selected inner-error route; it does not re-claim the system-call semantics.

## Observations

The outer routine `0x2ae0920` calls `0x2b782e0` and reads the output qword. The latter calls the previously studied `0x2b13800` completion routine. On the selected nonpending readiness path, the completion routine calls the relocation-backed `getsockopt` slot with level 1, option 4, a zero-initialized value and length 4. If that call returns -1, the selected value is read from the `__errno_location` slot; if it returns normally with nonzero option value, that value is used. In either case the selected error is shifted into the high dword and ORed with 2, cleanup is called, a non-`-1` descriptor is passed to `close`, and output tag 2 is written. The meaning of these imported functions is inherited from their dynamic symbol bindings, not measured runtime behavior.

The caller sees tag 2, retains its payload, and takes the branch at `0x2b78698`. When the prior raw word at its object `+0xc8` is 2, the selected continuation prepares result 2, passes the retained payload through `0x2a026d0`, and publishes output tag 2. The outer routine then invokes the selected error object method and selects its intermediate byte `0x34`. This links an `SO_ERROR`/syscall-failure completion to the outer error branch under the explicitly selected raw state. A separate pending completion tag 3 publishes 3 and is handled differently by the outer wait path. No claim is made about what happens for other values of `+0xc8`, the full retry behavior, all producers of tag 2, error object contents, real peer reachability or network activity.

Assumptions: valid initialized objects and output storage, ABI-conforming calls and selected helpers that return normally, stable state between pinned reads, and no mutation of the selected tag/error by callbacks. Static disassembly and digest-bound controls do not run, interpret or emulate target instructions. This packet is preparatory evidence and does not implement a network client or advance a component gate.

## Reproduce

From the repository root, with Python 3 and Capstone available:

```sh
PYTHONPATH=tools python3 -B research/work-items/RE-008-node115-verify-peer-connect-error/verify.py
```

The verifier authenticates the target, three complete FDE bodies and selected instructions, direct targets and RIP-relative slot addresses, then checks mutation controls. The retained log separately records the `readelf -rW` symbol bindings. Raw output is retained in `offline-log.txt`; whole-function extent is evidence scope, not coverage.
