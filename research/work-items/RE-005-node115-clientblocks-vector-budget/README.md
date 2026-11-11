# RE-005: #115 ClientBlocks success-vector budget

The [ClientBlocks success grammar packet](../RE-001-node115-client-block-success-grammar/README.md) describes the structural payload with budget-disabled decoding. Open [PR #4335](https://github.com/lalalune/hyperliquid-source/pull/4335) implements that selected structure without caller-specific metering. This packet studies the separate selected vector helper's precharge and per-element charge ordering, not the full nested ClientBlocks budget. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses; target instructions are neither executed nor emulated.

## Selected call and precharge

On the outer response's selected nested-success arm, `0x5aac96c` loads callback `0x5ab7f10` and `0x5aac979` calls `0x5824f20` with the existing state pointer. The earlier grammar packet owns the callback's ClientBlocks structure. This packet authenticates the selected binding; it does not assert runtime reachability or the semantics of every nested field.

The vector helper calls count reader `0x5821250` first. The following statements begin **after that reader returns tag `0x12`**: let `N` be its returned qword, `C` be the then-current qword at state `+0x20`, and `L` the qword at state `+8`. Earlier count-reader consumption and charges are not included in `C`. If the qword at state `+0` is zero, the helper skips its own precharge and per-element refund. If it is nonzero:

1. A nonzero `N >> 60` selects byte tag 2 without storing a new `C`; otherwise it forms `16*N`.
2. Carry from `C + 16*N` selects byte tag 2 without storing that sum.
3. Otherwise it stores the sum at state `+0x20` **before** comparing it with `L`. A sum greater than `L` selects tag 2 with the new value already stored; equality passes this particular check.

For example, with `C=20`, `N=2`, and `L=51`, this local gate stores 52 and then returns tag 2. With `L=52`, that gate passes. These examples are arithmetic consequences of the pinned instructions; they are not executions of the target. With `N=0`, nonzero mode still performs the addition and limit comparison, so an already excessive `C` is not assumed to pass.

## Allocation and callback ordering

On the selected continuation, initial capacity is `min(N, 65536)` records and the requested allocation size is that capacity times 16 bytes. This is an initial allocation cap, **not** an upper bound on `N`: the loop counts down the original `N` and may call a growth helper. For example, `N=65537` requests 1,048,576 bytes initially, subject to successful allocation; it is not rejected merely for exceeding 65536. Zero `N` takes the no-allocation path and returns the raw vector triple `(0, 8, 0)` with tag `0x12` after the prior gates.

Before each callback, when state `+0` is nonzero, the helper checks the current charge is at least 16, subtracts 16, stores it, and then calls the saved element callback with the same state pointer. A smaller current charge reaches a separate panic call. The callback can itself change state; this packet does not claim that the complete nested charge always equals a simple formula. A callback result other than tag `0x12` is copied to the outer error result; the helper then calls the vector cleanup routine and may deallocate its vector. It does not perform a visible local reversal of the immediately preceding 16-byte refund before that error-copy path. Effects of cleanup helpers, indirect callees and aliasing remain outside the claim.

On the selected normal vector result, the helper writes a raw three-qword vector descriptor and tag `0x12`; the response parent checks the tag and, on success, emits its selected raw outer word 3 with that descriptor. These raw layout observations do not identify a complete Rust ABI, final wire representation or whether a particular input is accepted.

## Evidence and limits

`instructions.tsv` records the full vector, callback and count-reader FDEs and a selected parent window. `verify.py` authenticates the target digest, four indexed FDE boundaries and hashes, 268 instruction spans, 62 byte pins, 12 targets and three relative relocations. Six arithmetic cases exercise the stated overflow/limit/allocation calculations and nine modified anchors are rejected. These are static evidence controls, not captured-instruction execution or an independent native oracle. Reproduce from the repository root with `PYTHONPATH=tools python research/work-items/RE-005-node115-clientblocks-vector-budget/verify.py` using Capstone.

Child field accounting, full malformed-input cursor and error behavior, all allocations and cleanup, dynamic execution, other response arms, network framing and cross-version compatibility remain open. No component-completion gate is requested.
