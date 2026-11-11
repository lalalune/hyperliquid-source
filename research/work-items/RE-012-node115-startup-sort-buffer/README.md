# RE-012: startup path sorting scratch allocation

- Component: `node-runtime`; requested bounded area: [issue #3927](https://github.com/lalalune/hyperliquid-source/issues/3927), startup/checkpoint selection and failure exits.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Question: when the two startup path-admission collectors select their count-at-least-21 routine, how much scratch storage does it request and where are allocation-failure and cleanup boundaries?
- Method: authenticated static ELF, not target execution or instruction emulation. All addresses are linked ELF virtual addresses before load bias.

## Context and result

The [entry/checkpoint packet](../RE-017-entry-checkpoint-115/README.md) and [startup admission packet](../RE-012-node115-startup-directory-admission/README.md) already establish the directory and non-directory collectors, 24-byte records and the count-21 handoff. The [replica discovery packet](../RE-017-node115-replica-discovery-order/README.md) explicitly excludes ordering for 21 or more entries. This packet does **not** assert that ordering. It resolves the scratch-storage and error-call boundary after that existing handoff.

Each collector, `0x15b58c0` and `0x15b59e0`, branches unsigned at count 21 and passes the base and count via `rdi` and `rsi` to relocation slot `0x64e0e58 -> 0x152d390`. For `n >= 21`, that routine computes, in unsigned 64-bit arithmetic:

```text
half = n - floor(n / 2)
capacity = max(min(n, 333333), half)
```

When capacity is at most **170**, it passes a pointer to its own stack scratch and capacity 170 to `0x14f3640`. When capacity is at least **171**, it requests `capacity * 24` bytes via `0x64df480 -> 0x6355830`, passes the returned pointer and capacity to the same callee, and on normal return releases the pointer and `capacity * 24` through `0x64df4a0 -> 0x635de30`. Thus the first count in these collectors that enters the heap route is 171: the selected sizes are 4,080 bytes for 170 stack slots and 4,104 bytes for 171 requested heap slots. A count below 65 passes flag 1 in `r8b` to the inner callee; counts 65 and above pass flag 0.

The heap path checks `half <= 0x0555555555555555` before the allocation call; exceeding it invokes `0x64df498 -> 0x141e264`. A null allocation return also reaches that error slot. The recorded normal-return free does not establish every exception action or cleanup outcome. The target's actual allocator behavior is not run or inferred. The captured instruction bytes and the raw disassembly contain the overflow, null and unwind paths.

These are conditional pointer, arithmetic and call-boundary observations, not proof that every count can arise from the filesystem, that the heap allocator succeeds, that the inner helper sorts correctly, or that a checkpoint exists. The maximum-five selection remains the earlier packet's result. Ordering for 21+ rows, inner helper closure, live side effects and whole-startup acceptance remain open. No progress gate or implementation-equivalence claim is made. Next: establish the ordering of the 21+ path through the inner helper and merge dependencies, before relying on it for checkpoint selection.

## Evidence and reproducibility

Three indexed FDEs are retained in full: directory collector `[0x15b58c0,0x15b59d2)` (274 bytes), non-directory collector `[0x15b59e0,0x15b5af2)` (274 bytes), and scratch wrapper `[0x152d390,0x152d4af)` (287 bytes). The two collector bodies are prior context; only the scratch wrapper's capacity, storage and failure boundary are the new claim. This 835-byte extent is evidence size, not source reconstruction coverage. `*.objdump.txt` retains bounded GNU disassembly with trailing whitespace removed.

From the repository root with Python 3.14.5, GNU binutils 2.42 and the project tools on `PYTHONPATH`:

```sh
PYTHONPATH=tools python3 research/work-items/RE-012-node115-startup-sort-buffer/verify.py
(cd research/work-items/RE-012-node115-startup-sort-buffer && shasum -a 256 -c MANIFEST.sha256)
```

The verifier authenticates the full input, indexes all three FDEs, checks their hashes, pins 39 instruction spans, resolves both caller slots and the inner direct call, and checks four relative relocations. It checks nine arithmetic cases including 170/171, 333333/333334 and 666666/666667, and independently rejects mutations to the collector threshold and storage threshold after bypassing the whole-body checks. These controls test the static evidence and the written arithmetic model; they are not an execution or differential oracle for the target. The `memcmp` comparator and inner ordering algorithm are outside this packet. Source code and dependency revisions beyond the base are not attributed.
