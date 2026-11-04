# RE-012: node115 retry poll states, attempt progression and retained-result ownership

- Component: transport / `net_utils/src/async_sleep_retry.rs`; bounded static retry-state mapping.
- Target: Linux x86-64 node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no inferred reference implementation consulted.
- Question: how do attempt progression, retained diagnostic data and suspended/resumed poll states fit together in this concrete retry body?
- Result: a target-bound local state/ownership map and one concrete caller binding. This is not a timer-only result, a reconstructed future, or a complete network retry contract.

## Scope, bounds and source bindings

The complete FDE `0x2a64130..0x2a64bd7` contains **2,727 bytes / 544 instructions**. The separate caller context `0x2aebde4..0x2aebe10` contains **44 bytes / 8 instructions** and is explicitly an **interior context, not a function**. Its actual owner FDE is retained in `records.json`; the complete owner is decoded to validate context/call instruction boundaries, but is not exported or counted as analyzed. Total native export denominator: **2,771 bytes / 552 instructions**. Five jump tables contain **84 additional data bytes**, not code-equivalence credit.

`native.asm` and `caller-context.asm` preserve GNU exports. The record retains full native body bytes/hash, unique file mappings, FDE/CIE, call/branch leads, raw dispatch tables, indirect slots, helper FDE leads, and exact source Location relocations. The three actual `R_X86_64_RELATIVE` Locations are `0x644aed0` (30:44), `0x644aee8` (32:38), and `0x644af00` (41:62), all resolving the full `net_utils/src/async_sleep_retry.rs` path. Source paths establish bounded association, not original public function/type names.

The native incoming convention uses output pointer RDI, state pointer RSI (retained in RBX), and a third context word RDX. Valid native objects, native discriminants, helper ABI preservation and normal helper returns are preconditions. Invalid arbitrary bytes are not a supported public input API.

## Outer poll state and caller

The byte at state **`+0x195`** selects an unchecked signed-relative jump table at `0x603058`. The four measured slots resolve to:

| Raw state | Target | Local role |
| --- | --- | --- |
| 0 | `0x2a64168` | initialize the retry state |
| 1 | `0x2a644b7` | diagnostic-helper path for a completed state |
| 2 | `0x2a644aa` | diagnostic-helper path for a poisoned/unwound state |
| 3 | `0x2a641e7` | dispatch the retained nested state and resume |

These labels describe the observed writes and destinations, not global Rust enum values. Nested dispatches use bytes `+0x188`, `+0xca`, `+0x158`, `+0x150` and tables at `0x603068`, `0x603078`, `0x60308c`, `0x60309c`. Every retained table entry resolves to an actual decoded instruction in the complete FDE. No bounds check for arbitrary invalid state values is inferred.

The bound caller at `0x2aebde4` passes its own object **`+0xae8`** as this state pointer and stack **`+0x350`** as output. After `call 0x2a64130` at `0x2aebdfb`, it tests the output's first dword against **2**, branching to `0x2aeca04` on equality. Independently, this callee's suspension exit writes output word 2, stores outer state 3, and returns. That establishes a concrete caller/result convention for this instance; it does not prove every caller or a stable ABI.

## Attempt progression and result distinction

Initialization saves an operation/configuration descriptor, writes **`UINT64_MAX`** to state `+0x60`, sets index `+0x50` to zero, and derives the attempt bound at `+0x58`. In this observed initialized instance the bound is **`UINT64_MAX`**, not a small configurable number. The general local derivation uses `cmp rax,1; adc rax,0`, so zero would become one; this packet does not invent a caller that supplies such a value.

Before each new attempt, `0x2a64719` compares the index `+0x50` with bound `+0x58` as **unsigned**. At or above the bound it takes the exhaustion path. Otherwise it stores index+1 to `+0x50` and saves the old, zero-based index at `+0x90`. The bound check ensures that this increment cannot wrap for admitted local iterations. There is no observed exponential-backoff calculation or randomized retry count here.

The code then copies **32 bytes** from the descriptor reached through state `+0x68` into the attempt state at `+0xd0..+0xf0`, with additional staged copies to `+0xf0`, `+0x110`, `+0x130`. It replaces a two-byte attempt discriminant with **4** before dispatching the previous value. Reencountering the old value 4 takes a diagnostic-helper path rather than consuming the same representation again. The original descriptor's type, variant names and inner operation implementation are not recovered.

The operation/conversion paths converge on a result discriminant in RBP. At `0x2a64886`, **RBP != 2** takes the terminal-result arm; **RBP == 2** retains a formatted diagnostic and reaches the wait/poll stage. This is the precise local branch relation. Calling 2 a global error variant or assigning concrete I/O error classes would require closing the imported conversion/helper bodies. The exhaustion path builds a diagnostic from the retained prior value and attempt-count field, sets RBP to 2, and reaches the line-32:38 diagnostic-helper arm at `0x2a64ae1`. If that helper returns, the local path reaches UD2. Exhaustion is therefore not described as a normally returned error result.

## Retained diagnostic ownership and suspension

The three-word retained representation starts at **`+0x78`**. On the retry arm, before replacing it, the code skips deallocation if the first word is the min-i64 sentinel **`0x8000000000000000`** or zero. Otherwise it calls relocated slot `0x64df4a0` with pointer **`+0x80`** and that first word as the size argument. It marks byte **`+0xc9`** as 1 and installs the new three-word representation. This is a concrete conditional release/replace sequence, not proof of allocator internals, original Vec/String type or a complete ownership model.

The wait-state prefix at **`+0xf0`** receives a binary64 value from descriptor-relative **`+0x20`**. The observed initializer supplies bits **`0x4000000000000000`** (binary64 2.0). The local body does not establish whether the unit is seconds or which clock/scheduler is used. It calls **`0x2a90a50`** with that state and the retained third context argument. That helper is not measured here:

- Nonzero AL reaches the suspension exit: nested tags are updated, output word 2 is written, outer state `+0x195` becomes **3**, and the function returns.
- Zero AL continues through cleanup of the completed attempt representation, including a virtual call through the descriptor at state **`+0xd0`**, then rechecks the attempt bound and starts the next attempt.
- A terminal operation result bypasses this retry/wait path, releases the retained diagnostic under the same sentinel/zero guards, cleans the nested retry state with `0x2ab0370`, copies the result to output, and stores outer state **1**.
- The unwind paths retain distinct cleanup tags and store outer state **2** before `_Unwind_Resume`. Exact helper failure, cancellation/drop closure and exceptional side effects remain unresolved.

This distinction prevents a reconstruction from recreating an operation on every suspended poll, dropping the retained diagnostic twice, incrementing an index on each poll rather than each new attempt, or confusing output tag 2 with a terminal operation result. No operational network/scheduler equivalence is asserted.

## Reproduce and controls

From repository root with Python **3.12.3**, Capstone **5.0.7**, GNU objdump **2.42**:

```sh
python3 tools/node115_retry_state.py --write
python3 tools/node115_retry_state.py
python3 -m unittest discover -s tests -p test_node115_retry_state.py -v
```

Only `--write` regenerates retained static records/exports; the default checks exact replay. **12 focused tests pass**, including the actual caller and source bindings, all 21 dispatch-table entries, wrong artifact, truncated body, and eight instruction-level counterfactual controls. Controls change unsigned limit comparison, attempt increment, ready/suspended outer-state writes, wait-result branch, retry-result discriminator branch, empty-retained-result release guard and the second half of the descriptor copy. These reject after decoded-instruction checking, not just by the full target hash.

The captured executable is only read. No original execution, instruction emulator, socket, live network, signing, private key or chain operation occurs. No Rust source or compiled comparison has been produced; raw-equal, normalized-only and unmatched comparison counts remain **unmeasured**. Raw export counts are not reconstruction coverage. Every component gate remains false; shared catalogues are untouched.

Next: close the operation-conversion and wait helpers, then validate cancellation and drop behavior against the concrete caller. The current packet constrains retry/control-flow and retained-data ownership without substituting a generic timer implementation for that work.

Native text exports trim trailing whitespace only; instruction bytes, operands and addresses are unchanged.
