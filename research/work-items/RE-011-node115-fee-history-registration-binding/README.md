# RE-011: bind the node 115 fee-history registration key

Partial progress for [#3922](https://github.com/lalalune/hyperliquid-source/issues/3922).
This packet closes the missing static method-key connection in
`RE-011-evm-fee-history-115`. It does not close the issue or any full-component
mapped, built, behavior, or identity gate.

## Target and question

- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Original node #115 ELF: 105,896,032 bytes; SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates are ELF virtual addresses, not file offsets or runtime addresses.
- Question: does the registration call actually supply `eth_feeHistory` to the
  wrapper and descriptors already associated with the fee-history future?

Previously the fee-history packet left its caller-supplied method key unbound.
The `eth_call` research identifies another edge in the same registration owner;
being in that owner alone does not establish this key. This contribution binds
the specific literal, length, argument registers, wrapper call and callback
relocations instead of inferring a name from a nearby string.

## Observed connection

| Boundary | Original observation |
|---|---|
| Registration owner `0x2a05f60..0x2a06528` | `0x2a0604d` places the address `0x6023fc` in RDX; its 14 bytes are exactly `eth_feeHistory`. `0x2a0605c` supplies ECX=14 and `0x2a06061` calls `0x2d024e0`. |
| Wrapper `0x2d024e0..0x2d025bd` | Preserves incoming RDX/RCX across allocation, restores them, and passes descriptor `0x6450758` to registration helper `0x2f1bce0` through relocation slot `0x64e2198`. |
| Descriptor `0x6450758` | Relative relocations at +0x20 and +0x28 resolve to callback `0x2d032b0`. No function role is inferred from pointer proximity alone. |
| Callback `0x2d032b0..0x2d0335b` | Allocates/copies its 0x90-byte state and returns descriptor `0x6450a48`, whose +0x18 relocation resolves to poll `0x2d0bee0`. |
| Selected poll window | `0x2d0c7cb` materializes descriptor `0x6445590`; `0x2d0c7e4` calls its +0x18 slot, whose relocation at `0x64455a8` resolves to `0x2a1fd20`. |

`records.json` retains four selected windows, **445 bytes / 108 instructions**,
with enclosing FDE bounds, hashes, instruction bytes and text. The denominator
is these selected windows, not the full registration owner or poll function.
The verifier checks 18 explicit facts, including RIP-relative targets, argument
registers, direct calls, literal bytes and relative relocations. No target code
is executed or emulated.

Eight in-memory corruption controls change the key, argument register, key
length, call displacement, two descriptor displacements and two callback/poll
relocations. They must fail the fact checks with global digest/window comparisons
bypassed inside the control run; rejecting a changed whole-file digest alone is
not counted as a semantic control. The original input digest is always checked
before any controls run.

## Reproduce and limits

Use an existing Python environment with Capstone **5.0.7** and the hydrated
repository artifact. The observed run used Python **3.14.7**. The verifier reuses
the repository's `RE-001-node115-registry-row-labels/verify.py` ELF/FDE support;
it adds no dependencies or downloads.

```sh
python3 research/work-items/RE-011-node115-fee-history-registration-binding/verify.py
```

Expected: 4 windows, 445 bytes, 108 instructions, 18 facts and 8 rejected
corruptions. `--target PATH` can point to another copy of the same pinned ELF;
a different digest is rejected. `verification.json` records the observed result.

This proves a static key-to-call-chain connection. It does not establish that
registration succeeds in a live process, prove all parameter decoding or JSON
rendering, or add new evidence for the already-described zero-count response.
Descriptor size/alignment semantics, arbitrary runtime object identity and
full transitive behavior are not claimed. The existing fee-history packet and
[PR #2129](https://github.com/lalalune/hyperliquid-source/pull/2129) retain credit
for the adapter/future evidence. No implementation is copied from inferred
third-party source; the verifier and interpretation are independently authored,
and imported artifact rights remain unchanged.
