# RE-008: consensus timer records in the constructed output

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Partial static evidence for [consensus issue #3926](https://github.com/lalalune/hyperliquid-source/issues/3926). The [timer conversion packet](../RE-001-node115-consensus-timer-conversion/README.md) identifies two adjacent calls in `0x2e1b6b0` and their stack result slots, leaving their caller-side destination open. [PR #2617](https://github.com/lalalune/hyperliquid-source/pull/2617) independently maps the shared timer constructor. This packet traces the **two result records in their consensus-state caller**, not the already characterized constructor arithmetic.

At `0x2e1c74c` and `0x2e1c762`, RELATIVE slot `0x64e87d8` resolves to `0x4eca5d0`. The output pointers are `rsp+0x368` and `rsp+0x388`; the two f64 constant bit patterns are `0x3fd3333333333333` and `0x3fb9999999999999` respectively. On each normal nonnull allocation route, the conversion body writes seconds at record `+0`, nanoseconds at `+8`, a pointer to its separately allocated `0x70`-byte constructed payload at `+0x10`, and a zero byte at `+0x18`. Bytes not written by these selected stores are not given semantic values.

At `0x2e1cd20..0x2e1cd5f`, the caller copies each complete `0x20`-byte record, in order, to `rsp+0x17a8` and `rsp+0x17c8`. The caller saved its original output pointer at `rsp+0x140` and the selected continuation reloads it into `rbx`. With byte `[rsp+0x50]` nonzero, the branch at `0x2e1cf41` bypasses an alternate helper, and `0x2e1cf68` calls imported `memcpy` for `0xbd8` bytes from stack base `rsp+0xd20` to that output pointer. The two record ranges therefore fall at output offsets **`+0xa88..+0xaa7`** and **`+0xaa8..+0xac7`** respectively. The heap pointers inside the 32-byte records are copied as values; this observation does not establish a deep copy of the two payload allocations.

These facts are conditional on both conversion calls returning normally, reaching the selected assembly/copy path, successful ordinary allocation and copying, valid nonaliasing memory, and no intervening mutation of the records. The bytes at other offsets, alternate branch, cleanup and ownership, timer firing, state-machine roles and runtime reachability remain open. No consensus gate is advanced.

## Reproduce

```sh
PYTHONPATH=tools python3 research/work-items/RE-008-node115-timer-record-handoff/verify.py
```

The static verifier authenticates the target, two complete indexed FDEs and their decoded partitions (1,431 and 150 instructions), 67 selected spans, 31 explicit instruction pins, seven edges, three relocations, two constant bit patterns, the `memcpy` import and six corruption controls. Capstone 5.0.7 is required. These are selected static evidence counts, not component coverage, and no captured code is executed or emulated.
