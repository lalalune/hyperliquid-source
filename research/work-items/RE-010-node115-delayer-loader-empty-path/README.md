# RE-010: #115 delayer loader's selected empty path

[The open state-projection PR #5050](https://github.com/lalalune/hyperliquid-source/pull/5050) identifies a loader call to `0x3bec320` on the materialized state's `+0x40c0` subobject but leaves its effects open. This packet traces one complete ordinary-return path through that routine and the two helpers actually reached on it. It does not claim that a real restored state takes this path. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses. Target instructions are neither executed nor emulated.

## Preconditions and result

Let `P` be the pointer passed as `rdi` to `0x3bec320`. Assume the object and stack accesses are valid, `P` does not alias the callee's stack, there is no concurrent modification, and the following incoming qwords hold:

- `[P+0]` is not `0x8000000000000000`;
- `[P+0x18]` is zero;
- `[P+0x20]` is zero.

The selected instruction path returns normally with the first 0x20 bytes of `P` unchanged, writes four qwords `(0, 8, 0, 0)` to `P+0x20..+0x40`, and writes zero to `P+0x60`. The raw value 8 is observed; a source-level container or ownership interpretation is not asserted. Depending on the original contents, some of these stores may write the same values already present. These are conditional static consequences, not a test run or a claim that such contents occur in production.

## Why the path is selected

At `0x3bec33a`, negating the first qword overflows only for the sentinel; the non-sentinel premise takes `0x3bec363`. The zero at `P+0x18` selects `0x3bec394`: three indices become zero, the first pointer is read from `P+8`, and the three addresses formed using 0x28-byte scaling are equal. The stack iterator kind is 2. The routine calls `0x4505c60` at `0x3bec3fc`. For kind 2 with both iterator ranges empty, its selected instructions reassign only its stack iterator and return `rax = 0` at `0x4505e69`. No row is dereferenced on this path.

The initializer then checks the original non-sentinel word and calls `0x4550060` with `P`. That helper tests the zero at `P+0x18`, follows `0x45500c6 -> 0x45500d0 -> 0x455039e`, and returns without any object store or nested call on that path. With the word still non-sentinel, the initializer goes to `0x3bec97c` and stages `(0, 8, 0, 0)` on its stack. A second traversal is initialized with equal pointers, kind 2, a zero pending pointer and zero counter. The empty-iterator comparisons at `0x3becb00..0x3becb2a` reach `0x3becbd0`, then the zero pending pointer leads to `0x3becbe4`.

The code saves the original `P`, takes `P+0x20` as the destination, and checks its first qword. The zero premise takes `0x3becc63 -> 0x3beccb6` without a deallocation. Two 16-byte stores copy the staged four qwords to `P+0x20..+0x40`; the zero counter is stored to `P+0x60`, followed by the function return. Under these premises, the only calls in this selected path are the two helpers described above, each followed through its own selected return path.

The selected loader call at `0x3c1294b..0x3c12959` supplies its base plus `0x40c0` to relative slot `0x64e4f10`, whose addend is `0x3bec320`. If its actual argument satisfies the above premises, the stores correspond to materialized base `+0x40e0..+0x4100` and `+0x4120`. This relationship alone does not prove the loader, preceding decoder and later queue extractor use the same runtime object. Open PR #4722 maps the surrounding loader with this helper stubbed; this packet adds the selected helper path and keeps the earlier state-projection packet's identity limitation.

## Evidence and limits

`instructions.tsv` records the complete initializer and two helper FDEs plus the loader call window. `verify.py` authenticates the target digest, four indexed FDE/body hashes, 1,095 instruction spans, 123 explicit byte pins, 19 direct targets and the relative relocation. It rejects 12 changed anchors. It decodes bytes and checks the pinned path; it does not run or interpret captured instructions. Reproduce from the repository root with `PYTHONPATH=tools python research/work-items/RE-010-node115-delayer-loader-empty-path/verify.py` using Capstone.

Sentinel cases, non-empty inputs, aliasing, allocation and failure paths, real object identity and cross-version equivalence remain open. No completion gate is requested.
