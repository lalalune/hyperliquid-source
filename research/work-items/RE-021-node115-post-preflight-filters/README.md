# RE-021: selected post-preflight record filters in two EVM drivers

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Partial static evidence for [EVM issue #3918](https://github.com/lalalune/hyperliquid-source/issues/3918). The [caller deduction packet](../RE-021-caller-deduct-115/README.md) ends at driver A `0x29a1fa4` and driver B `0x2963796`, immediately before calls to `0x2668560` and `0x2668a20`. This packet follows their selected caller-side results into a record scan. The separately studied access-list helper bodies are context, not new reconstruction credit.

After those calls, both drivers compare the first returned qword with `0x25`. A different qword takes a separate result arm. For `0x25`, each then tests its local byte (`rsp+0xd01` in A, `rsp+0x11e1` in B) against 4; non-4 branches elsewhere. Only the `0x25` / byte-4 continuation described below reaches the selected scan. A zero count takes a separate empty route; with nonzero count, the respective base and end are formed with `count * 0x90`, and each iteration advances by `0x90` bytes.

For each row on this path:

1. Two 16-byte loads read a 32-byte value at row `+0x08`. All-zero bytes pass to the next test. A nonzero value must equal the caller's selected qword followed by 24 zero bytes; otherwise the scan advances. The qword comes from A's local `rsp+0xd68` or B's `rsp+0x1248`, and its meaning is not inferred here.
2. A qword of all ones at row `+0x28` advances the scan.
3. If row dword `+0` equals 1, byte `+0x48` must be zero; otherwise the scan advances. The passing arm copies 20 bytes from row `+0x49..+0x5c` into a temporary. For other dword values both drivers call through slot `0x64e6cf8` → `0x5be3b50`; a first result byte other than 1 advances the scan.
4. On the selected passing route, A stages the 20-byte temporary for direct helper `0x299f4d0`. B stages it for slot `0x64e6ce8` → `0x5463980`. These are distinct helper boundaries; this packet does not claim that they have identical effects or name the temporary's source-level type.

The 32-byte zero check, all-ones test, tag and byte predicates are observations of the selected blocks, not a statement that every possible record is valid. Preconditions include valid nonaliasing records, normal helper returns, bounded count and a valid loop range. Empty and rejected routes, malformed pointers, complete helper behavior, journal consumption, rollback and concrete runtime reachability remain outside this packet. No EVM gate is advanced.

## Reproduce

```sh
PYTHONPATH=tools python3 research/work-items/RE-021-node115-post-preflight-filters/verify.py
```

The static verifier authenticates both complete indexed FDEs and instruction partitions (3,472 and 3,309 instructions), 159 selected spans, 94 explicit instruction pins, 21 selected edges, two relocations and seven corruption controls. Capstone 5.0.7 is required. The counts are scoped evidence rather than component coverage. No captured instruction is executed or emulated.
