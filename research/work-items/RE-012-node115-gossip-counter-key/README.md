# RE-012: selected node 115 request counter key handoff

This packet continues the over-threshold branch left open in [PR #5076](https://github.com/lalalune/hyperliquid-source/pull/5076). It is bound to Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The findings are selected static data-flow observations, not a security finding, an asserted access policy or proof of live request processing.

## Key handoff

On the selected `0x5a5dbc0` path, the incoming `edx` dword is retained in `r12d` across the call at `0x5a5dc0e`, then restored to `ecx`. On the route reaching `0x5a5dd01`, it is stored at stack `+0x61` and byte `+0x60` is set to zero. At `0x5a5de3c`, the stack region beginning at `+0x60` is passed as the second argument to `0x59db3a0`. Assuming the selected instructions, ABI-preserving helper returns and no interfering aliases, its first byte is zero and its next four bytes contain the original input dword in little-endian storage. The remaining bytes of the 17-byte region are not characterized here.

On the branch where the current qword is greater than the threshold, `0x59db62f` forms a pointer to object `+0x1a0`. It copies 16 bytes plus byte 16 from its saved key pointer into a stack temporary and passes the temporary to `0x4ef8bb0`. The threshold check and counter writes are covered in #5076; this packet studies the later key operation.

## Selected zero-tag key operation

`0x4ef8bb0` calls `0x4e527a0` as a hash boundary. If the key's low tag bit is zero, the selected arm reads the dword at key `+1`. In a candidate slot it first compares the entire stored tag byte to the key's tag byte, then compares the stored dword to that input dword. If both comparisons match, it returns low byte 1. The hash and complete probing algorithm are not reconstructed here.

On the distinct selected empty-slot insertion path at `0x4ef8d77..0x4ef8dc8`, the code updates two control bytes, adjusts table metadata, and copies all 17 input bytes into the selected slot. It then returns low byte 0. These observations apply only when execution reaches the specified slot paths with valid table storage; they do not imply that every miss reaches this insertion path or characterize collision handling and allocation failures.

The caller copies the helper's `eax` to `ecx`, sets `al` to 1, and tests `cl`; a nonzero result returns through the selected branch. A zero result continues to additional state-dependent checks and possibly calls. No conclusion is made here about their side effects or the overall result of all branches. Actual key meaning, policy, user identity, lock behavior and intervening helper effects remain open.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-counter-key/verify.py`. It authenticates the artifact, three FDE bodies, selected instruction bytes and direct targets and rejects instruction mutations. It parses and decodes bytes only; it never executes or emulates the captured node.
