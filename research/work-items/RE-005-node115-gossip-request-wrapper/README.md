# RE-005: node 115 GossipRpcRequest wrapper state and selected return

This static slice links the request decoder identified in `RE-005-node115-gossip-rpc-request` to a selected caller chain. It does not identify the network framing or a service handler. The artifact is `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; addresses are virtual addresses in this exact ELF. `instructions.tsv` and `verify.py` bind the selected observations to the three FDEs and the artifact.

## Selected path

At `0x5860970`, entry `rsi`, `rdx`, and `rcx` are saved as a pointer P, length R0, and limit L. The low selector from `r8d` is carried to the call at `0x58609bc`. At `0x4e4a1e0`, the `edx == 0` branch reaches `0x4e4a284`; there it reads the three staged values and builds the five-qword state passed to `0x5aac6a0` at `0x4e4a2bd`:

| State offset | Initial value |
| --- | --- |
| +0x00 | 1 |
| +0x08 | L |
| +0x10 | P |
| +0x18 | R0 |
| +0x20 | 0 |

This is conditional on valid, non-aliasing storage and ABI-compliant calls. The earlier request packet identifies the decoder and describes its request variants; this packet establishes this particular caller's state initialization and return handling, not the behavior of other callers.

If the decoder's result tag is `0x12`, `0x4e4a2cc` subtracts the resulting state remaining length R1 from R0. The unsigned-borrow branch goes to `0x4e4a6de`; on the non-borrow path the difference is stored at the inner output's `+0x28`, and `1` at `+0x20`. Thus the local count equals R0 - R1 only on this selected successful, non-borrow path. The decoder error branch and the nonzero selector are outside this conclusion.

The caller at `0x58609c1` snapshots the inner output's first 32 bytes with two 16-byte loads. On its selector-low-byte-zero path it later copies that 32-byte snapshot to its output. Those explicit moves do not copy the inner `+0x20` or `+0x28` fields. Instrumentation calls occur between these moves; this observation alone does not establish their effects, external ownership, EOF enforcement, or a framing rule.

## Reproduction and limits

From the repository root, run `PYTHONPATH=tools python research/work-items/RE-005-node115-gossip-request-wrapper/verify.py`. The check reads the ELF and decodes bytes only; it does not run or emulate the target. It checks FDE extents, complete body digests and decoding, selected instruction bytes and direct targets, arithmetic examples, and mutation controls. It does not prove reachability from a live node or behavior of unexamined calls.
