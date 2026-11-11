# RE-005: forward-client-blocks pipeline descriptor handoff

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Partial static evidence for the RE-005 pipeline and serialization work queue. The [block-fill writers packet](../RE-005-node115-block-fill-writers/README.md) ends its b-side trace at function `0x5a82670`, referenced by relocation slot `0x64b91c0`, with its pipeline-record producer outside the trace. This packet connects that slot to one descriptor construction and handoff. It does not establish that a real request executes the slot or identify all producers.

## Constructor and descriptor

In `0x5a81ed0..0x5a820c3`, under normal helper returns and successful allocation, the code copies `0x118` bytes from its first input pointer to stack base `rsp+0x10`. It places the original third argument at stack `+0x128`, the original fifth argument at `+0x130`, the low byte of the second argument at `+0x1b4`, and a zero byte at `+0x1b5`. Relative to the stack record base these are `+0x118`, `+0x120`, `+0x1a4` and `+0x1a5`. The first store precedes the `0x118`-byte copy and lies just beyond its end; the other stores follow it. The allocation at `0x5a81fde` requests `0x2d80` bytes, and `0x5a8200f` copies `0x2d80` bytes from that stack record to the allocated object. This describes the selected writes and copy only; it does not assert initialization or semantics for every remaining byte.

At `0x5a82015`, the code loads descriptor address `0x64b91a8`, passes the allocated object as argument 3 and that descriptor as argument 4, and tail-jumps through slot `0x64e1758`, a RELATIVE relocation to `0x15d6ef0`. The descriptor has a relocation at `+0` to `0x5a5c610`, qword `0x2d80` at `+8`, qword `8` at `+0x10`, and the previously identified relocation at `+0x18` to `0x5a82670`. Both code targets have indexed FDEs. These layout and target facts explain how the earlier slot relates to the allocated record; they do not by themselves prove a runtime dispatch.

The low input byte also selects either a null first argument or pointer `0x93b982` to the 31-byte literal `nv_stream_forward_client_blocks`; argument 2 is set to 31 in both cases. In `0x15d6ef0`, the zero-first-argument arm passes the object and descriptor to `0x15ca9e0`. On the nonzero-first-argument arm, after its recorded global guard resolves, the body passes the same pair as arguments 4 and 5 to `0x15d6730`. This binds the descriptor and data to two immediate continuation calls while leaving their deeper scheduling, aliasing and execution behavior unresolved. No claim is made that the literal names a source-level function or that every call uses a nonnull name.

## Reproduce

```sh
PYTHONPATH=tools python3 research/work-items/RE-005-node115-block-pipeline-descriptor/verify.py
```

Capstone 5.0.7 and the authenticated target are required. The static verifier checks two complete indexed FDEs and their byte partitions, two descriptor target FDEs, 80 selected instruction spans, 41 explicit instruction pins, eight resolved edges, five relocations, the `memcpy` import, descriptor size/alignment words, the literal, and five corruption controls. Original bytes are not executed or emulated. Preconditions include valid input memory, successful allocation, normal returns and ordinary SysV register preservation. The first input's original producer, record field meanings, the complete indirect consumer and runtime reachability remain open. No component gate is advanced.
