# RE-010: #115 generic variant helper error results

[The variant-payload dispatch packet](../RE-010-variant-payload-dispatch-115/README.md) leaves the bodies and meaning of three E114A generic helpers open. This packet traces their shared message construction, distinct result tags and three selected dispatcher arms. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses. Target instructions are not executed or emulated.

## Fixed construction

Each helper (`0x18bf680`, `0x18bfe80`, `0x18bf480`) builds a stack descriptor containing byte `0x0d`, the addresses `0x641f9a0` and `0x641ce90`, the value loaded through slot `0x64dfed0`, and formatter callback address `0x2d49fb0`. The first descriptor's relative relocation points to the 15 bytes `newtype variant`. Each passes `out+8`, the same piece at `0x44f07a`, and its descriptor to `0x18be120`. The 30 piece bytes contain the literal fragments `invalid type: ` and `, expected `, with intervening format control bytes. These observations do not independently establish a final rendered string or payload type name.

The helpers overwrite the incoming `rsi` with that fixed piece address before calling `0x18be120`; they do not load a caller-supplied payload through that register. With valid storage, the SysV x86-64 stack convention and normal formatter return, the descriptor pointer supplied in `rdx` is even. The shared constructor therefore takes its even-pointer arm through slot `0x64df6e8` (relative addend `0x141e3a0`). On normal return it writes byte 6 at constructor output `+0`, and copies the resulting three qwords to `+8`, `+0x10`, `+0x18`. Because that output is each wrapper's `out+8`, these land at wrapper offsets `+8`, `+0x10`, `+0x18`, `+0x20`.

After the common call, `0x18bf680` stores qword 1 at wrapper `out+0`; the other two helpers instead store `0x8000000000000000`. The code supports a fixed generic type-mismatch construction, rather than identifying the three payloads from their incoming content. Formatter internals, allocation failures and final rendered text remain outside this claim. [Earlier #2465](https://github.com/lalalune/hyperliquid-source/pull/2465) studied the same message piece and common constructor in different wrappers; it did not cover these three E114A arms.

## Selected dispatcher consequences

| Selected interior arm | Helper | Normal-return route |
|---|---|---|
| `0x2870d18` | `0x18bf680` | It compares the low byte of tag 1 against zero and selects dispatcher qword tag `0x86` at `0x28715ae`. |
| `0x2870fd1` | `0x18bfe80` | Comparing zero to the signed-minimum sentinel sets overflow; `jo` reaches the shared error-copy block `0x28711c4`, then tag `0x86`. |
| `0x28711a6` | `0x18bf480` | The corresponding `jno` is not taken for that sentinel; execution falls through to the same error-copy block and tag `0x86`. |

The error-copy block copies the 32 bytes at wrapper `+8..+0x28` into dispatcher output `+8..+0x28`. These are conditional consequences when the helper returns normally; they do not establish that any arm is dynamically reached, give the original enum's source-level error type, or cover other E114A arms. The earlier dispatch packet owns the broad switch/arm map and identified these helper calls; this packet adds the helper bodies and the selected branch outcomes.

## Evidence and limits

`instructions.tsv` records all three helper bodies, the common constructor and the selected dispatcher windows. `verify.py` checks the target SHA-256, five indexed FDE bounds and hashes, 168 instruction spans, 64 pins, 20 direct/RIP targets, three relative relocations and two static literals; nine corruption controls are rejected. Reproduce from the repository root with `PYTHONPATH=tools python research/work-items/RE-010-node115-variant-generic-errors/verify.py`, using Python with Capstone. The outcome reasoning is a static reading of those pinned instructions, not captured-instruction interpretation. No component completion is requested.
