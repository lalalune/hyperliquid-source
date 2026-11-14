# RE-008 - node #115 EMA array helper

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

This packet records the separate FDE `[0x4d25fe0, 0x4d26bc6)` (3046 bytes; FDE offset `0x12f23c0`) that follows the `+0x4e0` reader family. It observes the root/count loads, indexed record staging, count decrement, capacity/empty guards, record-field copies, and tail-slot movement. It does not assign source-level types or claim runtime equivalence.

Run `python3 research/work-items/RE-008-node115-ema-array-helper/verify.py` from the repository root. The captured binary is read only; no target execution or network access is used.
