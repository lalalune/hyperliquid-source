# RE-008 - node #115 EMA branch helper

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

This packet records the separate FDE `[0x4d26bd0, 0x4d26fbd)` (1005 bytes; FDE offset `0x12f2414`). It maps the `+0x3d0`/`+0x3e0` record staging, count decrement at `+0x4ae`, boundary guards, and descendant descriptor setup. It is static evidence only.

Run `python3 research/work-items/RE-008-node115-ema-branch-helper/verify.py` from the repository root. No captured binary execution or network access is used.
