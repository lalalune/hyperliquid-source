# RE-017: recover the replay timer delay word through materialization

The replay callback evidence in #7205 and #7206 reaches tracker `+0x88` but stops at the read. The expected-root provenance packet identifies tracker base `state+0x3e50`. This packet joins the consumer offset to the corresponding word in the restored state and to a later state copy.

| Selected path | Observed bytes |
| --- | --- |
| Checkpoint materializer `0x3c2e860` | At `0x3c2efd3..0x3c2efe9`, `memcpy` copies 0xb8 bytes from the historical input at `+0x2330` to the new state at `+0x3e50`. The timer word comes from historical input `+0x23b8`. |
| State copy `0x55ea030` | At `0x55f1a39`, a scalar load reads source state `+0x3ed8`. At `0x55f1b1a` it stores to stack `+0x648`. At `0x55f26ed..0x55f2703`, `memcpy` copies 0xb8 bytes starting at stack `+0x5c0` to destination state `+0x3e50`, placing the word at destination `+0x3ed8`. |
| Replay finalizer `0x54897e0` | At `0x548bf2d` it passes `state+0x3e50` to `0x5afa030`, which forms `tracker+0x88` at `0x5afa06a` and writes the pointer to callback context `+0x18`. |

The historical materializer's broad layout and call sequence were recovered by `RE-016-state-materialize-3c2e860-115`. The new result identifies the exact source word consumed by the timer, and demonstrates a later state copy preserving it by a different route. Both source-to-destination paths preserve the eight bytes on the selected normal path. Neither path establishes the original initializer, the accepted value range or the serialized field's source name.

Run `python3 -B research/work-items/RE-017-node115-replay-delay-word-materialization/verify.py` from the repository root. It checks the #115 digest, FDEs, import, call and register anchors, and recomputes the three offsets. The raw offline log records evidence and corruption control results. No captured instruction is executed.
