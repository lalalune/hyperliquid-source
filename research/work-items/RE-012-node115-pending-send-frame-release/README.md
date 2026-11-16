# Pending send: parent state to the owned frame's release

Target: node/115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, size 105896032. Static ELF/FDE, jump-table and instruction data-flow evidence only; no captured execution or emulation.

## Remaining boundary and prior work

The owned-frame send reconstruction in #7046 connects frame ownership, chunk progress, pending/resume and normal ready/error release. It explicitly leaves pending destruction unclosed. #2261 (`RE-017-abci-greeting-115`) identifies the post-greeting continuation through `0x2ae27c0` and `0x2ae3cc0`, but leaves cleanup effects opaque. #3655 already reconstructs the generic `0x2ac5520` nested drop; #3656 covers its `0x2aaa460` shared-child drop. This packet reuses those helper contracts and establishes the missing parent-state, object-offset and frame-pointer connection. The generic helpers themselves are not new findings.

The downstream consumer is the RE-012 owned asynchronous send implementation: it may use this evidence to justify releasing the current owned frame when destroying either selected pending parent variant. This is a bounded destructor-entry contract. It does not prove when a scheduler invokes destruction, arbitrary cancellation safety, global alias freedom, or exactly-once behavior across all owners.

## Match poll and destructor on the same embedded object

Let `R` be the input object of poll `0x2ae27c0` and its state-dispatched destructor `0x2abfa20`. Let `Q` denote one embedded send wrapper, `F` its inner sender, and `D` the nested-drop argument.

| Parent branch | Poll argument Q | Pending parent state | Destructor dispatch |
| --- | --- | --- | --- |
| first selected send | `R + 0xc8` at `0x2ae2faf`, passed to `0x2ae3cc0` at `0x2ae2fc1` | output byte `0x45` branches at `0x2ae2fd0`; stores `R[0x98] = 4` via `0x2ae31b2` / `0x2ae35bc` | table state 4 → `0x2abfa97`, calls `0x2abfeb0(R + 0xc8)` |
| second selected send | `R + 0xa8` at `0x2ae33b9`, passed at `0x2ae33cb` | output byte `0x45` takes `0x2ae33e7`; stores `R[0x98] = 5` via `0x2ae35bc` | table state 5 → `0x2abfaac`, calls `0x2abfeb0(R + 0xa8)` |

The destructor loads the same `R[0x98]` at `0x2abfa24`. Its six signed 32-bit relative table entries at `0x603d64` resolve to `0x2abfb07`, `0x2abfb22`, `0x2abfb22`, `0x2abfa48`, `0x2abfa97`, `0x2abfaac`. States 4 and 5 therefore select exactly the corresponding embedded object used by the poll; swapping the offsets would select a different object. This does not treat every outer state as a pending send.

## Pending state preserved through the wrapper

In `0x2ae3cc0`, `Q` is saved in RBX. It passes `F = Q + 0x70` to `0x2b7a290` at `0x2ae3ddd`. For the sender's selected pending return `RAX = 1`:

- `0x2ae3dee` writes `Q[0x398] = 3` through RBP, which was set to `Q + 0x398` on both initial and resumed paths.
- `0x2ae3dfe` returns outer result byte `0x45`.
- `0x2ae3e02` / `0x2ae40a7` store `Q[0x3a0] = 3`.

In the sender, the selected pending path stores `F[0x309] = 3` through stack+0x70 at `0x2b7b0b1` / `0x2b7b0b6`. Both initialization (`0x2b7a326` / `0x2b7a32d`) and resume (`0x2b7a451` / `0x2b7a458`) establish that exact pointer. It then takes `0x2b7a6f0`, stores `F[0x310] = 3`, and returns 1. Consequently `Q[0x380]`, which aliases `F[0x310]`, is also 3.

These are saved native state bytes, not source-language enum names or an assertion that every numeric 3 elsewhere means pending.

## Destructor guards reach the current owned frame

`0x2abfeb0(Q)` first requires `Q[0x3a0] == 3`, then `Q[0x398] == 3` and `Q[0x380] == 3`. It calls `0x2ac5520` with `D = Q + 0x98` at `0x2abfeec`. Because `F = Q + 0x70`, the same argument is `D = F + 0x28`.

The generic helper's guard `D[0x2e1] == 3` is exactly `F[0x309] == 3`, the inner state saved before returning pending. On that branch, it first calls the previously documented shared-child drop `0x2aaa460(D + 0xb8)`. On its normal return, for a nonzero current frame capacity, it calls the deallocation helper through slot `0x64df4a0` (relocation to `0x635de30`) with:

| Deallocation argument | Drop view | Sender view | Wrapper view |
| --- | --- | --- | --- |
| pointer | `*(D + 0x60)` | `*(F + 0x88)` | `*(Q + 0xf8)` |
| size/capacity | `*(D + 0x58)` | `*(F + 0x80)` | `*(Q + 0xf0)` |
| third argument | zero at `0x2ac5549` | zero | zero |

`F+0x80/+0x88` are the owned frame capacity/pointer fields populated at `0x2b7a71f` / `0x2b7a726` and used to construct the frame slice at `0x2b7a7b5` / `0x2b7a7bc`. The pointer here is the **current** owned frame pointer, including any preceding successful reserve; it is not the serialized input buffer or an interior chunk pointer. #7046 supplies the construction and write-side borrow chain. This packet proves the offset identity to the pending destructor's release, rather than inferring it from equal field widths.

## Reproduction and limits

```sh
python3 research/work-items/RE-012-node115-pending-send-frame-release/verify.py --target artifacts/node/115/hl-node
```

Use Capstone 5.0.7 and pyelftools 0.32. The verifier binds six complete FDE windows (2508 instructions), 75 instruction witnesses, the deallocation relocation and the six-entry dispatch table to the exact target. Ten negative controls cover the wrong artifact, swapped table dispatch, swapped embedded object, wrong parent pending tag, missing wrapper tag, wrong inner sender, wrong inner pending tag, wrong drop base, wrong released pointer and skipped shared-child drop.

The controls detect divergence from retained static witnesses; they are not target behavioral tests. The proof assumes a valid object at a selected pending boundary, invocation of the identified destructor with that object, and normal return from the already documented nested drop. Initial, completed and unrelated parent states are excluded; the unwind bodies are retained for boundary integrity but not newly reconstructed here. The packet does not claim runtime reachability of cancellation, scheduler installation, socket close behavior, allocator internals, a complete send-task state machine, or full RE-012 completion.
