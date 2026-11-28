# RE-017: node #115 replay timer pointer on the tree route

- Component ID: `abci` / `storage`; bounded follow-up to the open timer-delay and alternate-route questions in `RE-009-node115-expected-root-provenance`.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `e1528748a34c6ef79736ba16002caadbdff163a4`; addresses are ELF virtual addresses.
- Question: on the alternate tree traversal, does callback `0x51520f0` receive and dereference the `tracker + 0x88` pointer?
- Claim: **yes, by static pointer identity on the selected tree path.** Runtime reachability, the stored value and full timer eligibility remain unknown.

## Evidence

The drain at `0x5afa030` forms `tracker + 0x88` at `0x5afa06a`, stores it in callback-context word `+0x18` at `0x5afa07f`, and passes the context base to `0x4de0540` at `0x5afa0a0`. In the tree route, `0x4de0540` copies context bytes `+0x00..+0x2f` to its local stack in three 16-byte moves (`0x4de0578`, `0x4de057b`, `0x4de057f`) and copies word `+0x30` separately (`0x4de056c`, `0x4de0570`). Thus the pointer at source-context `+0x18` is retained in the local copy.

The tree descriptor points to that copied context (`lea rdx,[rsp+0x70]` at `0x4de0755`; store at `0x4de075a`), and the tree walk calls `0x51520f0` at `0x4de0786`. The callback loads descriptor word 0 as its context pointer at `0x5152101`, then loads copied context word `+0x18` at `0x5152189` and reads an 8-byte scalar through that pointer with `movsd` at `0x515218d`.

The alternate route is the fallthrough from `jno 0x4de05f7` at `0x4de0562` when the overflow flag is set by `cmp 0,[map]`. This packet states only that flag condition; it does not infer general map validity or runtime use. The route and context copy are statically evidenced and do not establish that the timer event is eligible or fires.

## Reproduction

From the repository root:

```sh
python3 tools/replay_timer_tree_pointer_115.py --self-test
python3 -m unittest tests/test_replay_timer_tree_pointer_115.py
```

The collector authenticates the full target SHA-256, requires exact FDE extents for the drain, map processor and tree callback, fully decodes those extents with Capstone, checks 24 byte anchors and both direct-call targets, and rejects one-byte mutations at all anchors. `records.json` retains structured observations and `instructions.tsv` retains Capstone disassembly for the three complete function extents. Collected on macOS 27.2.1 arm64 with Python 3.14.3 and Capstone 5.0.7. The binary is parsed statically and never executed.

## Limits and next question

This establishes that the alternate tree callback consumes a pointer derived from `tracker + 0x88`; it does not depend on the flat-route finding. It does not establish who initializes or changes that field, its value or units, runtime branch reachability, concurrent mutation, the callback's complete behavior, source equivalence, or any component acceptance gate. The next question is to identify every writer/initializer of `tracker + 0x88` and validate its owning state path.
