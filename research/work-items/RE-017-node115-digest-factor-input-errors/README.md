# Node #115: selected digest-factor input failure exits

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the length and parsing failure branches excluded by the selected input path in #6751, without claiming all dispatcher's failures.

`0x538d241` rejects a first descriptor length of 101 or more. At `0x53906a0..0x53906c1` it conditionally calls the pinned deallocation slot for the first owned buffer, writes result tag `0x158` and the rejected length at result `+0x18`, and continues to conditional cleanup of the second buffer. `0x538d2b5` similarly rejects a second length of 101 or more: `0x5393b62..0x5393b83` conditionally releases its buffer, writes tag `0x158` and the rejected length, and joins the return path. The first buffer was already conditionally released after a successful first parse.

When the first parse produces a tag other than `0x1a2`, `0x539261e..0x539268f` copies the returned tag and error payload into the outer result and follows both conditional cleanups. When the second parse fails, `0x5394df5..0x5394e66` propagates that tag and payload and conditionally cleans up the second buffer. The selected branches reach the common result return instead of `0x54cf1b0`; the packet does not assign names or meanings to error payloads.

The failure statements assume valid descriptors, normal cleanup return and the observed branch conditions. They do not establish how parser failures arise, behavior on allocation failure or malformed pointers, or network-facing errors. No target code is executed; no component gate changes.

Run `python3 research/work-items/RE-017-node115-digest-factor-input-errors/verify.py` for target digest, instruction anchors, call and mutation controls. Static windows and deallocation relocation are in `windows.txt`.
