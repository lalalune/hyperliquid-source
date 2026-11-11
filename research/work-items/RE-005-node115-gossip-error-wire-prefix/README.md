# RE-005: node 115 selected gossip error wire prefix

This packet resolves the selected count/write helpers left open by [#5094](https://github.com/lalalune/hyperliquid-source/pull/5094) and connects their raw error tags to the display mapping in [#5093](https://github.com/lalalune/hyperliquid-source/pull/5093). It is bound to Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is a selected byte-prefix result, not a full response or network-frame specification.

## Selected tag path

In both the count helper `0x5aaac40` and the write helper `0x5aaa810`, an input qword of 3 selects the same first constant, dword 0. When the following input dword at `+8` equals 1, both next select dword 1 and dispatch on the qword at input `+0x10`. Their respective seven-entry signed-relative tables select dword constants 0 through 6 in tag order. Those raw tags correspond to the selected formatting inputs documented by #5093; no source enum ABI or behavior for other tags is asserted.

The count-side primitive `0x58220e0` increments state `+0x10` by one for each selected dword below 251, provided its overflow branch is not taken. The write-side primitive `0x5821f30`, when its cursor differs from capacity and valid writable storage exists, writes the selected low byte at `buffer+cursor`, advances cursor by one and returns raw tag 8. Since constants 0, 1 and 0..6 are all below 251, the selected successful write path appends exactly the three bytes `00 01 TT`, where TT is the raw tag 0..6. The selected count path adds three to its initial counter for these three constants. These statements assume the same input across the two calls, normal helper returns, sufficient buffer, valid storage and no interfering aliases.

For tags 0, 2, 3 and 4, the selected table arms return success immediately after that third primitive, so on the #5094 path with initial count zero the selected local count is 3 and the selected output consists of those three bytes. Tags 1, 5 and 6 instead pass the input qwords at `+0x18` and `+0x20` to two further count/write helper calls. This packet does not infer the encoding or width of those qwords. It also does not claim live reachability, frame headers, network delivery, target execution or complete behavior for failures, malformed tags and other top-level variants.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-005-node115-gossip-error-wire-prefix/verify.py`. It authenticates the target, five FDE bodies, selected instructions, both seven-entry tables, constants, direct targets and mutation controls. It never executes or emulates the captured node.
