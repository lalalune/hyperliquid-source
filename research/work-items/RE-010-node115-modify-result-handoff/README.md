# RE-010 · Node #115 single modify payload split and result selection

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The decoder arm for `modify` calls `0x56c1dd0` at `0x4d409c5` and selects internal tag `0x92` on the successful path. Execution cell 12 reaches wrapper `0x54f45e0` with the payload pointer advanced past the tag. This packet traces that scalar wrapper's argument split and result branches.

At `0x54f4b98` the wrapper builds a temporary with qwords 0 and 1 followed by the dword from payload offset `+0x38`. It calls the preparation function `0x50f9720` at `0x54f4bc1`. Preparation and the two check calls must each return word `0x1a2` before the selected modification call.

The call at `0x54f4c8c` uses the payload pointer as argument four, payload address `+0x18` as argument five and the zero-extended byte from `+0x50` as argument six. This preserves three independent lanes from the original payload to `0x555f0d0`. The wrapper writes result byte `0x0e` if this helper returns word `0x1a2`. Otherwise it branches to the error-copy path at `0x54f4ea5`. The helper's writes and the wire meaning of the result byte remain unqualified.

Run `python3 research/work-items/RE-010-node115-modify-result-handoff/verify.py` from the repository root. It checks both table cells and the selected prepare, check and result paths. Altering either argument offset or the result branch in memory causes verification to fail.
