# Node #115 tracker demotion iterator: initial descent

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Conditional static analysis of the iterator called by the independently traced 80-byte demotion builder.

At `0x51e32be` the iterator checks remaining count at descriptor +0x40. When nonzero it decrements that count before testing variant tag 1. If the current node at descriptor +0x08 is null, `0x51e33eb..0x51e346e` loads the root from +0x10 and height h from +0x18, follows h child-zero pointers at node +0x380, and stores the resulting node into descriptor +0x08. It sets the node-depth and slot fields at +0x10/+0x18 to zero and changes the tag to 1.

Assuming valid pointers, a consistent height, a nonempty resulting leaf, and h descent steps, `0x51e3484..0x51e34ff` selects leaf slot zero. The output triple at `0x51e3551..0x51e3559` contains that node, zero depth and slot zero; the iterator state stores the same leaf with next slot one. The caller `0x5b8eae6..0x5b8eafe` checks the returned node before reading its selected key/value. Empty count cleanup, malformed trees, later ascent and full ordering are outside this finding.

Run `python3 research/work-items/RE-017-node115-tracker-iterator-first/verify.py` for target digest, byte/direct-call anchors and mutation checks. `windows.txt` gives the disassembly; no target code is executed.
