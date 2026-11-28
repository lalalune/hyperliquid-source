# RE-007 — Node #115 borrow/lend refresh flat-ring iterator

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [index writer packet](../RE-007-bole-index-writer-115/) leaves the refresh iterator at `0x4506810` as a separate question.

When the iterator state word is 2, the next item comes from two half-open spans. The active cursor and end are at +8/+0x10. If they are equal, the helper exchanges that pair with the second span at +0x18/+0x20. A nonempty active span returns its row pointer in RAX and its payload pointer at row +8 in RDX. Only the active cursor advances by the row stride 0xb8. When both spans are empty, the returned RAX is zero.

At `0x369a678` the refresh caller checks RAX before reading the row key at +0 and forwarding RDX. This establishes how both outputs are consumed and how the end sentinel is recognized. The other iterator variants and the downstream operation receiving the payload are outside scope.

Run `PYTHONPATH=tools python3 research/work-items/RE-007-node115-bole-refresh-ring-iterator/verify.py` at the repository root for static byte and edge checks, plus span-transition cases using synthetic addresses.
