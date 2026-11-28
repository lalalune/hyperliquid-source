# RE-007 — Selected node #115 borrow/lend refresh diagnostics

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet covers local diagnostic collection and handoff in `0x369a480`.

The zero scale result at call site `0x369aa3b` adds the seven-byte string `mark px`. A zero scale result at `0x369ac84` selects the nine-byte `oracle px` entry through the shared append path. The zero median result at `0x369aef5` adds the 14-byte string `missing median`. These are exact byte spans in one contiguous literal pool. They describe these selected branches, including the zero-median path established in #7411.

The refresh keeps capacity, buffer and length at stack +0x10, +0x18 and +0x20. Entries are 16 bytes with pointer first and length second. At the selected final handoff, the refresh copies those three words to a fresh stack region, passes its address in RCX and sends the asset word from R14 in RDX to `0x3ce2d10`. The median-zero path can reach this handoff without taking the normal price store. The formatter or event internals downstream of the call and the other diagnostic producers are outside scope.

Run `PYTHONPATH=tools python3 research/work-items/RE-007-node115-bole-refresh-diagnostics/verify.py`. It reads the pinned ELF to verify instruction bytes, calls, branch edges and literal spans.
