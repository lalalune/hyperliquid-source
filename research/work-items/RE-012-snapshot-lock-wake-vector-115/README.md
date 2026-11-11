# RE-012: map node #115 wake list growth policy and commit

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: qualify the growth policy of the wake list helper. Existing timed-wait and grant-wake packets identify the ninth push and name this callee but leave its internal allocation rules outside their scope.

The input qword at +0xc0 controls a threshold of nine. Below nine the BSR operand is that qword; at nine or above it is the value at +8. For the selected operand x the routine uses an all-ones shift mask derived from BSR(x), special-cases x=0 to mask zero, and rejects all-ones before adding one. Thus x=8 produces 16, whereas x=0 produces one. It also chooses eight or the +0xc0 value as a separate size operand using the same threshold. At the later commit site 0x5bb55e6 it writes a pointer to +0, a saved qword to +8 and the computed capacity to +0xc0. This records selection and commit without assigning Rust type names or claiming allocator ABI closure.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-lock-wake-vector-115/collect.py --out work/node115-snapshot-lock-wake-vector-fresh
python3 -B research/work-items/RE-012-snapshot-lock-wake-vector-115/verify.py --out work/node115-snapshot-lock-wake-vector-check-fresh.json
```
