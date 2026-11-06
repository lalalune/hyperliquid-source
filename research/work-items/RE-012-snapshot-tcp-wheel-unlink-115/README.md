# RE-012: resolve node #115 TCP wheel slot unlink and bitmap update

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: the indexed helper reached from 0x5ceb06e mutates an intrusive list by unlinking, resolving a prior RE-005 packet's tentative “insert body” label for 0x5ce29a0.

The entry multiplies level at bucket+0x400 by six, rejecting multiplication overflow and a shift count >=64. It selects the 16-byte slot indexed by (node[+0x10] >> shift) & 63. With a nonnull previous link it updates previous+8 to next, and with a nonnull next link it updates next+0 to previous and zeros the node's two link words. With a null previous link, it requires the slot head to equal the node before replacing that head with next. The no-next path tests the slot tail against the node. On reaching the empty-slot path both endpoints are checked and the selected bit is XORed in bucket+0x408. This is a toggle, so interpreting it as clearing requires a previously set bit. These stores establish unlink behavior without asserting the scheduler type or proving the list invariants for malformed inputs.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-wheel-unlink-115/collect.py --out work/node115-snapshot-tcp-wheel-unlink-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-wheel-unlink-115/verify.py --out work/node115-snapshot-tcp-wheel-unlink-check-fresh.json
```
