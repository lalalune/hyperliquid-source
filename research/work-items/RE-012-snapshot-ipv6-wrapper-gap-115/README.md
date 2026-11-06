# RE-012: map node #115 IPv6 compressed gap wrapper

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012: bind the IPv6 compressed-gap wrapper left open by the upstream group-reader packet. A first reader result of eight skips the separator path and goes directly to the SIMD per-word byte swap. For a shorter result, DL bit zero set rejects; otherwise the wrapper needs at least two remaining bytes beginning with a colon. It advances the descriptor by two before checking the second colon, and the failure continuation restores both saved descriptor qwords and writes output tag zero. For a valid double colon the second reader receives capacity 7 minus the first group count. The returned suffix count selects destination word index 8 minus that count and a copy length of twice that count. Success uses the same word-swap path and writes tag one. This is wrapper-level static evidence and does not assert outer full-string acceptance or re-credit the helper.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-ipv6-wrapper-gap-115/collect.py --out work/node115-snapshot-ipv6-wrapper-gap-fresh
python3 -B research/work-items/RE-012-snapshot-ipv6-wrapper-gap-115/verify.py --out work/node115-snapshot-ipv6-wrapper-gap-check-fresh.json
```
