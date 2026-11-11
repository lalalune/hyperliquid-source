# RE-012: recover node #115 TCP listener setup and descriptor ownership

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The address tag selects AF_INET6 for tag one and AF_INET otherwise. Both branches call socket with type 0x80001 and protocol zero and set SOL_SOCKET/SO_REUSEADDR with an integer one. They serialize their address variant into a stack sockaddr, swapping the port bytes and choosing length 28 for IPv6 or 16 for IPv4.

After bind succeeds, listen is called with backlog 128. Only when it succeeds does the function write the descriptor to result +4 and tag zero. Failure from setsockopt, bind or listen first captures errno as (errno << 32)|2, stores error tag one and closes the acquired descriptor. Failure from socket uses the same result layout without a close. These observations describe the local listener setup and descriptor ownership.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-listener-setup-115/collect.py --out work/node115-snapshot-tcp-listener-setup-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-listener-setup-115/verify.py --out work/node115-snapshot-tcp-listener-setup-check-fresh.json
```
