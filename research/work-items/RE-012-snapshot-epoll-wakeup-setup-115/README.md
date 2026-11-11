# RE-012: recover node #115 epoll wake descriptor initialization

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This setup helper creates the epoll descriptor with flags 0x80000 and the eventfd with initial value zero and flags 0x80800. It registers the eventfd with epoll_ctl operation one using a packed record with mask 0x80002001 and a zero data qword. Successful registration proceeds to fcntl on the epoll descriptor with command 0x406 and minimum descriptor three.

After duplication it multiplies the requested event count by 12 and tests both unsigned multiplication overflow and the signed high bit before entering the allocation arm. Distinct descriptor acquisition and registration failures load errno before performing their applicable closes. The result's failure sentinel is 0x8000000000000000. This recovers initialization and the event-storage width without assigning the subsequent polling loop's behavior to the constructor.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-epoll-wakeup-setup-115/collect.py --out work/node115-snapshot-epoll-wakeup-setup-fresh
python3 -B research/work-items/RE-012-snapshot-epoll-wakeup-setup-115/verify.py --out work/node115-snapshot-epoll-wakeup-setup-check-fresh.json
```
