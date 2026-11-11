# RE-012: recover node #115 pidfd identity probe and fallback

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The descriptor identity probe issues ioctl request 0xc040ff0b with leading request qword one. Success copies the dword at request +0x10 to output +4 and sets output tag zero. Failure captures errno and packs it as (errno << 32)|2. Only errno 22 or 25 permits the alternate path, and only when the imported pidfd_getpid entry is present.

The alternate call receives the original descriptor. It returns the PID at +4 on success or the alternate errno at +8 with tag one on failure. If the fallback is unavailable or not selected, the result preserves the initial ioctl errno. This maps descriptor-to-PID selection, distinct from the waitid helper which uses the same ioctl number with a different request bit and output field.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-pidfd-identity-probe-115/collect.py --out work/node115-snapshot-pidfd-identity-probe-fresh
python3 -B research/work-items/RE-012-snapshot-pidfd-identity-probe-115/verify.py --out work/node115-snapshot-pidfd-identity-probe-check-fresh.json
```
