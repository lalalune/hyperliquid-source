# RE-012: map node115 child pre-exec option ordering and error dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The pre-exec path conditionally applies the group list, then
gid, then uid. When uid is requested and no group list was
supplied, it calls setgroups with zero and null. Only errno
one from that implicit call is discarded before setuid.

The continuation conditionally calls chroot, chdir, setpgid
and setsid, in that order. A global byte gates the signal
call with signal number 13 and handler zero. Failed calls
take the packed errno path and converge on cleanup. The next
callback loop advances by 16-byte entries and stops at a
nonzero result. This packet starts after the mapped child
descriptor remaps and stops before exec.

The retained 1 full FDEs cover 1037 bytes and 274 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 9 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-child-preexec-options-115/collect.py --out work/child-preexec-options-fresh
python3 -B research/work-items/RE-012-child-preexec-options-115/verify.py --out work/child-preexec-options-check-fresh.json
```
