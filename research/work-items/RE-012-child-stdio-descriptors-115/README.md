# RE-012: map node115 child stdio descriptor setup

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This packet resolves descriptor setup for the child-process family
at 0x5c87f70. The four signed-relative dispatch entries at
0x947ebc go to 0x5c87f92, 0x5c88021, 0x5c87fd0 and 0x5c87fa5
respectively. Three direct calls within the process-creation
FDE are pinned at 0x5c85a19, 0x5c85a6b and 0x5c85b0f.

Arm 0 stores a zero qword and -1 at +12. Arm 3 compares its fd
unsigned against 3. The low-fd branch invokes fcntl with command
0x406 and minimum fd 3. The other branch forwards the original fd,
writes -1 at +12, and stores 0x100000000 in the leading qword.
A successful duplicate uses the owned single-descriptor branch.

Arm 2 calls pipe2 with flags 0x80000. It checks each returned fd
for -1 and uses the input direction byte to select the order of
the pair stored at +8 and +12. Arm 1 supplies the embedded device
path to the actual open-options helper 0x5c97060. Its option bytes
come from the direction byte and its XOR with 1. A successful
device open or duplication stores a single fd at +8 with -1 at
+12. Both the owned pair and the owned single use 0x200000000 in
the leading qword.

A -1 import result reads errno and packs the error as
(u64(u32(errno)) << 32) | 2. The open helper error passes its own
error word through the same result arm. That arm stores dword 1
at +0 and the error at +8. The retained exceptional handler
passes its saved fd to close before unwind resume. This is a
static descriptor contract through bound calls and result stores.
Qualification reads the capture as bytes.

The retained 1 full FDEs cover 404 bytes and 96 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 17 instruction/data windows, 0 RELATIVE addends, 4 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-child-stdio-descriptors-115/collect.py --out work/child-stdio-descriptors-fresh
python3 -B research/work-items/RE-012-child-stdio-descriptors-115/verify.py --out work/child-stdio-descriptors-check-fresh.json
```
