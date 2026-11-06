# RE-012: map node115 posix_spawn file-action setup and destruction

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The spawn path initializes attributes first and file actions
second. A failed attribute initialization bypasses both destroy
calls. Failed action initialization destroys only the attributes.

Once both objects are live, each nonzero descriptor tag adds
a dup2 action for target 0, 1 or 2. A nonnull selected chdir
function may append the working-directory action. An optional
pgroup attribute uses the saved pgroup value. The setflags
call on the selected route combines the pgroup bit and the
stored byte shifted by seven. Nonzero direct return codes
from these calls enter the packed-error route and destroy
file actions before attributes. The packet isolates the
pre-execution action lifetime, distinct from the direct child
dup2 implementation and the pidfd receive subpath.

The retained 1 full FDEs cover 9849 bytes and 2000 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 7 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-spawn-action-lifecycle-115/collect.py --out work/spawn-action-lifecycle-fresh
python3 -B research/work-items/RE-012-spawn-action-lifecycle-115/verify.py --out work/spawn-action-lifecycle-check-fresh.json
```
