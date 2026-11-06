# RE-012: map node115 timespec difference sign and carry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The comparison orders seconds as signed and uses unsigned
nanoseconds when seconds match. For the nonnegative arm,
a subsecond borrow adds one billion before subtraction
and subtracts one from the seconds difference. The range
check normalizes a subsecond value at or above one billion
and guards seconds overflow before increment.

For the reverse ordering it recursively swaps operands,
then flips the result marker using the recorded vector
mask. It retains the magnitude words. This packet isolates
the helper arithmetic from its timed-wait callers.

The retained 1 full FDEs cover 198 bytes and 58 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-timespec-signed-difference-115/collect.py --out work/timespec-signed-difference-fresh
python3 -B research/work-items/RE-012-timespec-signed-difference-115/verify.py --out work/timespec-signed-difference-check-fresh.json
```
