# RE-001: resolve node115 startup line-count helper and result tags

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The startup height composition packet identifies an opaque count helper at 0x1500e50. In node115 that entry uses the exact four-byte .lz4 suffix and a nonzero state word to take an extra callback path, then rejoins ordinary command assembly. Both paths reach adjacent two-byte rodata slices wc and -l, followed by the supplied path slice. The command handoff is followed by distinct sentinel checks before the returned text is scanned.

A selected token is parsed as unsigned decimal. The optional plus is consumed, lone signs fail, and at 17 digits the parser switches to multiplication and addition with overflow checks. Success returns tag zero and the count in rdx; failure returns tag one and an error word. The caller can therefore distinguish process/text failure from a valid zero count. The packet does not claim that the launch helper was executed or that every platform would emit the same output.

The retained 1 full FDEs cover 1083 bytes and 276 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 7 instruction/data windows, 4 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-line-count-115/collect.py --out work/startup-line-count-fresh
python3 -B research/work-items/RE-001-startup-line-count-115/verify.py --out work/startup-line-count-check-fresh.json
```
