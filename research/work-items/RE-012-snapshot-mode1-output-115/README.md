# RE-012 snapshot mode-1 output worker

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Addresses are original ELF virtual addresses.

The existing snapshot-selection packet resolves which workers call the mode-1 output path. This packet follows one of those callees into its path routing and byte framing.

- At 0x26a5f9d the worker compares the input length with 9 and checks all nine bytes against the immediate encoding of `/dev/null`. Equality branches to the common exit with EAX zero, before the path and buffer helpers. For other inputs the first-byte slash check is guarded by a nonzero length.
- At 0x26a6001 the path helper is called through 0x64e0938. The relocation resolves it to 0x5cab560. Only result tag 9 proceeds to the dot scan. A component equal to `..` bypasses the scan, and a dot at byte zero cannot reach the suffix comparator. The comparator gets three reference bytes, `rmp`, and the span after the last dot. A nonzero comparator status routes to 0x2299b30 with a local three-word record initialized to [0, 1, 0]. The returned first word is compared with 0x8000000000000004.
- The fallback requests 128 bytes through the relocation at 0x64df480. It writes `[`, a line feed and two spaces, then appends the pointer/length returned by 0x26d4420. A zero length skips the copy and insufficient capacity branches to growth. It then adds a comma, line feed and two spaces before building the descriptor passed to 0x2529970. One descriptor arm scales three indices by 96, while the other arm is selected by NEG overflow on 0x8000000000000000.
- The retained FDE spans 0x26a5f70 through 0x26a6648 exclusive, 1,752 bytes and 407 instructions. GNU, LLVM and Capstone agree on instruction boundaries, and GNU readelf confirms the unwind extent. Six window mutations, two relocation mutations, one import mutation and two identity controls were rejected.

This records the observed branch and framing behavior. The complete serializer schema, callback effects and runtime filesystem behavior remain open. The target was examined statically. Collector scaffolding is adapted from the MIT Build ID packet via the listener frame packet.

Run with authenticated inputs and the versions in tools.json from the repository root. Use fresh output paths.

```sh
python3 -B research/work-items/RE-012-snapshot-mode1-output-115/collect.py --out work/snapshot-mode1-output-fresh
python3 -B research/work-items/RE-012-snapshot-mode1-output-115/verify.py --out work/snapshot-mode1-output-check-fresh.json
```
