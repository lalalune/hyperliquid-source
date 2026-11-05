# RE-001 · Node #115 startup CPU dispatch word

Component: foundation utilities, startup and native dispatch. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Repository baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

The [initializer census](../RE-001-node115-init-array-census/README.md) supplies the slot map. This packet follows slot two to the dispatch word it writes and the instruction pattern that consumes the two bits.

## Evidence

- Slot 2 has a relative relocation to `0x5d20090`. The initializer executes CPUID with EAX and ECX zero. It clears ECX after that call, then uses a signed `jle` after comparing the returned EAX to 6. The low-leaf path stores zero.
- On the other path, it executes leaf 7, subleaf 0. The shifts and masks map returned EBX bit 19 to output bit 0, and EBX bit 29 to output bit 1. The initializer stores the result as a 32-bit word at `0x65000d0` in `.bss`.
- A byte search across `.text` resolves **19** RIP-relative `test` sites with immediate mask 1 and **2** with mask 2 to that word. Each candidate decodes as `test` followed by `jne`. The two mask-2 sites share taken target `0x5d21248`. The [transcript](evidence.txt) lists all 21 sites and their taken targets.

The consumer scan covers the exact `F7 05 disp32 imm32` encoding with the two single-bit immediates. It does not cover different access encodings, establish complete function boundaries or trace the taken branches beyond their first destination. This word is distinct from the [refresh helper's larger feature composition](../RE-002-node115-cpuid-field-map/README.md). No reconstruction gate change is claimed.

## Reproduction

From the repository root after materializing the pinned artifact, with Python 3.11+, Capstone 5.0.9 and pyelftools 0.33:

```sh
python3 -B research/work-items/RE-001-node115-cpuid-dispatch-word/inspect_dispatch.py
```

The script checks the binary digest before parsing it. The positive control detects a known mask-2 test. The negative control flips one displacement byte and requires rejection. No captured code or CPUID instruction is executed by the script.
