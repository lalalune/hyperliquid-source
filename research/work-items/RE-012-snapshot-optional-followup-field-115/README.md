# RE-012: map node #115 snapshot optional follow-up value path

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The dbOrder body invokes 0x260d6a0 immediately after the optional field helper. This worker tests its own leading descriptor byte, uses the same key helper, and dispatches the value to 0x25fba40, a different formatter from 0x243c060. A separate copy site uses the memcpy slot. The packet maps the follow-up path while leaving the original field type unresolved.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-optional-followup-field-115/collect.py --out work/node115-snapshot-optional-followup-field-fresh
python3 -B research/work-items/RE-012-snapshot-optional-followup-field-115/verify.py --out work/node115-snapshot-optional-followup-field-check-fresh.json
```
