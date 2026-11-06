# RE-012: bind node #115 TCP compression scratch unwind

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

RE-012 transport question: who releases the temporary compression scratch on codec unwind? #2768 qualified the normal selection and handoff, while #2789 explicitly leaves the original unwind contract open.

The LSDA at ELF VA 0x26a0e0 uses FDE-relative call-site offsets. The action-zero row `fc022da10f00` covers [0x2b7a40c,0x2b7a439) and selects 0x2b7aa31. Row `ab052d8f0f00` covers [0x2b7a53b,0x2b7a568) and selects 0x2b7aa1f. These landing pads preserve the exception value in r15 and fetch the scratch pointer from rsp+0x180. They provide 0x2000 and 0x4000 respectively to the shared indirect release call at 0x2b7aa43 and pass zero in edx. The large codec call at 0x2b7a562 lies in the latter range and its ordinary continuation releases at 0x2b7a57d before inspecting the result.

Reproduce the row interpretation with the repository's tools/re011_balance_read115.py parse_lsda helper using the FDE start/end and .gcc_except_table bounds, then inspect the selected landing pads in the two saved disassemblies. This establishes the selected scratch ownership paths under static unwind metadata, with no claim about allocator failure handling outside these ranges or full sender unwinding.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-tcp-scratch-unwind-115/collect.py --out work/node115-snapshot-tcp-scratch-unwind-fresh
python3 -B research/work-items/RE-012-snapshot-tcp-scratch-unwind-115/verify.py --out work/node115-snapshot-tcp-scratch-unwind-check-fresh.json
```
