# RE-002: qualify the node #115 loader's RELA prefix

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Baseline: 2da45cb0a761cff6b478e40421699857d87a94df. No external source used.

The [load segment study](../RE-002-node115-load-segment-tls-layout/README.md) left the PT_DYNAMIC handoff open. Reading PT_DYNAMIC at file offset 0x64dd248 and translating virtual addresses through file-backed PT_LOAD ranges gives this loader view, independently of the ELF section headers:

- DT_RELA at VA 0x6be8 has 60,723 records of 24 bytes. DT_RELACOUNT is 59,534. Every record in that exact prefix is R_X86_64_RELATIVE with symbol index zero. The remaining 1,189 records are 924 R_X86_64_64, 263 R_X86_64_GLOB_DAT and two R_X86_64_TPOFF64 records.
- DT_JMPREL at VA 0x16a8b0 begins immediately after that table. Its 278 entries are all R_X86_64_JUMP_SLOT, with DT_PLTREL selecting RELA. DT_RELR, DT_RELRSZ and DT_RELRENT are absent.

This fixes a comparison boundary for candidate links. A RELA rebuild can be checked against the exact relative-prefix cutoff and the distinct PLT relocation inventory. It does not establish loader runtime behavior, the originating linker invocation, or any component gate.

From the repository root run:

```sh
python3 research/work-items/RE-002-node115-loader-rela/verify.py
```

The retained run checks the full table counts and rejects both one-record shifts of the declared cutoff. It reads the captured ELF as data.
