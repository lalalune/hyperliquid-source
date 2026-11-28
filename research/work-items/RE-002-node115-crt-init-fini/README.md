# RE-002: qualify the node #115 scalar CRT init and fini entries

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. No external source.

The existing constructor census covers the arrays. This evidence covers the scalar DT_INIT and DT_FINI entries used by the linked image, at ELF VAs 0x63f0a00 and 0x63f0a1c. A candidate CRT link can be checked for the same optional profiling call separately from its constructor arrays.

GNU objdump 2.42, using `objdump -d -M intel -j .init -j .fini artifacts/node/115/hl-node`, displays the null guard and the return-only finalizer. The DT_INIT RIP-relative load at 0x63f0a08 resolves to slot 0x64df460. The slot's sole RELA record has type GLOB_DAT and points to an undefined weak symbol named `__gmon_start__`. A zero slot takes the branch past the indirect call. DT_FINI has no call. The packet makes no claim about runtime symbol resolution or exact CRT package identity.

Run `python3 research/work-items/RE-002-node115-crt-init-fini/verify.py` from the repository root to verify the exact bodies, dynamic tags and relocation. The offline log includes a branch-displacement mutation rejected by the selected branch check. No capture is executed and no component gate changes.
