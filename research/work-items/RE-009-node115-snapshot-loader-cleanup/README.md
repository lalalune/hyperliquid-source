# RE-009 · Shared snapshot loader cleanup

Two distinct Node #115 state-loading cleanup paths call `0x3d13a40`, at `0x3c12ac9` and `0x3c135e2`. The routine uses descriptor +0 as a guard. When nonzero, it passes descriptor +8, descriptor +0 and zero to the slot at `0x64df4a0`. The zero branch skips that call. Both branches advance the descriptor pointer by 24 and tail-jump to `0x3932230`. The conditional leading field cleanup and unconditional nested cleanup therefore have different guards. This concerns teardown on the selected loader paths, and leaves field types, callback identity and normal-load ownership open.

From the repository root run `python3 research/work-items/RE-009-node115-snapshot-loader-cleanup/verify.py`. It checks the pinned ELF digest, the full cleanup extent, both caller edges with corruption controls, and the shared tail target. No captured code is executed.
