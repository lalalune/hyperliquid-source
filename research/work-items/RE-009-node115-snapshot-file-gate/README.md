# RE-009 · Snapshot reader file admission

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Inside the previously mapped reader 0x26a3610, the prepared path pointer and length are passed to slot 0x64e0950 at 0x26a3642. The ELF relative relocation binds this slot to the previously identified regular-file-shaped predicate 0x1500d20.

Zero AL branches before suffix parsing. It builds a diagnostic from the path record and the encoded descriptor containing `missing file: `, then calls 0x2a02000. The common error continuation saves the returned object, selects status 1, conditionally releases the prepared path allocation, and returns status in RAX and the object in RDX. The previously mapped caller checks that low status bit. The message can accompany a rejected path without proving why the predicate returned zero.

Run `python3 research/work-items/RE-009-node115-snapshot-file-gate/verify.py` from the repository root to check the authenticated instruction windows, diagnostic bytes and relative relocation.
