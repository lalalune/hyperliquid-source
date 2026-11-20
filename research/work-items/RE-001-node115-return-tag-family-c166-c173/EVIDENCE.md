# Evidence: node115 sibling return-tag family c166–c173

- Target digest: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Raw disassembly: `excerpts.objdump.txt`
- Structured observations: `records.json`
- Deterministic verifier: `verify.py`
- Address coordinate system: linked ELF virtual addresses in `.text`; FDE values are `.eh_frame` virtual/file coordinates reported by the repository readers.
- Reference revision: repository pinned inputs at base `a8a165e65d53abc1c996bcc9b609749529cfc41a`.

The verifier checks the digest, all eight exact FDE extents and unwind-index entries, one direct call target per extent, terminal store witnesses, and two padding/boundary negative controls. No captured binary is executed.
