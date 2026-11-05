# RE-009: complete node115 sponge permutation, full state comparison

Foundation helper required by the mapped ABCI/result/bridge digest paths.
Sole node115 target SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base05bc2de303c05525b71e7e257426e741bc66a390. Existing
RE-017-abci-result-digest-115 retains selected sponge constants and mapping;
its complete permutation was not independently reconstructed/compared. This
one contribution addresses that missing whole1410B354instruction helper,
not a new alias, isolated rotate or already-known data-table extraction.

The complete FDE5cda380..5cda902 is visited, all354starts. No CALL/helper return
or interior-entry trace is supplied. Original instructions really execute the
24-round loop in the explicitly operator-authorized offline Python evaluator;
no captured ELF process, Unicorn, service, network/chain/signing/wallet runs.
Every one of the200state bytes is significant; realRET/SP, callee-saved register
canaries, state guards, readonly data and precise writable footprint are checked.
CONTRACT.md fixes premises, API boundary and remaining library/caller gaps.

262distinct inputs cover every lane at bits0/1/7/8/31/32/62/63, each full lane,
allzero/allone, byte-order/asymmetric patterns and32fixed-seed dense states.
12actual opcode/operand/constant COW changes alter normal200byte outputs, with
2separate origin/bound rejections. All24captured constants match an independent
FIPS202 LFSR derivation. Source/gold must be Git-sealed BEFORE Rust is authored.
The expected function is actual original instructions, not another Keccak loop.

The existing machine rejected native ROL(kind0) at the first smoke,4.428s.
Only this packet adds the missing actual64bit ROL semantics, with masked counts,
preserved ZF/SF and undefined multi-bit OF keptunknown. A second two-input smoke
passed5.975s. Shared tools are unchanged. Both original failure/pass logs and the
full262input freeze110.103s are retained; initial failure is not a passing run.
The final corpus has6219actual steps per vector and covers the entire FDE.

```sh
python3 research/work-items/RE-009-sponge-permutation-115/proof.py --objdump /path/to/objdump
python3 -m unittest discover -s tests -p test_sponge_permutation115.py -v
```

Public mathematical references and exact ISA-extension scope are in CONTRACT.md.
No unlicensed inferred source, guessed dependency version or fabricated Cargo
graph is used. The algorithm label is not a claim that the original library,
compiler output, entire sponge/digest or private preimage is reconstructed. New
code uses root MIT; captures/imports and original static packet keep their rights.
No first-party/dependency/completion percentages or gates advance. Next close
actual sponge absorb/finalize/helper contracts before a complete digest API.
