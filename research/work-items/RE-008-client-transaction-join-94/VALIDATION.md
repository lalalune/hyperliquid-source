# Actual pre-code qualification

Both final author commands completed with exit0:

```sh
python3 -B verify.py --pre-freeze-check --out /tmp/txjoin-prefreeze-complete-normal-v2-20261102
python3 -B -O verify.py --pre-freeze-check --out /tmp/txjoin-prefreeze-complete-optimized-v2-20261102
```

Each regenerated two independent output trees, matched all retained exports and
361 independent input/expected frames, and rejected74 controls. Normal and `-O`
validation JSON are byte-identical. `static-validation/commands.json` binds the
actual script hashes, command statuses, raw combined-output logs and the retained
report. No Rust compilation, captured executable, instruction emulator, old
native evaluator, broad test suite, hosted CI or whole-node run occurred.

The controls include target SHA/size, omitted/shortened ranges, wrong denominators,
missing decoded functions, GNU/LLVM disagreement,56 changed native field/stride/
branch/tag/width/clone/cleanup instructions decoded afresh below target/body SHA,
five raw relocation changes, one raw FDE extent, selected table corruption and
three independent CFG/prefix bypass controls. The latter do not rely on body
hashes or instruction pins. Rejections are structural evidence checks, not
executed mutant behavior or an automated proof of all machine-code semantics.

Full retained native exports use a private read-only snapshot of the admitted
ELF; snapshot bytes are checked again after every export batch. Both native
providers decode complete FDEs. `native/commands.json` lists all24 successful
invocations, exact options, logical executable/snapshot paths and normalized
stdout hashes. Only the disassembler input filename becomes `hl-node`; native
addresses, bytes and operands are unchanged. Executable identities/raw versions
are in `providers.json`. Provider versions may change formatting; passing a
different provider is not a normalization waiver. Replay accepts explicit paths:

```sh
python3 -B verify.py --out /tmp/txjoin-new-frozen-replay \
  --gnu /path/to/gnu-objdump --llvm /path/to/llvm-objdump
```

The default command after freeze omits `--pre-freeze-check`, checks every frozen
pre-code file, then performs the full reproduction/control run. A new output
directory is required. `evidence.py --out NEW` reproduces native records alone;
`corpus.py --out NEW` reproduces fixture archives alone. Gzip mtime is zero and
packet `.gitattributes` stores archives as normal Git blobs. Do not replace an
unhydrated captured ELF LFS pointer with a fabricated target.

An initial scout LLVM command rejected unsupported `--show-raw-insn` with exit1;
`initial-provider-failure.json` preserves that outcome. The unsupported flag was
removed, and full exports were rerun successfully. Preliminary pre-freeze passes
were preserved in session scratch before adding command metadata and the complete
`.rela.plt` overlap census. Those refinements changed no fixture formula/bytes or
native text. The final reported passes bind the complete code/records now frozen.

The proof and oracle are from the same research lineage as the binary evidence.
Other independent reviewer observations can be retained separately, but do not
upgrade these results into independent native execution. Actual Rust behavioral
qualification and meaningful compiled controls require a later source/build gate.
Repository-wide static integration checks remain the parent's publication step;
this file does not claim their results in advance.
