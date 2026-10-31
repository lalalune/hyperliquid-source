# RE-002: node #94 call-frame bases and entry prologues

- Component: build provenance / foundation.
- Question: what does the captured node's unwind information establish about
  frame bases, and does a leading `push rbp` identify an RBP frame?
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (91,774,280 bytes).
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Claim status: static observations; no reconstructed implementation,
  execution, equivalence claim or progress gate.

The existing [build-provenance packet](../RE-002-build-provenance/README.md)
leaves `frame_pointers` unresolved and asks for a prologue survey. This packet
adds a complete census of **FDE records starting in `.text`**, with an
independent GNU readelf comparison. It does not resolve one global compiler
option from a mixed, linked executable.

## Results

Both parsers find 121,299 FDE records, all starting and ending in `.text`
(`0x1343c80` through exclusive `0x56600b0`). Register sets below are the union
of the CFA base registers over each decoded FDE's rows. They are not a count
of functions, executed paths or stack frames observed at runtime.

| CFA registers in an FDE | Records |
| --- | ---: |
| RSP only | 119,221 |
| RBP and RSP | 1,657 |
| RBP only | 365 |
| RSP and R11 | 55 |
| RBP, RSP and R11 | 1 |

These are DWARF x86-64 register numbers 7, 6 and 11 respectively. No decoded
CFA expression occurs in this target's FDE rows. `check_readelf.py` separately
reads GNU readelf's interpreted text; it does not use pyelftools to decode CFI.
The two complete register-set counts agree exactly.

There are 29,139 FDE entries whose first byte is `55` (`push rbp`):

| Entry bytes / CFA observation | Records |
| --- | ---: |
| `55 48 89 e5` (`push rbp; mov rbp,rsp`), with RBP/RSP CFA rows | 1,226 |
| Other `55` prefixes, with RBP/RSP CFA rows | 23 |
| Other `55` prefixes, with RSP-only CFA rows | 27,857 |
| Other `55` prefixes, with RSP/R11 CFA rows | 33 |

Thus 27,890 of the leading-push records do **not** describe RBP as their CFA
base. A saved RBP register and an RBP-based CFA are distinct observations.
The byte test is explicitly limited to these entry encodings; it is not a
general instruction decoder or an exhaustive search for every possible
frame-establishment sequence.

### Two concrete controls

`frame-positive.objdump.txt` shows `0x1343d69..0x1343d90`: the entry is
`push rbp; mov rbp,rsp`. Its decoded CFA changes from `rsp+8` to `rsp+16`, then
`rbp+16`. The corresponding FDE is retained among the summary samples.

`hour-caller.objdump.txt` shows `0x14027b0..0x1403c29`, the caller already
bounded in the [hour packet](../foundation-hour-94/README.md). It starts with
`push rbp` but uses RBP as data: at `0x14027e1` it loads EBP from `[rsp+0x10]`,
later loads RBP from `[rbx+0x80]`, and at `0x1403089` loads the immediate
`0x1000000000000000`. Its 16 decoded CFA rows use RSP. This is a concrete
counterexample to classifying every leading `push rbp` as an RBP frame.

GNU objdump's nearest dynamic-symbol labels are not function names or source
ownership claims. The addresses here are ELF linked VAs, without runtime
rebasing. The original FDE extents, bytes and decoded rows in `summary.json`
allow the observations to be checked without trusting those labels.

## Reproduce

Use the repository's authenticated artifact setup first. `survey.py` refuses
any input with a different size or SHA-256 before parsing it. The Python
dependency is optional and confined to this packet:

```sh
python3 -m venv work/frame-survey-env
work/frame-survey-env/bin/python -m pip install --only-binary=:all: --require-hashes \
  -r research/work-items/RE-002-frame-pointers-94/requirements.txt
work/frame-survey-env/bin/python research/work-items/RE-002-frame-pointers-94/survey.py \
  --check research/work-items/RE-002-frame-pointers-94/summary.json
python3 research/work-items/RE-002-frame-pointers-94/check_readelf.py \
  --input artifacts/node/94/hl-node \
  --summary research/work-items/RE-002-frame-pointers-94/summary.json \
  --output work/frame-pointers-94/readelf-crosscheck.json
work/frame-survey-env/bin/python research/work-items/RE-002-frame-pointers-94/check_controls.py
```

Validation used the exact pyelftools 0.32 wheel from `requirements.txt`,
unpacked into an isolated `PYTHONPATH`, with CPython 3.12.3 on Linux and
3.13.15 on Windows. The Python summaries and generated TSV are byte-identical
between the two operating systems. The GNU comparison used binutils 2.42 on
Linux; `readelf-crosscheck.json` and `.txt` retain its result and four example
FDE dumps.

The 121,299-row `frames.tsv` is generated under ignored `work/`, not imported
into the source tree. Its SHA-256 on both hosts is
`23ec2a0f85f5641e84fcfa000189b710498664ed35bcc19f4583fa6a7d38f8a6`.
The full GNU interpreted output has SHA-256
`294dd13b0ad4a19de1f036ca3288032dbee3f5308587e8d859ef1f4486058f57`.
No operand or address normalization is applied.

Repository checks on Linux:

```sh
make PYTHON=python3 doctor
make PYTHON=python3 verify test catalogue-check
make PYTHON=python3 reproduce
```

All pass, including **431 existing tests**, all three artifact signatures,
37 imported-file checks and every pinned source-repository check. Captured
node/visor programs are never executed. The Windows source checkout cannot
materialize the reference's reserved `node/aux.rs` name, so complete repository
checks were run in a separate Linux checkout at the same baseline, with
unaltered pinned reference names and commits.

`check_controls.py` also runs five negative controls through the real CLIs:
each checker refuses a truncated capture and a full capture with one changed
byte, and the GNU checker refuses a summary whose RSP count was increased by
one. All five return nonzero without creating result files. The authentic
capture is never modified.

## Limits and next question

- FDEs can describe fragments and omit code; this is not a function census.
- A CFA base is unwind metadata, not by itself proof of the frame-chain
  convention in every instruction path. The two disassemblies above are
  bounded concrete controls, not whole-executable semantic verification.
- The executable mixes application code and linked libraries. This packet
  neither assigns all FDEs to Rust crates nor identifies a single
  `force-frame-pointers` setting for the build.
- No code, compiler configuration, imported evidence, catalogue or progress
  gate changes. Node #115 and visor are not part of this census.

The next useful question is which of the 2,023 RBP-bearing FDE records belong
to first-party Rust code versus linked objects, using validated source and
call relationships rather than nearest-symbol labels. That attribution is
required before changing the unresolved build-flag field.
