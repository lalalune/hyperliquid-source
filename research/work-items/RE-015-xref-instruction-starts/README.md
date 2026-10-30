# RE-015: report the first byte of each constants xref instruction

- Component: `constants`; task `RE-015`, correcting the tooling in #7.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Reproduced source: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Pinned reference: `can1357/hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`; no reference implementation is copied.
- Claim: observation and tooling correction. No reconstruction gate change.

## Problem and evidence

The scanner stores seven bytes beginning with a REX prefix, but returned the
opcode VA one byte later. Its JSON and TSV therefore pointed inside the
instruction and the bytes at `site_file_offset` disagreed with `instruction`.
Using that site for disassembly loses the prefix (including register/width
bits); a byte-window or instruction-boundary check fails.

For `/cham`, the old site was `0x164f841`, while GNU objdump decodes
`48 8d 35 a5 c8 ba fe` at `0x164f840`, resolving to `0x1fc0ec`.
`sites.tsv` preserves all nine original site/file coordinates beside the
correct coordinates. `objdump.txt` retains the commands and instruction
lines from the enclosing index windows. Every reported seven-byte sequence
has exactly one matching decoded instruction in its window.

Before: 9/9 sites differ by +1 and 9/9 byte windows disagree.
After: 9/9 sites agree with GNU objdump and 9/9 byte windows agree.
Target VAs, instruction bytes, nine-site/seven-target census, 76 table entries,
window bounds and `strings.tsv` are unchanged. The two generated canonical
outputs and the coordinate/hash references in their README are corrected;
the original target bytes, imported inputs and disassembly are retained.

## Reproduce

Ubuntu 24.04 under WSL, Python 3.12.3, GNU objdump 2.42. Static reads only;
the captured node and visor are never executed. Inputs pass the repository's
SHA-256, GPG signature and submodule/import checks.

From the repository root, after materializing the pinned inputs:

```sh
mkdir -p work
git show 1f8c67c63ca4794c9689235471c60297f8a5c985:tools/constants_scan.py > work/constants_scan-before.py
python3 work/constants_scan-before.py --release 94 --out work/constants-before
python3 tools/constants_scan.py --release 94 --out work/constants-after
python3 tools/constants_scan.py --release 94 --check research/work-items/constants
objdump -d --start-address=0x164f810 --stop-address=0x164f970 artifacts/node/94/hl-node
python3 -m unittest discover -s tests -p test_constants_scan.py -v
make verify test catalogue-check reproduce
```

The fixture's expected VA is corrected from the opcode to the instruction
start. A regression also reads the returned site's byte window and requires
it to equal the reported instruction. Both assertions fail before the fix;
the focused 11 tests pass after it. The full repository results belong to
the PR's exact-head validation record.

## Scope and limitations

This changes the reported coordinate only. It does not add a general x86
decoder, expand the scanner's supported encodings, validate arbitrary byte
matches as instructions, reconstruct Rust, execute targets or compare runtime
behavior. GNU independently validates the nine retained #94 matches only.
No normalization masks are used. Node #115, visor, function/ABI/helper closure,
build equivalence and all component progress gates remain outside this change.
Next step: reuse these corrected sites in bounded constants research.
