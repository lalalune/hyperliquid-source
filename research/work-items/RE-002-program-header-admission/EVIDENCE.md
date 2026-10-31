# RE-002: bound the program-header table before deriving segment facts

- Component: build provenance, static tooling only; no completed gate requested.
- Baseline: node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Separate controls: node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
  visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Changed paths: `tools/build_provenance.py`, `tests/test_provenance_program_headers.py`.

## Reproduce

```sh
python -X utf8 -m unittest discover -s tests -p test_provenance_program_headers.py -v
python -X utf8 -m unittest discover -s tests -p test_build_provenance.py -v
python -X utf8 tools/build_provenance.py --check 94 115 visor
```

The regression authenticates retained artifacts before use. Negative cases
change only the node #94 ELF header in an owned memory copy: `e_phentsize` at
file offset 54 to 0, 1, 55 or 57, and `e_phoff` at offset 32 to 0, 1, 63 or
one byte before EOF. Seven cases previously returned bogus/repeated program
headers and one leaked `struct.error` on truncation. They now raise a bounded
`ValueError` before segment facts are derived. No captured file is rewritten.

All three authentic artifacts retain their original 12 program-header records;
tests retain golden hashes from the base decoder rather than inventing segment
expectations. Section-only inputs with no program-header entries remain
supported by existing synthetic provenance controls.

## Results and limitations

New regression: four tests pass; actual base source produces seven failing
subcases and one truncation error. Existing provenance suite: nine tests pass.
All committed provenance records match all three authenticated targets.
Windows, Python 3.12.14. Full-suite and required root-check results are reported
in the PR; missing native tools, partial Windows reference checkout and stale
catalogue remain separate limitations. No catalogue/progress record is changed.

This validates one parser's supported ELF64 table layout and bounds, not the
correctness of build-flag inference or a reconstructed node. No target binary
executes, no dependency version is inferred or changed, and no equivalence or
accepted component gate is requested. Next step: independent target-grounded
verification of unknown build settings under the original RE-002 criteria.
