# RE-001: bind unwind-index bounds to unambiguous section coordinates

- Component: shared static function-map tooling; no completed gate requested.
- Baseline: node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Paths: `tools/elf_index.py`, `tests/test_unwind_section_coordinates.py`.

## Problem and evidence

The first index pass finds a section by the unwind start address, but the
upper-bound pass finds it again by its name. Names are not unique section
identities: the [ELF gABI section specification](https://gabi.xinuos.com/v42/elf/03-sheader.html)
explicitly permits repeated section names. The second lookup can therefore
use another section's end. The first pass also silently chooses one of
multiple executable ranges covering the same start.

The regression authenticates node #94, changes `.init`'s name to `.text`,
then swaps its header with the original `.text` header. Section payloads and
virtual ranges are unchanged. Main extends the final unwind upper bound from
90,570,928 to 90,570,955, using `.init`'s end rather than the range containing
the start. With coordinate-based lookup the complete index rows equal the
unmodified input's rows. A second metadata-only control moves `.init` over
the first unwind start: main guesses, while the fix rejects ambiguity.

These are owned in-memory section-table controls, not modified captured
files or replacement executable artifacts. No transformed image is run, and
its unrelated symbol/loader relationships are outside this index test.

## Reproduce

```sh
python -X utf8 -m unittest discover -s tests -p test_unwind_section_coordinates.py -v
python -X utf8 -m unittest discover -s tests -p test_research_tools.py -v
python -X utf8 -m unittest discover -s tests -p test_fde_extents.py -v
```

New tests: main has two failures; after the fix all three pass. Existing
research/FDE suites pass 13/17 tests. All complete sections and index rows
for the authenticated original #94, #115 and visor inputs are identical
before/after; `results.json` binds their separate hashes and counts.

Full-suite and required root-check results are disclosed in the PR. Windows
native-tool and reference-filename limitations remain; no broad passing
verification is inferred. Python 3.12.14. No progress/catalogue data or source
pin changes. Unwind upper bounds remain non-function extents: this establishes
neither complete function boundaries nor equivalence, buildability or safety.
Next question: actual FDE/CFG extent validation under RE-001's original scope.
