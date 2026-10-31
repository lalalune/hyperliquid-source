# RE-015 / RE-001: include complete terminal RIP-relative operands

Bounded offline-tooling question: do the constants and bridge xref scanners include every complete supported operand at the end of their scan interval? Base 1f8c67c63ca4794c9689235471c60297f8a5c985. Affected files: tools/constants_scan.py, tools/bridge_inventory.py, tests/test_constants_xref_tail.py and this packet. Two instances of the same terminal-bound error are fixed together, not counted as separate contributions. Pool-entry and string-table validation in other PRs is outside scope.

Target: retained node #94 SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f, hashed by the regression. Original /static_config LEA bytes: 48 8d 35 40 fa b9 fe, instruction VA 0x164fbae, file offset 0x164ebae, resolved pool-entry target 0x1ef5f5. The existing constants packet's site 0x164fbaf is the opcode coordinate, one byte after REX; that existing schema is preserved. No new function-boundary or instruction-census claim is made.

The regression passes actual capture bytes with a reduced declared scan interval of 7, 8 or 9 bytes from that instruction. Constants base drops the complete instruction at sizes7 and8; bridge base drops it at size7. Both already detect it with extra trailing bytes. Sizes0..6 are negative controls: a physically present displacement beyond the interval must not be read. No bytes, captured section headers, artifact paths or pins are modified. Reduced views test scan bounds, not a replacement loader-consistent ELF or a new component inventory.

Constants' loop variable names the opcode after REX, so six bytes remain from it through disp32. The stop becomes end-5. Bridge's variable names disp32 itself, so four bytes remain and its stop becomes len(body)-3. Both are exclusive Python range stops. Original return coordinates and report schemas are unchanged.

Reproduce on Windows/Python3.12.14, PYTHONUTF8=1 and PYTHONIOENCODING=utf-8:

```text
python -m unittest discover -s tests -p test_constants_xref_tail.py -v
python -m unittest discover -s tests -p test_constants_scan.py -v
python -m unittest discover -s tests -p test_bridge_inventory.py -v
python tools/constants_scan.py --release 94 --check research/work-items/constants
python tools/bridge_inventory.py --release 94
python -m unittest discover -s tests -v
python tools/doctor.py
python tools/artifacts.py verify
python tools/verify_imports.py
python tools/catalogue.py --check
python tools/reproduce.py
git diff --check
```

Before: final five-test regression replayed against the unmodified Git object sources yields three failing subcases. After: all five pass. Existing constants10 tests pass; bridge12 attempted tests have11 passes and one pre-existing Windows NamedTemporaryFile sharing PermissionError, not a parser regression.

Real complete workflow checks: base and changed constants main() both match every stored constants output. Because the reference checkout is incomplete on Windows, only its two authentic pinned source files (global_constants/aws_name.rs and static_config.rs from can1357 commit999556f6e0a474b8312db96ec3149e1c44e97c23) were read from Git objects into an owned temporary input directory and passed via the existing reference path globals. No fake arrays or reference functions are substituted; no inferred Rust is committed. Both complete bridge main() reports are identical, canonical sorted-JSON SHA-256 4669206094ae4248326a305a6de3c0962a17b4e699d4ec768da36f4acc706a28.

Full suite: baseline281 and final286 tests both have seven failures, 32 errors, nine skips. Final elapsed118.371s. Full tooling is not green. make is unavailable; its Python commands were attempted directly. Doctor lacks GPG/native/Rust tooling; artifact hashes match before missing GPG prevents signature checking. Imports fail at incomplete Windows reference checkout (reserved node/aux.rs); catalogue-check is stale and reproduce stops at artifact verification. git diff --check passes. Original transient logs and source replay/workflow scripts are retained in the preparation directory (xref-tail-final-before/after/full, xref-tail-workflow, xref-tail-bridge-workflow, xref-tail-existing, xref-tail-bridge-existing and xref-tail required-check logs).

No captured execution, recovered source, complete function census, equivalence, progress gate or hosted CI success is claimed. Further instruction-boundary validation remains outside these existing byte-pattern scanners. Next: maintainers reproduce terminal controls and full workflows on a complete checkout.
