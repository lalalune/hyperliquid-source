# RE-001: unique bridge static address mappings

Component: bridge offline evidence tooling, not a bridge transaction or recovered implementation. Bounded question: can Mapping select one interpretation by segment order and silently omit executable regions? Base 1f8c67c63ca4794c9689235471c60297f8a5c985. Files: tools/bridge_inventory.py, tests/test_bridge_mapping_uniqueness.py and this packet. No inferred reference source is used. The terminal operand-loop fix in a separate PR is not included here.

Target: node #94 SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f, authenticated before tests. Original PT_LOAD records (file offset, linked VA, file size, flags): (0,0,20196480,4), (20196480,20200576,70374864,5), (90571344,90579536,1143808,6), (91715152,91727440,56480,6). Executable region begins at file0x1342c80 / VA0x1343c80. These are segment coordinates, not function or section bounds.

Controlled metadata edits are in owned memory only. Locate the first PT_LOAD in the real program-header table. Change p_vaddr at header+16 to the original executable VA: VA0x1343c88 then maps to two different file offsets, selected differently when row order is reversed. Change p_offset at header+8 to the original executable offset: file0x1342c88 maps to two VAs, also order-dependent. Set PF_X at header+4 on that first region: two distinct executable regions exist, but execute_segment() silently returns only the first. Neither these edits nor reversed views are claimed loader-consistent; they challenge the static mapper's admission behavior. No captured bytes/pins are rewritten or executed.

Base has five failing corruption subcases: both orders of each ambiguity and multiple executable regions are accepted. The fix requires a unique resulting file coordinate/VA, and a unique region for the existing single-region scanner. It preserves identical duplicate mappings, which have one interpretation, and rejects only distinct results. A normal target/reordered-input control compares real mapped bytes. execute_segment() only selects static coordinates; it never executes code.

Reproduce from repository root, Windows/Python3.12.14, PYTHONUTF8=1 and PYTHONIOENCODING=utf-8:

```text
python -m unittest discover -s tests -p test_bridge_mapping_uniqueness.py -v
python -m unittest discover -s tests -p test_bridge_inventory.py -v
python tools/bridge_inventory.py --release 94
python -m unittest discover -s tests -v
python tools/doctor.py
python tools/artifacts.py verify
python tools/verify_imports.py
python tools/catalogue.py --check
python tools/reproduce.py
git diff --check
```

After: all five new tests pass. Existing bridge12 attempted tests have11 passes and one existing Windows NamedTemporaryFile sharing PermissionError. The complete actual node94 bridge main() reports from base and changed sources are equal; canonical sorted-JSON SHA-256 4669206094ae4248326a305a6de3c0962a17b4e699d4ec768da36f4acc706a28. No packet regeneration is needed.

Required broad checks are attempted through Python because make is absent. Full tooling is not claimed green: baseline281 has seven failures,32 errors,nine skips; current full result is recorded in the PR after completion. Doctor lacks GPG/native analysis/Rust tools. Artifact hashes match before missing GPG blocks signature checks. The incomplete Windows reference checkout (reserved node/aux.rs) blocks imports; catalogue-check is stale and reproduce stops at artifact verification. Original logs are retained in the preparation directory as bridge-mapping-before/after/existing/workflow/full and bridge-mapping doctor/artifacts/imports/catalogue/reproduce logs.

Full suite completed: 286 tests in125.138s, seven failures,32 errors,nine skips, the same failure counts as baseline. git diff --check passes.

No loader policy, complete instruction census, source recovery, whole-program equivalence, captured execution, live networking or progress gate is claimed. Next: maintainer reproduction on a complete supported checkout, then separately design any multi-region scanner support rather than silently claiming it here.
