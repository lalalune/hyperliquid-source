# Validation receipt

Baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`, real Git checkout and
six real pinned upstream Git checkouts; authenticated current #115 and visor
inputs. No retired #94 binary, inferred reference or source was restored.
No captured executable was run.

## Observed checks

| Command / check | Result |
| --- | --- |
| `make doctor` | analysis ready; exact rebuild remains unavailable |
| Baseline `make verify` | artifact hashes/signatures, pinned sources and 28 packet manifests / 456 entries passed |
| Both complete native exports, repeated | exit 0, empty stderr; same full raw hashes |
| `reconcile.py` | 135,313 bound FDEs agree between GNU and LLVM; 9 decoded-record corruptions rejected |
| `capture.py` + `check.py` on fresh repeated exports | 19 generated files reproduce byte-for-byte; all seven complete selected FDE bodies match both native byte streams |
| `controls.py` | 4 additional native-parser/identity corruptions rejected |
| `make doctor test catalogue-check reproduce` with isolated Capstone | exit 0; 76 files attempted, 382 reported cases, zero failed files; 4 explicitly optional skips |

The full-suite log SHA-256 is
`798933a6110cf4b82937b3b3ec90e0a7ad26a1b59469440ea73c8aff2d33432f`.
This receipt records local checks; no hosted-CI or full-node build pass is claimed.
The final manifest verification is run after this receipt and manifest exist.

## Environment and initial failures

Linux x86-64, Python 3.12.3; native versions are in `versions.json`.
An existing rustc 1.95.0 installation was added to this process's PATH.
No global tool or repository dependency was changed.

The first doctor lacked ripgrep and Git LFS in its noninteractive PATH. Existing
tool installations fixed that environment. Verify then identified two current
#115 LFS fixture pointers (`RE-004-node115-u128-binary64/inputs.tsv.gz` and
`expected.tsv.gz`). They were fetched through public unauthenticated Git LFS and
explicitly checked out, preserving and then verifying their committed identities.

The first complete test command attempted all 76 files but failed three that
imported missing Capstone, so it did not reach catalogue/reproduce. Its log hash is
`5f0b24a32742ae258d0a7b55aa8a5b49da0930efecc555505ff4411d7909f915`.
No source/test expectation was changed to fix this. The corrected full command
used `PYTHONPATH=<isolated-capstone-site>` and the existing Rust/analysis tool PATH.
Official PyPI Capstone 5.0.6 wheel:
`capstone-5.0.6-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`, SHA-256
`0358855773100bb91ae6681fabce7299df83156945ba943f6211061a592c54a6`.
Release metadata, wheel paths and install metadata were inspected; the wheel was
hash-checked and unpacked into the research environment, without running an
installer or modifying user/global Python. The packet's census uses only stdlib
Python and existing repository readers; Capstone is needed by existing root tests.

## Optional skips, unchanged

- `setUpClass (test_node115_field_adapter_drift.ActualNode115Bindings) ... skipped 'Set HL_RE014_LIBCORE to the explicitly supplied pinned official archive; no download or qualification is implied.'`
- `test_actual_compilation_layouts_and_source_corruptions (test_nonce_ring_rust.NonceRingRustTests.test_actual_compilation_layouts_and_source_corruptions) ... skipped 'explicit HYPERLIQUID_NONCE_RING_RUSTC and Capstone5.0.6 required; not a Rust pass'`
- `test_real_nested_jre_uses_enclosing_jdk (test_rea_java_home.NativeJavaHomeTests.test_real_nested_jre_uses_enclosing_jdk) ... skipped 'native macOS resolver required'`
- `test_system_launcher_uses_registered_jdk_root (test_rea_java_home.NativeJavaHomeTests.test_system_launcher_uses_registered_jdk_root) ... skipped 'native macOS resolver required'`

These skips are not Rust compilation or official-library comparison passes.
All incomplete component gates remain unchanged. Full source/object attribution,
compiler flags, runtime behavior, call/data closure and whole-node equivalence
remain unresolved; this packet advances only the bounded static RE-002 question.
