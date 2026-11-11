# Validation scope

Base `05bc2de303c05525b71e7e257426e741bc66a390`; Windows host, Python
3.12.14, Capstone 5.0.6, pyelftools 0.32. All investigation was static. Neither
captured executable nor any chain action was run. No runtime/compiler result
or hosted CI pass is claimed.

| Check | Observed result |
| --- | --- |
| `python research/work-items/RE-012-send-readiness-state-115/verify.py --write` | exit 0; full SHA-256 identity, exact FDE, 443 bytes / 120 decoded instructions, 22 internal branch destinations and seven calls |
| same command without `--write` | exit 0; byte-identical records and disassembly regeneration |
| operative byte mutations with whole-file guard disabled | 7/7 refused by focused semantic pins, including changed retry branch condition |
| two arithmetic forms of the readiness projection | 65,536 cases; zero mismatches; no target execution |
| artifact sizes and SHA-256 values | all six manifest entries match after LFS materialization |
| manual detached node signature check | GPG exit 0; VALIDSIG `CF2C2EA3DC3E8F042A55FB6503254A9349F1820B`, matching the pinned fingerprint |
| `python tools/verify_imports.py` | exit 0; 32 imported files and all six exact submodule commits verified |
| `python tools/verify_packets.py` on the unchanged tracked baseline | exit 0; 558 manifests / 7,123 entries; 31 historical unresolved rows grandfathered by the existing checker |
| `python tools/doctor.py` | `analysis_ready: false`; GNU objdump/readelf, Rust toolchains and Ghidra absent from this host's PATH |
| `python tools/artifacts.py verify` | exit 1 at GPG public-key import; MSYS path conversion was not discovered through Python's executable search |
| `python tools/reproduce.py` | exit 1 at its mandatory artifact-verifier subprocess; inventory reproduction not completed |
| `python tools/catalogue.py --check` initial baseline | exit 1 at root README decoding under Windows cp949 |
| `python -X utf8 tools/catalogue.py --check` baseline | exit 1: stale root README (559 recorded versus 560 tracked work items before this packet) |
| `python -X utf8 tools/catalogue.py` with this packet in an isolated Git index | exit 0; README and progress SVG inventory regenerated to 561 work items; no gate or coverage change |
| `python tools/run_tests.py` | repository-wide run launched; partial output contains baseline failing files; no complete-suite pass claimed |

The manual signature check used Git's explicit GPG executable, an isolated
ignored `work/gpg-public-verification` directory, `--batch --no-options
--no-autostart`, and explicit MSYS `/c/...` paths. Public-key import reported
the key imported but exited 2 because the agent socket path was too long;
the separate detached-signature verification itself exited 0 and produced the
expected VALIDSIG. This does not turn the repository's failed verifier into a
pass. No existing keyring or private key was accessed.

The regeneration control compares raw exports, while the mask cross-check
tests a finite arithmetic derivation. Neither establishes helper ownership,
concurrent scheduling behavior, a native Rust ADT ABI or complete transport
correctness. The final call beyond ordinary result paths remains an external
boundary. The evidence contribution deliberately leaves every component gate
and registered byte-coverage record unchanged.
