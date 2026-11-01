# Exact-tree validation

All commands ran from the repository root. Full local streams remain in ignored `work/row-selector-checks/`; the receipt below preserves their exact output identities.

| Command | Exit | Output bytes | Output SHA256 |
| --- | ---: | ---: | --- |
| `make doctor` | 0 | 1972 | `2bce4e007979e8a9c2afb7a3c8db3a0978054610e255cad04b2d31303eddf28c` |
| `make verify catalogue-check` | 0 | 756 | `4d6919f9e2d8ab98f1a1233b01aa40d0e415b3b6978338c374dbbbf1b2ee699e` |
| `make reproduce` | 0 | 12396 | `08ec436df402ddae68cd72a53774ca9a7d2fcb5487171fa908a0c6bdf49d45ba` |
| `python3 -B -m unittest discover -s tests -p test_row_lookup_default94.py -v` | 0 | 1550 | `0b0e0dc1a42f90afe5d802cc1ea6e3c6d74bc1937b19a4d3d30b6f99cebd6c73` |
| `python3 -B -m unittest discover -s tests -p test_row_selector_rust94.py -v` | 0 | 1038 | `9f1595d2b3cd9ec6c6bbc1906ee50f0c422afa8036fb7fc6f807f20b51ee7caa` |
| `python3 -B research/work-items/RE-007-row-selector-rust-94/observed.py` | 0 | 728 | `a0ff834baebd4ebb0a8c980c55afb2b7e70af857f9e829d9cadb16e7dd3d3c0a` |

Input/pin checks inherited invocation-local standard Git LFS filters only: `filter.lfs.clean=git-lfs clean -- %f`, `filter.lfs.smudge=git-lfs smudge -- %f`, `filter.lfs.process=git-lfs filter-process`. No persistent configuration or pinned input changed.

The pinned compiler is Rust1.94.1, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, executable SHA256 `ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`. The full compiler/Cargo/rustdoc identities, all58 command exits and116 original stdout/stderr channels are losslessly retained under `observed/`. The retained report SHA256 is `dd21ad34cbdcda443e9582fb34247e8d6bd959976aedb47c2305456a991b39d5`.

Exact-tree results: four901-case authored-Rust comparisons (894 conditional native-posthash plus7 new API-policy cases each),10 normal-value native-relation mutants,3 API-error-label mutants,5 malformed-driver controls,40 existing component tests in each profile,14 comparator/snapshot controls and21 native anchor corruptions pass. The original lookup9 and new replay6 Python tests pass. No captured execution or emulator ran.

Rustfmt and Clippy are not present in the approved compiler/std/Cargo bundle; those checks were not run or installed. Repository-wide `make test`, hosted CI and component completion gates are not claimed. Independent reviewer reran the manifest, actual-output replay and6 focused tests, and accepted the checked wrapper/corpus partition without rerunning the compiled suite.

## Preserved preparation failures

Before the final freeze, the first shallow ignored snapshot failed Cargo integration-test compilation with exit101 because its repo-relative external `boundaries.tsv` include escaped the snapshot. The next original-layout snapshot passed all40 component tests but Cargo exited101 when `rustdoc` was absent from PATH. Fresh freezes retained the exact base-pinned include and explicitly selected the already installed official rustdoc; neither correction changed the qualified selector relation. Original failed streams remain in ignored `work/row-selector-compiled-v1/` and `work/row-selector-compiled-v2/` of the separate draft worktree. The final tracked-source run has no failing command.


## Final archive packaging

The gzip payloads are stored as strict base64 text to avoid new Git LFS objects. Decoding reproduces the original gzip bytes and the same report/stream SHA256 values above. All retained streams contain local synthetic driver/component outputs and build diagnostics only. No private reserve-path material or credentials are included.

- `observed.py --archive-from work/row-selector-built-main-v1`: exit0; output SHA256 `80aec5f28f085ff938142842d5894889605f7ab812c14ff7a39542d48ced36c6`.
- `observed.py`: exit0; output SHA256 `a0ff834baebd4ebb0a8c980c55afb2b7e70af857f9e829d9cadb16e7dd3d3c0a`.
- `python3 -B -m unittest discover -s tests -p test_row_selector_rust94.py -v`: exit0; output SHA256 `106eebe485faa50ed207fa602f35b00b6c39a771cff16d08122a9ec39522e24e`.
