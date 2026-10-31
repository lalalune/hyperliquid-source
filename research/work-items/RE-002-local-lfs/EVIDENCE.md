# RE-002: initialize LFS in each repository that materializes pinned inputs

- Component: build-provenance/setup tooling; no completion gate requested.
- Question: do documented setup and `make pull` materialize the pinned inputs
  when Git LFS is installed without global Git filter configuration?
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
  Node #115 and visor are separate retained inputs checked by `make verify`.
- Changed entrypoints: `scripts/setup.sh` and the Makefile's `pull` target.
  Imported files, signatures, source pins and generated catalogues are unchanged.

## Observation and cause

A real fresh setup with Git LFS 3.8.1 and no global LFS filters downloaded the
retained artifacts, but the reference copy remained a 133-byte LFS pointer.
The parent repository's `git lfs install --local` does not configure a
submodule. Its subsequent `git lfs pull` exited zero while reporting:

```text
Skipping object checkout, Git LFS is not installed for this repository.
Consider installing it with 'git lfs install'.
```

Setup's final verification failed with `Pinned upstream mismatch` for the
node #94/reference pair. Installing LFS locally in the reference repository
before pulling restored the 91,774,280-byte file with the expected hash.
Standalone `make pull` also needs parent-local initialization when setup has
not previously run. The fix initializes exactly these two repositories; it
does not depend on or write global Git configuration.

## Reproduce

First materialize the source checkout using the corrected setup. The replay
requires Git, Git LFS, Python 3.10+, make and GnuPG. It clones the actual base
and all seven pinned references locally, copies their real cached LFS objects,
and uses an empty temporary global Git configuration with system configuration
disabled. No Git/LFS command or binary content is mocked. No captured program
is executed. Temporary clones and configuration are removed afterward.

```sh
mkdir -p work
python3 -B research/work-items/RE-002-local-lfs/reproduce.py > work/local-lfs-replay.json
```

The original macOS replay additionally used `sandbox-exec` with
`(version 1)(allow default)(deny network-outbound (remote ip))(deny network-inbound (local ip))`.
IP networking was denied; Unix sockets remained available to isolated GPG
verification. An initial runner that denied Unix sockets as well could not
verify signatures; that runner failure is not a product result.

## Results (original macOS record)

The adjacent `results.json` retains actual command output, target sizes/hashes,
tool versions and the reproducer's SHA-256 from the original macOS run. It is
preserved unchanged, including its then-unobserved hosted-CI flag. Later Linux
qualification is recorded separately below.

| Authentic cached-clone condition | `make pull` | `make verify` | Node #94 parent/reference sizes |
| --- | --- | --- | --- |
| Base, neither repository configured | 0 | 2, artifact mismatch | 133 / 133 |
| Base, only parent configured as in setup | 0 | 2, pinned-pair mismatch | 91,774,280 / 133 |
| Candidate, both locally initialized | 0 | 0 | 91,774,280 / 91,774,280 |
| Candidate repeated | 0 | 0 | 91,774,280 / 91,774,280 |

Both candidate files match the full target SHA-256. All seven submodule
commits and clean contents, source input hashes, and the empty global config
are checked unchanged. Successful verification includes all retained artifact
hashes/signatures and the imported-file/source-pin checks.

On the working checkout, corrected `scripts/setup.sh` completed successfully.
`make doctor verify test catalogue-check` passed on base after manual local
configuration and on the candidate: analysis ready, 431 tests passing, and
catalogue consistency passing. The replay proves the differing fresh-config
behavior; the broader suite checks for regressions.

## Limits and next question

This is a local setup correction, not a reconstruction or equivalence result.
No Rust implementation, function-boundary or target-behavior claim is made;
address coordinates and normalization masks are inapplicable. No progress
gate changes. Static verification does not establish node safety. The original
macOS record did not include hosted CI, Windows or Linux runs; the subsequent
fork-side Linux results below do not rewrite that record. Windows remains
untested. Existing custom LFS hooks can still require operator resolution;
initialization is not forced. The replay needs already cached inputs and does
not test a remote LFS service or missing-cache recovery. A full Linux
`scripts/setup.sh` invocation remains a separate next check.

## Later Linux qualification — October 30, 2026 (Phoenix)

Both fork-side Ubuntu 24.04 runs completed successfully:

| Run | Exact source | Observed result |
| --- | --- | --- |
| [Original workflow](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41163962997) | PR product revision `51cac6d7626accb406a42676f6c8cb01738c756e` | 431 tests; artifact hashes/signatures, 37 imports and source pins; catalogue/index checks, pinned REA smoke and `make reproduce` pass |
| [Fresh-LFS replay](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41164312513) | Fork-only CI revision `a550be505741a83c776a8a87014c9206e14a627d` | Same checks pass, followed by all four expected local-LFS replay phases |

The auxiliary revision changes only `.github/workflows/verify.yml` relative to
`51cac6d7626accb406a42676f6c8cb01738c756e`. Its three measured product-file
SHA-256 values match that PR revision and the original `results.json`:

| Product file | SHA-256 |
| --- | --- |
| `Makefile` | `dadc584e4ff42dbcd65b9d1442a49f580e8dbfdf7ce8985bd278eb9fd5d7fb28` |
| `scripts/setup.sh` | `a628ee2fa75c7fbf6fe26ee03370543c377bbbb7062d1029371f093908c1f4d8` |
| `research/work-items/RE-002-local-lfs/reproduce.py` | `ec39892ed34c2171c1bcf7a0122a6354a3874324c3db6cf7229467ec396fae74` |

The Linux amd64 replay uses genuine cached objects and Git LFS 3.8.1:

| Phase | `make pull` exit | `make verify` exit |
| --- | ---: | ---: |
| Base, neither repository configured | 0 | 2 |
| Base, only parent configured | 0 | 2 |
| Corrected initialization | 0 | 0 |
| Corrected initialization repeated | 0 | 0 |

Both successful phases restore full 91,774,280-byte parent/reference files with
the target SHA-256 above. The isolated global configuration and all seven
submodule pins remain unchanged. The replay run retains its normalized JSON
as the `pr118-local-lfs-replay-linux` workflow artifact.

These results qualify the two named revisions, not a later documentation-only
head. They are fork-side results, separate from the upstream workflow's
maintainer gate. They do not establish a full Linux `scripts/setup.sh` run,
remote LFS availability/outage behavior, Windows support or Linux IP network
isolation. No captured executable was run; no node build, equivalence,
security-clearance or completion-gate claim follows from these checks.
