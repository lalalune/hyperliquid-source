# RE-002: select a supported Node later in PATH

## Question and observation

Can the pinned REA launcher use an already installed supported runtime when
the shell's first Node is incompatible? Main `1f8c67c63ca4794c9689235471c60297f8a5c985`
queries only the first PATH match. With real Windows Node **24.12.0** first
and **24.22.1** later, `python tools/rea.py --version` exits 1 and asks for a
supported runtime. The same checkout and pinned **rea-agents 6.8.0** return
`6.8.0`, exit 0, when the later runtime is selected with `REA_NODE`.

`docs/REA.md` says the launcher selects a supported installed Node rather
than inheriting an incompatible shell default. Enumerate the PATH entries
in order before the existing fallback locations. Preserve the preferred nvm
location, the first supported runtime, and a strict explicit override. No
user PATH, registration, package pin or provider setting is changed.

## Reproduce

Install the existing package lock with a supported Node and lifecycle scripts
disabled, as documented in `docs/REA.md`. Supply two existing executables:

```sh
python research/work-items/RE-002-rea-path-runtime/probe.py \
  --first /path/to/node-24.12.0 --later /path/to/node-24.22.1 \
  --out work/rea-path-runtime.json
python -m unittest discover -s tests -p test_rea_launcher.py -v
```

The probe invokes the real pinned package's `--version` only. It does not
install dependencies, register an agent, start a provider or open a target.
The captured before/after files use Windows / Python 3.10.11, actual Node
24.12.0 and 24.22.1, and rea-agents 6.8.0. The supported executable has SHA-256
`b59feb2088f80e1fa431c8f9c316861e660e5936f968fd97b802e550fed356c5`.

Before: automatic selection exits **1**; explicit supported selection exits
**0**, output `6.8.0`. After: automatic selection exits **0**, output `6.8.0`;
an explicit incompatible override still exits **1**; explicit supported
selection still exits **0**. The source-tool hashes are in the JSON files.

The two regression cases use explicitly declared executable version-protocol
fixtures, not actual Node. Before: one pass and one expected `ValueError`
error. After: two pass on Windows. They exercise real process lookup and
version reads, including first-supported priority. The actual CLI comparison
above separately verifies the supported runtime and real REA package.

## Validation boundaries

The original Windows seven-case launcher suite has **5 pass, 1 failure and
1 error**. The unchanged provider-environment assertion expects POSIX slash
spelling, and the target-identity case sees an unmaterialized 133-byte LFS
pointer. Both original results are retained outside the packet. They are not
passes and are not the new PATH regression. Full native repository validation
belongs to the exact tested commit's Linux check record and PR description.

This is RE-002 analysis-tool setup. Node #94 remains the baseline artifact,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
the reference remains `999556f6e0a474b8312db96ec3149e1c44e97c23`. Neither is
read or executed by the runtime-discovery probe. #115 and visor remain
separate. Addresses, ABI/layout, Rust implementation/build equivalence,
native provider analysis and component progress gates are not claimed.

Next step: maintainers run the launcher with their installed runtime order
and review the exact-head checks. The tool still fails when no supported
runtime exists or when the explicit override is incompatible.
