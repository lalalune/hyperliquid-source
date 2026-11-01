# RE-001: distinguish node reconstruction from dependency comparisons

- Scope: RE-001 inventory/accounting and RE-002 dependency attribution; no gate requested.
- Source baseline: `d3af7525` (2026-11-01).
- Node #94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Node #115: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Visor: `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Reference revision remains `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Status: observed section sizes and registered comparison counts; existing
  reviewed dependency attribution; unresolved full-component ownership/build.

## Bounded question and blocker

Can the README distinguish code that needs independent reconstruction from
already available dependencies, and state the measured scope of every number?

The RE-001/RE-002 work-selection view was misleading in two concrete ways:
all nine registered #94 windows were allocated to `foundation`, although their
reviewed sources are Rust runtime or Zstandard dependencies, and `N/A` meant
unmeasured rather than outside reconstruction scope. The main completion total
also combined the baseline node and separate visor. The displayed map did not
include source/license closure, integration, container or network acceptance.

Existing tools checked hashes and byte equality but had no dependency ownership
field and omitted visor from the byte-registry target inventory. The minimal
fix adds that field, excludes tagged dependencies from component counts,
includes the visor's measured zero-window target, and renders the separate
scopes. The audit also registers one previously accepted 198-byte division
window omitted from the old totals. No existing comparison bytes, masks, excerpts,
component acceptance gates or submodule pins were changed.

## Evidence and result

`evidence/observations.json` records the three target identities and exact
section counts. `evidence/*-sections.txt` retains independent GNU readelf output;
its `.text`, other allocated executable sections, allocated file-backed data
and NOBITS totals agree with the catalogue parser. `evidence/SHA256SUMS` pins
those files. Section addresses are ELF virtual addresses; offsets are file
offsets. Neither is a function-boundary claim.

| Target | Compared bytes | Raw matching positions | Windows | First-party registered windows |
| --- | ---: | ---: | ---: | ---: |
| #94 | 4,873 | 4,781 | 10 | 0 |
| #115 | 2,808 | 2,773 | 3 | 0 |
| Visor | 0 | 0 | 0 | 0 |

The #94 windows comprise six Rust core windows (2,060 bytes), two
compiler-builtins windows (395 bytes), and two Zstandard windows (2,418 bytes).
#115 has one Rust core window (390 bytes) and two Zstandard windows (2,418
bytes). Individual source/boundary/mask evidence remains linked from
`research/byte-windows.json`; its existing hashes and raw negative results are
unchanged. `component` retains the research allocation; `dependency` controls
separate reporting. This is not evidence that no other work exists, that all
these dependencies have been built from source, or that they are integrated.

The omitted [division leaf](../RE-002-u128-division-leaf-94/README.md) occupies
`0x565f5a0..0x565f666`. Its existing complete-FDE and official-archive records
establish 198 raw-equal bytes with no code relocations. Both official symbol
candidates have the same body, so only one interval is admitted. Source and
record hashes are now in the registry. The previous totals were 4,583/4,675
bytes and 4/9 raw-equal windows; the corrected totals are 4,781/4,873 and 5/10.
The additional window is still dependency attribution, not newly written Rust.

A bounded search of retained JSON for `raw_equal`/`raw_equal_bytes` also found
same-build reproducibility reports and already registered runtime comparisons.
Equal own rebuilds, target-to-target drift comparisons and data/vtable matches
are not silently converted to reconstructed first-party code. This search does
not prove every differently formatted or unregistered packet was inventoried.

The baseline has 23 declared node components and 92 full-scope gates; visor
has one component and four gates. All remain unaccepted. Whole-component byte
sizes and function counts remain unknown: a zero compared count does not turn
an unknown denominator into zero or establish zero correctness. Known ELF
section sizes do not assign individual instructions or data to a component.

## Reproduce

From the repository root, with its pinned submodules and LFS artifacts:

```sh
export PATH="$(brew --prefix binutils)/bin:$PATH" # macOS GNU tools already installed
make doctor verify
readelf --wide --section-headers artifacts/node/94/hl-node
readelf --wide --section-headers artifacts/node/115/hl-node
readelf --wide --section-headers artifacts/visor/captured/hl-visor
make catalogue
python3 -m unittest discover -s tests -p 'test_byte_progress.py'
python3 -m unittest discover -s tests -p 'test_research_tools.py'
make verify test catalogue-check
make reproduce
```

Recorded host: macOS arm64, Python 3.14.6, GNU Binutils 2.47.20260726.
No Ghidra analysis or target execution was needed. Initial doctor selected
Apple objdump and lacked readelf; putting the installed GNU tools on PATH
resolved it. Initial verification in the new worktree lacked submodules;
initializing the existing pins resolved it without advancing any revision.

Negative controls retain rejection of changed target/source hashes, overlaps,
bad bounds, malformed relocation masks and out-of-text windows. New controls
show that a dependency window counts once in target/dependency totals and zero
times in component progress; an unknown dependency label is rejected. Existing
gate tests still reject completion without evidence. Validation results are
recorded in `VALIDATION.md`.

## Remaining work

The [delivery acceptance criteria](../../../docs/SCOPE.md#source-built-network-node)
separate a usable source-built network node from whole-ELF identity research.
Public contracts and companion services are not extra private node components.
An open-source supervisor is needed only if that deployment uses one; direct
container startup must not be blocked on reproducing the captured updater.

No full node build, runtime image, live peer handshake, state synchronization,
or restart test was performed. The installed Docker CLI cannot contact a daemon
on this host; independently, the repository lacks an accepted integrated node
to put in that image. The next reconstruction question is the startup-to-peer
path under RE-012, including dependency and state prerequisites, not a wrapper
around the captured executable. Current-network compatibility also needs a
separate versioned acceptance run; historical #94/#115 matches cannot prove it.
