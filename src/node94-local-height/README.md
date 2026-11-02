# Selected node #94 startup height decisions

This independently authored `no_std`, safe Rust module implements two numeric
decisions already established by the maintained
[local-state gate packet](../../research/work-items/local-abci-gates-94/README.md).
It turns existing static findings into buildable code, without claiming new
function discovery or a complete startup state machine.

`select_heights(count, values)` takes the values of an already collected map,
one entry per distinct peer. Empty values fail selection; a single value is
accepted only if exactly one peer was queried. Otherwise it returns the
unsigned lexicographic maximum of `(initial, latest)`. Both words come from
the same value. For example `(10, 100000), (11, 12)` selects `(11, 12)`,
not the synthetic pair `(11, 100000)`.

`classify(local, selected)` implements these ordered exits:

1. `local.saturating_add(20000) <= selected.latest`: `TooFarBehind`.
2. Otherwise `local < selected.initial`: `StaleHardfork`.
3. Otherwise `Continue` through this selected window.

`Continue` does not mean the node accepts the state. The state-age gate, map
construction, peer requests, iterator invariants, allocation/error handling,
async resume states and downstream consumers are excluded. Callers must supply
the map-value slice with valid backing memory; raw word inputs need not describe
a reachable node state. The Rust interfaces/types are new, not recovered ABI.

## Build and validate

No dependencies, Cargo workspace, build scripts or lockfile are needed. Use the
research compiler `rustc 1.94.1`; this is not a recovered full-node build recipe.

```sh
mkdir -p work/local-height
rustc --edition=2021 --crate-name node94_local_height --crate-type=rlib \
  -D warnings -C overflow-checks=on -C opt-level=3 \
  src/node94-local-height/lib.rs -o work/local-height/libnode94_local_height.rlib
rustc --edition=2021 --test -D warnings -C overflow-checks=on \
  src/node94-local-height/lib.rs -o work/local-height/unit-tests
work/local-height/unit-tests
python3 -B research/work-items/RE-012-local-height-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/local-height-validation --controls
```

The validation output directory must not already exist. The runner authenticates
the entire node #94 capture, reuses the existing byte/data/FDE checks and compares
three separately built Rust runners against 25,135 scalar cases. It receives
input words only, while Python retains the expected answers. Eight compiled
semantic mutants must disagree. The selected LLVM and Capstone listings have
matching instruction byte boundaries; the decoder text remains review input.

See the [implementation evidence packet](../../research/work-items/RE-012-local-height-rust-94/README.md)
for actual results, reproduction, provenance and environment limitations. No
captured code is executed or emulated, no original machine code is transplanted,
and no original ELF equality, runtime equivalence or component gate is claimed.
