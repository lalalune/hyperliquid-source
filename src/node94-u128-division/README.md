# Node94 two-limb quotient contract

This independently authored, dependency-free, safe `no_std` Rust component
implements the unsigned quotient data contract corroborated by the RE-004
node94 helper packet. It uses 128 steps of binary long division on two u64
limbs. It does not use u128 division, which could introduce a dependency on
the compiler runtime helper whose source is being reconstructed.

This is a new Rust interface and algorithm, not a recovered native ABI,
instruction sequence, compiler-library attribution or performance match.
`NonZeroWords::new` rejects a zero divisor before division. The captured
helper instead reaches hardware divide faults; no native trap is reproduced.

From the repository root, ordinary component tests need only an existing
Rust/Cargo toolchain; they do not invoke GNU/LLVM decoders or Z3:

```sh
cargo test --manifest-path src/node94-u128-division/Cargo.toml --offline --locked
```

This runs four focused tests and explicitly ignores the corpus until its
authenticated export exists. The evidence runner below sets
`NODE94_U128_VECTORS` and includes the corpus: five tests per profile, zero
ignored.

The optional target-backed evidence run additionally requires existing GNU
and LLVM objdump executables. `scripts/setup.sh` does not install these tools.
GNU objdump must be on `PATH` as `gobjdump` or `objdump`; LLVM objdump must be
on `PATH` as `llvm-objdump` or named by `LLVM_OBJDUMP`:

```sh
python3 tools/u128_division_rust.py --controls --output work/u128-rust-fresh
```

The runner authenticates an owned non-executable node94 snapshot, decodes the
complete helper independently with both providers, and repeats its existing
bounded instruction evaluation. Each result must equal the retained static
packet. A fresh per-case stream must match its original SHA-256 before Rust
debug and release compare both quotient limbs on all 159,431 cases. The count
includes repeats. The six native zero-divisor observations remain separate
from the Rust constructor's checked boundary.

The command checks formatting, Clippy with warnings denied, two clean offline
release builds, absence of i128 division/remainder instructions and division
runtime calls in the component's emitted LLVM IR, and compiling source
corruption controls. Use a new output directory; previous evidence is refused.
Successful compiler caches are removed between controls, retaining raw logs,
mutant sources, emitted IR and both actual release archives under `work/`.
Unexpected failures retain their build tree for diagnosis.

The separate RE-004 arithmetic verifier also requires an existing Z3
executable on `PATH` or supplied with `--z3`; setup does not install it.
These prerequisites are optional for ordinary Cargo tests. Explicit evidence
commands fail when a prerequisite is missing; a skipped proof is not a pass.

Existing Rust1.88 is the host component minimum. The root rebuild toolchain,
imports, reference pins and component gates remain unchanged. Finite agreement
does not prove all unsigned input pairs, target execution, caller behavior,
Linux build provenance or whole-node equivalence. See the RE-004 packet for
the actual target digest, decoder evidence, versions and remaining questions.
