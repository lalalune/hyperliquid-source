# RE-002: qualify node115's duplicated canonical field normalization

- Component: foundation allocation, public dependency/build provenance (RE-002),
  with function mapping (RE-001) and bounded arithmetic interpretation.
- Target: Linux x86-64 node **#115**, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Public source: `rust-bitcoin/rust-secp256k1` commit
  `6648126c69ce8056d053cbaa22246d12c76f3fc1`, MIT.
- Bounded question: which complete #115 bodies admit a source compilation
  witness for canonical five-limb field normalization, and when does their
  numeric result equal the input modulo the secp256k1 field prime?
- Claim status: observed two-body source correspondence; proved properties of
  admitted numeric equations; historical build identity and caller contracts
  remain unresolved. No component gate or registry change is requested.
- Intended files: this packet plus the generated README/banner work-item
  count. No implementation outside it, imported-input edits, submodule
  changes or retired-target dependency.

Two distinct complete **259-byte** bodies match the same isolated public-source
compilation, with **no normalization masks**:

| ELF VA interval, end exclusive | File offset | Direct E8 caller site | Enclosing caller FDE |
| --- | --- | --- | --- |
| `0x631d630..0x631d733` | `0x631c630` | `0x632565e` | `0x6325530..0x6325731` |
| `0x632c130..0x632c233` | `0x632b130` | `0x6337dbd` | `0x6337d80..0x6337f8b` |

Each body has SHA-256
`3cead16bae6d94fead58e2a6f7544fc470c9049fc267d4a3beb8cf379eeea994`.
The denominator is these two validated extents, **518/518 raw-equal bytes**,
not a component or function census. These are public dependency witnesses,
not first-party Rust reconstruction bytes.

## Gap addressed and evidence

The baseline's four registered dependency windows cover Zstandard, rust-core
and compiler-builtins. It has no admitted secp field-normalization window.
The authenticated #115 inventory reports `secp256k1` 0.29.0 and 0.30.0 and
`secp256k1-sys` 0.10.0. Those strings are leads, not proof assigning a version
to either body. This packet adds #115-specific body, FDE, caller, source-build
and arithmetic evidence without inheriting a historical release's addresses.

The public witness is the unchanged
[`rustsecp256k1_v0_10_0_fe_impl_normalize`](https://github.com/rust-bitcoin/rust-secp256k1/blob/6648126c69ce8056d053cbaa22246d12c76f3fc1/secp256k1-sys/depend/secp256k1/src/field_5x52_impl.h)
function. Unlike weak normalization, its second carry pass conditionally
subtracts the field prime: representing exactly `p` produces zero. It can
therefore support canonical storage/encoding boundaries, subject to actual
caller invariants still needing proof.

[observed/record.json](observed/record.json) retains full admitted body bytes,
section/PT_LOAD mappings, raw CIE/FDE records, complete caller extents, direct
xrefs, relocations, compiler identity and unmasked comparisons. Capstone
exports retain every instruction in both bodies and their two direct callers.
Independent GNU exports retain both target bodies and the compiled witness.
All addresses are ELF VAs; no loader or Ghidra base is guessed. GNU nearest
symbol annotations are not recovered function identities.

The unique FDEs agree with complete linear decoding, a final `ret`, thirteen
trailing `int3` bytes and the next FDE entry. Each helper has no branches,
helper calls, RIP-relative data references or code relocations. Literal
constants are embedded in its instructions. The full `.text` E8/E9 pattern
scan finds the two calls in the table, and decodes each enclosing caller to
confirm the call boundary. It finds no E9 entry references. This does not
cover indirect references, short jumps or all possible entry points.

Both callers accept an input through RSI and an output through RDI. They
normalize two consecutive five-qword regions at input offsets 0 and `0x28`,
using one inlined arithmetic sequence and one helper call, then pack them
into two 32-byte output regions. The first caller calls the first helper on
the second copied region; the second calls the second helper on the first
copied region. Their full exports support this bounded structural observation;
the inlined sequences and entire callers have not been source-built or formally
proved here. No original caller name, public-key type, full calling contract
or satisfaction of the field bounds is asserted.

## Source and actual build scope

[SOURCES.json](SOURCES.json) binds five complete public files to immutable
upstream Git blob IDs, byte lengths and SHA-256 values. The independently
queried tag, commit tree and selected blob records are retained in
[observed/upstream-provenance.json](observed/upstream-provenance.json).
Original copyright notices and `COPYING` are unchanged. They reuse the licensed witnesses from
historical packet commit `65a805949b74b3598988f3fb1fb6f241124d2692`; no retired
capture, inferred reference code or historical validator is required.
The source tag `secp256k1-0.29.0` resolves through tag object
`320b877a07c70acafbffe7498bb5516f02eeead3` to the pinned public commit above.

The translation unit selects one unchanged function, includes the unchanged
public `field_5x52.h` type, and uses the actual non-VERIFY macro expansions
witnessed in `field.h` and `util.h`. These remove optional assertions and
metadata fields under that documented public configuration. No helper is
stubbed and no captured bytes are compiled or transplanted.

Each fresh directory uses:

```sh
/usr/bin/gcc -std=c99 -O2 -fcf-protection=none -fkeep-static-functions \
  -c probe.c -o probe.o
```

GCC 13.3.0, target `x86_64-linux-gnu`, emits the complete named local FUNC as
the entire 259-byte allocated executable `.text` section. Two fresh complete
objects are identical, SHA-256
`22066bdba403ce7e47f029916d287eca99b33c045c249fbe74b3e6b73777614d`.
The only object relocation section is unwind metadata; no code operands are
masked. This is an isolated C source compilation witness, not a full secp
crate build, independent Rust implementation or recovered node build.
Original source/version selection, compiler/flags, unwind/link identity and
the reason there are two copies are not established by equality.

## Mathematical result and controls

[PROOF.md](PROOF.md) states the native equations and their bound argument.
[prove.py](prove.py), with `z3-solver==4.15.4.0`, checks those equations after
full target admission. For `B=2^52`, `C=2^32+977`, `p=2^256-C`, and unsigned
limbs satisfying

```text
input[0..3] <= 64*(2^52-1)
input[4]    <= 64*(2^48-1)
```

it returns **UNSAT** for a violation of either `0 <= N(output) < p` or
`N(output)=N(input)-((input[4]>>48)+final_selector)*p`, with
`N(a)=sum(a[i]*2^(52*i))`. Thus the numeric output is the unique residue.
It also proves the final selector is Boolean and the output remains below
`p` for arbitrary u64 inputs. Modular input/output congruence outside the
stated bounds is false: the removed-bounds solver returns **SAT**, and its
counterexample is replayed with ordinary integers.

The proof is of the retained equations. Opcode-to-equation interpretation
and compiler correctness are reviewed assumptions, not formally verified
ISA semantics. Valid readable/writable field memory, normal stack/return
behavior and no alias with saved stack state are assumed. Straight-line
code is not a security or microarchitectural constant-time proof.

Retained controls include:

- Two compiled counterfactuals: CET adds a four-byte prefix (263-byte full
  extent); changing `C` by one changes the 259-byte body at offset 2. Both
  fail whole-body comparison against both authentic helpers.
- An actual full-input byte mutation for each target body fails digest
  admission and also fails unmasked comparison independently of the guard.
  Counterfactual input digests are retained with unqualified provenance.
- Truncating the body by one byte fails the extent/equality check.
- Mutating the public source under the unchanged manifest fails admission
  before compilation. The admitted source files themselves are not modified.
- Advancing the arithmetic threshold by one exposes exactly `p` as an
  unreduced output. The solver returns SAT and integer replay confirms it.
- 160 magnitude-corner controls (125 distinct inputs) and nine integer boundaries include zero,
  `p-1`, `p`, `p+1`, `2p-1`, `2p`, and the 256-bit carry boundary. These
  finite cases supplement the theorem and are not captured execution. The
  full corner rows are retained in [observed/proof.corners.tsv](observed/proof.corners.tsv),
  whose hash is bound by the proof JSON.

## Reproduce and limits

Run from the repository root on Linux x86-64. Research dependencies are
`pyelftools==0.32`, `capstone==5.0.7`, and optionally for the proof
`z3-solver==4.15.4.0`; Python 3.13.12 and GNU binutils 2.42 were used.
The collector performs no downloads and runs only GCC/version queries.
The proof runs only the local solver. Neither script executes captured
instructions, generated object code, build hooks or a node service.

```sh
python3 research/work-items/RE-002-node115-secp-canonical/collect.py \
  --gcc /usr/bin/gcc --output work/new-node115-secp-canonical
python3 -O research/work-items/RE-002-node115-secp-canonical/collect.py \
  --gcc /usr/bin/gcc --output work/new-node115-secp-canonical-optimized-python
python3 research/work-items/RE-002-node115-secp-canonical/prove.py \
  --output work/new-node115-secp-proof.json
objdump -dr -Mintel work/new-node115-secp-canonical/build-a/probe.o
objdump -d -Mintel --start-address=0x631d630 --stop-address=0x631d740 \
  artifacts/node/115/hl-node
objdump -d -Mintel --start-address=0x632c130 --stop-address=0x632c240 \
  artifacts/node/115/hl-node
make doctor
make verify catalogue-check
mkdir -p work/secp-canonical-validation/tmp
TMPDIR="$PWD/work/secp-canonical-validation/tmp" make test
make reproduce
```

Transient objects, translation units, compiler streams and raw check logs
remain in ignored `work/`. Compact exports, raw comparison records and actual
validation results are retained in `observed/` and [VALIDATION.json](VALIDATION.json).
A different compiler may produce a legitimate negative result; no source
substitution, byte patch or operand mask makes it pass.

The explicit repository-local temporary directory keeps the catalogue test's
hard links on the capture's filesystem. The initial default-`/tmp` full run
completed with an EXDEV error in that test; its five-case retry passed after
this environment adjustment. The initial failure remains in the validation
record.

The complete repeat passed all **76 modules**, with **382 reported unittest
cases and zero failed modules**. Four optional/platform outcomes were skipped:
the explicitly supplied libcore archive, an opt-in nonce-ring compiler/Capstone
configuration, and two native macOS Java checks. Those skips are not component
build or behavior passes. `make doctor`, `make verify`, `make catalogue-check`
and `make reproduce` also passed; hosted CI and container success are not claimed.

Only the generated README/banner work-item count increases; no milestone,
byte registry or component gate changes. Full-component
helper/data/ABI closure, caller magnitude invariants, the inlined copies,
source-version uniqueness and whole-node equivalence remain open. Next,
qualify the storage callers' field bounds and packed-output semantics before
using the normalized words in a reconstructed signing/verification path.
