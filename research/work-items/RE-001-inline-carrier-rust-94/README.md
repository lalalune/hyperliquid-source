# RE-001: admitted inline carrier in the existing alias component

This adds `inline_carrier(&[u8]) -> Option<u128>` to `src/node94-alias`.
It reconstructs the constructor's admitted 0..16-byte route through the
checked recursive packer. The low 64 bits project native RAX and the high
64 bits project native RDX. It preserves embedded and trailing zero bytes;
the integer has no separate length. Existing alias-feed/hash behavior stays
unchanged. No new crate, workspace, dependency or lockfile is introduced.

The earlier merged `RE-001-short-string-94` packet discovered the constructor,
packer and little-endian recurrence; `RE-001-short-string-alias-94` supplies
the existing feed/ten-letter implementation. Those native discoveries and
bytes are credited. The new result is the missing admitted carrier behavior
implemented and compared in an existing component, not new owner-byte credit.

## Artifact, complete bodies and call boundary

Node #94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

| Credited role | Complete FDE extent, exclusive end | Bytes | Body SHA-256 |
| --- | --- | ---: | --- |
| Constructor | `0x1449a80..0x144a009` | 1,417 | `722081a7f180ea0975defbc65814bdd65eb76a10534a8dfa6c64f101ac5516c3` |
| Recursive packer | `0x144a010..0x144a069` | 89 | `e5786bcf006e4207862b5b8985c2a9ba7fd7488c171b9e86a5cc6a137b35ccdb` |

`native.json` retains exact indexed FDE/CIE records, LSDA pointer, full hashes,
the unique `R_X86_64_RELATIVE` slot `0x576f5f0 -> 0x144a010`, constructor
tail jump `0x1449af2`, recursive call `0x144a026` and credited generated-form
call `0x1449cd9`. Whole-image admission is unmasked. Complete GNU 2.44 and
LLVM 19.1.7 exports are retained and every exported byte is rebound to the ELF.

The constructor has 315 GNU rows and 323 LLVM rows: LLVM emits eight off-route
LOCK prefixes separately. The initial all-constructor row-equality assertion
failed for that reason. All eight differences are explicit in `native.json`;
both exports cover the same 1,417 bytes. The admitted constructor entry/short
tail and all 25 packer rows agree exactly. No raw export or captured code
byte is normalized, and no long-constructor semantics follow from its binding.

Fresh intake checked 206 full open PR bodies before the Rust edit and found
no selected address/component/inline-carrier claim. `ownership.json` records
the terms and base. Refresh ownership before any publication.

## Selected native contract and proof

At `0x1449a9b/9f`, unsigned length<=16 selects `0x1449adf`. That block clears
index EDX, restores the constructor frame/nonvolatile registers and tail-jumps
through the authenticated slot, preserving pointer/length inputs. It reaches
no cache, allocation or lock helper on this route.

The packer compares index and length at `0x144a018`. Equality returns zero
in RAX/RDX; greater index goes to an excluded bounds helper. Otherwise it
zero-extends the current byte into EBX, increments index, and recurses through
the same slot. RBX's saved byte survives that recursion through PUSH/POP.
Given the returned 64-bit pair `(lo,hi)`, the native normal unwind requires
`hi >> 56 == 0`, then computes:

```text
next_hi = ((hi << 8) | (lo >> 56)) modulo 2^64
next_lo = ((lo << 8) | current_byte) modulo 2^64
```

The byte load is unsigned. RCX preserves the recursive high half across the
overflow check; SHLD provides the low-to-high carry. Return moves RCX to RDX.
For a constructor-admitted input, each recursive suffix contains at most 15
bytes before its parent shift, so its high half is below `2^56`. Induction
from the zero base gives `sum(byte[i] * 2^(8*i))` for the initial index zero.
All values fit in 128 bits. Empty input performs no byte load. At most 17
packer invocations are needed, conditional on valid protected stack storage.

Rust uses a fixed-width reverse fold over u8 values; it performs no allocation
or unsafe access. The projection requires immutable valid bytes and ordinary
normal calls/relocation, protected input versus live recursive frame/control
storage, and no concurrent mutation. It does not reproduce original pointer,
struct or return ABI, invalid-index/fault/unwind behavior or stack exhaustion.

Length17+ returns `None` only in the new API. Native construction takes its
long cache/alias route instead; this is neither a native error nor full
constructor behavior. Accepted identifier grammar, string identity, display,
wire format, long cache ownership/allocation/locking and complete foundation
reconstruction remain open. No component gate or progress record changes.

## Frozen expectations and real compiled outputs

`PLAN.json` and the component's `evidence/inline-carrier-vectors.tsv` were
frozen before Rust. The fixture SHA-256 is
`8f42424e6dbebe4f4d832d813f9cb88f511fa05a534556d1f8d0169fee810d68`.
There are 156 admitted native rows: every length0..16, all128 one-bit
positions, 1/8/15/16-byte zero/ff boundaries and explicit trailing-zero pairs.
Two additional rows test only the chosen API's long-input refusal.

Expected low/high words come from the width-explicit two-u64 recurrence and
are independently checked by an unbounded little-endian integer sum. Neither
oracle imports Rust or executes/evaluates captured instructions. Five inert
native operand controls change length admission, indexed byte source, each
shift or overflow guard; all have concrete scalar-relation counterexamples.
Leaving the normal inline relation assigns no behavior to opaque helpers.

`input-only.rs` receives only IDs, lengths and bytes on stdin and calls the
actual production library. Its stdout carries status and both full u64 words.
The Rust process receives no expected path, bytes or answer environment. The
qualifier builds fresh library/driver products, checks dep-info names exactly
those two source files, and compares actual stdout pipes with the frozen
expectations. All compiler-read project sources and fixture bytes are pinned
before/after; every mutant derives from the same fixed source snapshot.

`comparison.json` records the real builds, source/input/provider hashes,
commands, actual stdout hashes and first mismatch for each control. The
authenticated TEXT bundle `raw-streams.json` contains authored inputs,
expected/actual outputs, compiler stdout/stderr, dependency logs, source-hash
manifest and recipes. Its current decoded payload is 7,984 bytes with an inspectable
156-file list. It contains no executable, rlib, object, captured artifact or
duplicate native-body/source blob. It is decoded only as inert data. Scoped
source text omitted from the bundle is checked against the original snapshot
manifest. The original full binary archive remains private under ignored work/.
See `RESULTS.md` for exact observations and remaining verification limits.

## Reproduce

Use the existing official Rust1.94.1 compiler/std/Cargo, with `RUSTC` and
`RUSTDOC` pointing to that installation. No installer or network dependency
fetch is needed. From the repository root:

```sh
cargo build --offline --locked --manifest-path src/node94-alias/Cargo.toml
cargo build --release --offline --locked --manifest-path src/node94-alias/Cargo.toml
cargo test --offline --locked --manifest-path src/node94-alias/Cargo.toml
cargo test --release --offline --locked --manifest-path src/node94-alias/Cargo.toml
python3 -I -B research/work-items/RE-001-inline-carrier-rust-94/verify.py
python3 -I -B -m unittest discover -s tests -p test_inline_carrier_rust94.py -v
python3 -I -B research/work-items/RE-001-inline-carrier-rust-94/verify.py \
  --qualify work/inline-carrier-fresh
(cd research/work-items/RE-001-inline-carrier-rust-94 && sha256sum -c MANIFEST.sha256)
make doctor verify catalogue-check reproduce
```

The qualifier refuses an existing output directory. It creates only authored
Rust products and inert data under that fresh ignored path. The older alias
runner's captured-instruction evaluator is not run by this follow-on.

## Source history and requalification

The original inline source, snapshot and receipt are preserved at commit
`743257a699da958290d18dd89825c7a1804f58b8`; `historical.json` binds those
historical bytes. The separate key-hash extension changes whole-file Rust
pins, so current `comparison.json`/`raw-streams.json` contain a fresh rerun of
the same 156 native rows, two API refusals and six source controls on the actual
changed source. [RESULTS.md](RESULTS.md) separates the historical comparison
from this current-source requalification. It does not reuse the old receipt
as evidence for the changed lib or count the new key-hash cases as inline work.
