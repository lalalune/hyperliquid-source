# RE-001: safe Rust reconstruction of the node94 two-stream mixer

The previous packet established a static rule but explicitly left Rust
unimplemented. This contribution adds a complete safe slice/value version of
that rule, including odd lengths, middle overlap, seed order and both halves
of each product. It does not establish the function's source-level identity.

- Component: `foundation`; bounded RE-001 reconstruction following the existing
  [static packet](../foundation-multiply-xor-mixer-loop-94/README.md).
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
  Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No unlicensed inferred implementation was read or copied for this work.
- Scope: complete FDE body `[0x16488e0,0x1648946)`, 102 bytes and 30
  instructions; safe input slices on 32/64-bit Rust targets, related to valid
  nonwrapping mapped native buffers. Ten following `int3` bytes are padding.
- Excluded: native pointer ABI, arbitrary raw length/pointer values, source or
  hash identity, caller ownership, native execution, native differential
  comparison, machine-code equality, node integration and component gates.

Only `src/node94-two-stream-mixer/` and this new packet change. The old packet
and `src/node94-keyed-mix/` (a different body at `0x399c600`) remain untouched.
The prior author's unretained 5,062-case interpreter is historical reporting,
not a reproducible result used here. No captured instruction evaluator ran.

## Static evidence and complete dataflow

`static_evidence.py` authenticates the entire ELF, then resolves ranges through
the ELF section table. `static/records.json` retains the body, hashes, CIE/FDE,
relocation and slot bytes. `static/gnu.txt` and `static/llvm.txt` are fresh raw
disassembly exports. Their complete instruction byte partitions agree, with
no normalization. These are two decoders of target data, not rebuilt-code
comparisons. The bytes are evidence only and never linked into the Rust build.

All addresses here are linked ELF VAs. The body maps to file offset
`0x16478e0`. The FDE at VA `0xd0210c` (`.eh_frame+0x20bf4`) names the exact
start and endpoint; its CIE is at `0xce1518`. A full existing FDE parser and
fresh GNU frame output independently agree. The following FDE starts at
`0x1648950`. FDE evidence is combined with complete decoding, three internal
branch targets and a terminal RET; no stride is substituted for body length.

The RELA scan covers 80,300 entries. Exactly one record names this function:
`.rela.dyn` file offset `0x1b9488`, slot VA `0x57709e8`, `r_info=8`
(`R_X86_64_RELATIVE`, symbol index zero), addend `0x16488e0`. The slot's raw
eight file bytes at `0x576e9e8` are **zero**. Relocation semantics establish its
load-base-relative target; the file contents alone do not. Its consumer and
purpose remain unknown. No complete incoming xref census is added; the old
packet's direct-call pattern result does not establish absence of callers.

| Instruction group (inclusive endpoints) | Established effect |
| --- | --- |
| `0x16488e0`, `0x16488e3` | R9 receives seed A from RCX; RCX receives seed B from RDX. |
| `0x16488e6..0x16488f0` | R11 becomes raw RSI AND `0x7ffffffffffffff0`. |
| `0x16488f3` | Zero R11 branches directly to final xor. |
| `0x16488f5..0x16488f8` | RSI becomes base RDI plus the raw length's low nibble. |
| `0x16488fb` | Alignment NOP. |
| `0x1648900..0x1648907` | RAX = RSI + R11; unsigned RDI >= RAX exits to final xor. |
| `0x1648909..0x1648915` | Multiply `(A xor LE64(front+8))` by `(LE64(bound-8) xor key)`, unsigned 64x64→128. |
| `0x1648918` | Preserve the first product's low half in R10. |
| `0x164891b..0x1648923` | Form `(B xor LE64(front))` and `(LE64(bound-16) xor key)`. |
| `0x1648926` | Preserve the first product's high half in R9 before the second MUL overwrites RDX. |
| `0x1648929..0x164892f` | Second unsigned product; B receives its high xor low half. |
| `0x1648932` | A receives the first high xor saved low half. |
| `0x1648935..0x164893d` | Advance front by 16; reduce R11 by 16; repeat iff R11 is nonzero. |
| `0x164893f..0x1648945` | Return A xor B in RAX. |

The body has no calls and no stores to input or external memory. The key in
R8 is unchanged. The two lane updates depend on their own previous state;
the first product's RDX value must be saved before the second multiplication.
Little-endian loads are potentially unaligned, including backward loads when
the length has a nonzero low nibble.

## Relation to the safe slice API

`two_stream_mix(input, seed_b, seed_a, key)` deliberately preserves the native
seed order while replacing pointer and raw-length arguments with a slice.
This is a value API, not a declaration of the stripped binary's source type.
Valid Rust byte slices on supported 32/64-bit targets have length at most
`isize::MAX`; the native relation additionally assumes the mapped interval
`[base, base+n)` does not wrap. Thus bit 63 is zero in the related native
length. Native raw values with bit 63 set and wrapped addresses are outside
the API's claim; none are quietly mapped to a shorter slice.

Write `n=16q+r`, `0<=r<16`. At entry to potential round `j`, induction on the
native instructions gives:

```
front = base + 16j
R11   = 16(q-j)
RSI   = base + r
bound = RSI + R11 = base + n - 16j
```

The initial zero test and subsequent loop-back test admit exactly `j<q`.
The unsigned meeting test additionally requires `32j<n`. No pointer operation
in those rounds wraps under the stated premise. The Rust loop maintains
`front=16j`, `back=n-16j`: its `back>=16` is equivalent to `j<q`, and
`front<back` is equivalent to `32j<n`. The source has both tests; the lower
bound prevents short slices from entering a round.

For `n<16`, q=0 and both versions return the seed xor without reading memory.
For `n>=16`, q is at least `ceil(n/32)`, so the count is `ceil(n/32)`.
Each admitted j reads `[16j,16j+16)` and `[n-16(j+1),n-16j)`. Since `j<q`,
both spans are within `[0,n)`. Each source addition/subtraction and each
eight-byte load is therefore within the slice; no unsafe pointer or unchecked
index operation is needed. At most `n` is reached by `front+16`, so index
arithmetic does not overflow on the stated Rust targets.

The two spans need not be disjoint. For n=17 they overlap by 15 bytes. For
n=32 the next meeting test exits with front=back=16. For n=33 a second round
reads `[16,32)` and `[1,17)`; rounding the tail down would change the result.
For n=47 the second spans are `[16,32)` and `[15,31)`. For n=48 both second
spans are `[16,32)`. The algorithm intentionally rereads middle and previously
visited bytes in these cases. A disjoint-chunk or half-buffer traversal is
not a valid replacement.

Let `F(x,y) = low64(x*y) xor high64(x*y)`, with unsigned multiplication, and
`W(k)=LE64(input[k:k+8])`. For each admitted j:

```
A[j+1] = F(A[j] xor W(16j+8), key xor W(n-16j-8))
B[j+1] = F(B[j] xor W(16j),   key xor W(n-16j-16))
result = A[last] xor B[last]
```

Rust implements the two exact products with `u128`. There is no truncation
before folding their high halves. For `[0,3]` as little-endian qwords, seed
A=`2^64-1`, seed B=0, key=0, product A is `3*(2^64-4)`:
low=`2^64-12`, high=2, xor=`0xfffffffffffffff6`. Swapping the qwords and
putting the all-ones seed in B exercises the second high half independently.
With qwords `[1,2]`, seeds B=5/A=3/key=0, the answer is 6; `[1,2,3,4]`
gives 8; `[1,2,3,4,5,6]` gives 77 after the shared middle round.

## Frozen oracle and native checks

`oracle.py` was authored from the complete decoded dataflow and frozen before
writing the Rust files. It uses a fixed round count and reduction over paired
indices, weighted-byte integer loads, and base-2^32 schoolbook multiplication.
The Rust code instead uses front/back guards, native little-endian conversion
and u128 products. The oracle does not read Rust, old interpreter outputs or
instruction operands. It is a mathematical model justified by the static
argument, not an independent target execution. A shared error in that argument
is still a limitation; these tests do not establish native equivalence alone.

`fixtures/freeze.json` binds the target, oracle source and separate
`inputs.tsv`/`expected.tsv` files by SHA-256. The 1,774 cases comprise seven
hand calculations, two patterns for every exact length 0..512, bytewise
perturbations at 11 meeting/overlap boundary lengths, 256 varied cases of at most
4096 bytes and nine lengths around 1024/4096/8192. Seeds include zero, one,
32-bit and sign-bit boundaries and all ones. No user or runtime data appears.

`verify.py` first regenerates and checks the immutable fixture files. It builds
the separate library and input-only client with Rust 1.94.1 at opt-level 0 and
3, twice per level in different directories. The client only receives inputs
on stdin; it has no expected-output path, embedded answers or access code for
expectations. The Python parent compares ID/order/count and all output bits.
All four runs pass 1,774/1,774, with zero mismatches. Rlib and Mach-O client
hashes agree between the repeated builds at each level. This is host build
reproducibility, not Linux x86-64 target byte identity.

Twelve separately compiled opt3 source mutants are all rejected by ordinary
output disagreement: discard each high half independently; swap seeds; use
big-endian loads; discard the length residue; omit the overlap round; omit
the meeting guard; omit each lane's key xor; change forward lane selection;
change backward lane selection; return A alone. Each mutant compiles, exits
normally and produces all 1,774 rows. Counts and first witnesses are in
`native/result.json`. All 16 raw output streams are retained losslessly in
`native/raw-streams.json.gz`, a single deterministic JSON archive with zero
gzip timestamp and per-stream names, lengths and SHA-256 values. Packaging
was checked against the original result hashes without recomputing outputs.

Twenty-eight static corruption controls pass. Besides the whole-file digest,
they exercise body, FDE/CIE, padding, relocation type/symbol/slot/addend and
zero-in-file slot checks below the full-file digest gate. Body mutations are
rejected by the exact body witness, not claimed as semantic mutant execution.
Four comparator controls reject an altered value, omitted row, duplicate row
and reordered rows. No corrupted captured code is executed.

## Reproduce and actual environment

Observed host: macOS arm64; Python 3.14.3; GNU binutils 2.47.20260726; Apple
LLVM objdump 17.0.0; rustc 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8). Cargo manifest and lockfile contain no third-party dependencies.
There is no root Cargo workspace. All native executions are the newly authored
client/library or their deliberate source mutants.

From repository root, use a fresh output directory:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 research/work-items/RE-001-two-stream-mixer-rust-94/oracle.py
python3 research/work-items/RE-001-two-stream-mixer-rust-94/verify.py --check-archive
python3 research/work-items/RE-001-two-stream-mixer-rust-94/verify.py --out work/two-stream-review
cargo +1.94.1 build --offline --locked --manifest-path src/node94-two-stream-mixer/Cargo.toml
rustfmt +1.94.1 --edition 2024 --check src/node94-two-stream-mixer/lib.rs src/node94-two-stream-mixer/client.rs
make doctor verify catalogue-check reproduce
```

The archive check can run without rebuilding and the normal verifier also
checks it. Decompressing the archive with Python's `gzip.decompress` yields
JSON whose `streams` entries contain the unchanged ASCII `text`. The raw
decoder exports retain their original whitespace through packet-local Git
attributes. The verifier's source mutations and exact compilation commands are retained in
`native/commands.json`. Flags are edition 2024, codegen-units=1,
overflow-checks=yes, panic=abort, debuginfo=0, denied warnings and a build-path
remap. `static_evidence.py --out <directory>` independently regenerates the
four static exports. The eight existing focused tests in
`tests.test_foundation_multiply_xor_mixer_loop` also pass; they statically
inspect bytes and evaluate the pre-existing mathematical rule, not captured
instructions. Their temporary target copies were confined to an automatically
removed temporary directory. Final `make doctor`, `make verify`, `make catalogue-check`, `make reproduce`,
Cargo offline build and rustfmt checks pass. Doctor reports analysis readiness,
not exact whole-target rebuild readiness. The clean import-verification result
is in `logs/verify-clean.log`; catalogue/reproduction and focused-test results
are retained alongside the earlier environment failures.

Development corrections are recorded rather than hidden: the first collector
mistakenly expected the function VA in the raw slot; direct byte inspection
showed eight zero bytes and the separate RELATIVE record. An initial Cargo
invocation could not locate rustc on PATH and did not compile; selecting the
installed compiler explicitly passed. Initial doctor found Apple objdump and
no readelf; putting installed GNU binutils first on the command's PATH fixed
that environment selection. The initialized reference submodule first held an
LFS pointer and then appeared modified after materialization; the parent task
restored its local LFS clean-filter/object state without changing the gitlink
or source-tree hash. Final import verification was rerun after that repair.
No system-wide configuration was changed.

## Limits and remaining question

The native compiler may call its platform's u128 multiplication support or
slice-panic machinery. We do not identify those with target helpers or claim
a machine-code match. No captured program, emulated instructions, networked
service, chain action, signing or model-backed program was run. Hosted CI,
Docker and a whole-node build were not tested. The parent task owns the full
repository test sweep; this packet reports its own focused and component
checks only. All acceptance gates and byte-window registries remain unchanged.

The remaining question is which consumer uses relocation slot `0x57709e8`
and what domain it supplies. That caller closure is necessary before claiming
the safe slice contract describes every native call site.
