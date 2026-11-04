# RE-012: node115 normal-return command program and argument construction

Component: foundation; task RE-012. Sole target Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Original ELF virtual
addresses, no rebasing or normalized bytes. New reconstruction and evidence
are MIT; bundled dependency provenance and LICENSE are preserved.

## Question and implementation

What program classification, owned bytes, argv pointers and NUL state do the
complete selected constructor and argument appender produce on normal return?
The independently authored `src/node115-command-construction` supplies that
bounded state with genuine owned storage and an actual local CString dependency.
It does not implement process execution or the whole native Command object.

The primary complete FDEs are constructor **0x5c94cb0..0x5c95025** and
argument appender **0x5c94bb0..0x5c94ca2**. The retained context
`0x1535fd0..0x153661e` contains actual constructor/argument calls, including
slot `0x64e0ee8` -> `0x5c94bb0`. Both selected helpers call the actual CString
entry through slot `0x64df718` -> `0x141e960`; its complete constructor and
finalizer extents are retained as supporting dependency context.

## Observed normal-return state

The constructor classifies **the original input bytes before conversion**:

| Original bytes | Raw program kind |
| --- | ---: |
| First byte is `/` | 2 |
| Another `/` occurs | 1 |
| No slash, including empty input | 0 |

The classification includes bytes after an interior NUL. Backslash is not a
separator in these Unix branches. These numeric observations do not by
themselves close path search, executable resolution or later launch behavior.

A successful CString conversion supplies an owned buffer with one trailing
zero. An interior NUL conversion error instead selects the exact **18-byte**
placeholder `<string-with-nul>\0` and sets the NUL-seen byte. The original
classification is retained even when the program is substituted. The target
placeholder bytes are pinned at `0x44c079`.

Program bytes and argv[0] have **separate owned allocations with equal contents**.
The constructor establishes an argv sequence containing the argv[0] pointer
and a null terminator. Native selected stores bind the independent program
pointer/length at object+0x80/+0x88, raw classification at +0xc3, and NUL flag
at +0xc0. These local observations do not assert a stable public Rust ABI.

Each normal argument append:

* Converts its bytes or owns the same NUL placeholder.
* Sets the NUL flag when conversion encounters NUL; a later valid argument
  does not clear an already-set flag.
* Replaces the prior final null pointer with the new argument pointer and
  appends another null pointer, growing the pointer storage when needed.

The new library owns its buffers in safe Rust containers and constructs an
actual pointer vector. `arguments_with_nul()` includes argv[0], so k appended
arguments produce k+1 owned argument buffers and k+2 argv entries including
the terminator. Moving an inner Vec descriptor during outer-container growth
preserves its owned byte allocation. The probe checks the actual produced
pointers; it does not substitute a list of expected pointer-like integers.

## Genuine pinned CString dependency

Cargo resolves `node115-owned-cstring = =0.1.0` through the local `cstring/`
path. It is a real buildable dependency, containing the independently authored
MIT converter from contribution head
`5b0d012a8329ae6b3c9aba849fe13bea3b625246`, original path
`src/node115-owned-cstring/src/lib.rs`, source SHA-256
`bfb169d3ad619f4e65a4b9d68a581964637e079018169a5bedffca1e8e33272c`.
`ORIGIN.json` pins this identity and the original LICENSE is retained.
The snapshot makes the main-based contribution reproducible while that
independent contribution is unmerged. No stub, fake Cargo graph or guessed
registry version stands in for the converter. Its primitive credit belongs
to the original contribution.

The converter actually allocates/copies, rejects the first interior NUL with
its owned copy, or appends the reserved terminator. This command library maps
InteriorNul to the observed placeholder. Allocation failure reaches an
explicit local panic boundary; its behavior is **outside** the normal-return
claim, together with placeholder/clone/vector allocation failure and native
panic or unwind states. No atomic rollback guarantee is introduced.

## Frozen expectations and actual compiled qualification

`oracle.py` is a declarative byte-level relation for original-input kind,
converted/substituted contents, sticky NUL flag and argv entry count. It does
not evaluate captured instructions or invoke a process. `freeze.json` records
**4821 unique program/argument cases**, generated while the new Rust directory
was absent. The deterministic gzip/hex fixture decompresses to SHA-256
`3f970b00dfcd75dc7082b95f099a194147103e46583cd07be4aa628be210ea5d`.
The oracle and static scope source hashes are also frozen and rechecked.

Qualification builds the actual Cargo graph, including that immutable CString
source, in both **debug and release profiles**. Each production executable
exited **0** and matched **all 4821 rows**. The fixture covers empty/raw-byte
inputs, slash and backslash classifications, short/word-scan boundaries,
interior NUL positions and multiple argument sequences. This is a bounded
static-oracle comparison, not captured-node execution or complete process
compatibility.

Seven real source mutants were separately compiled with the same dependency:

| Mutant | Observed exit | Detection |
| --- | ---: | --- |
| Wrong leading-slash kind | 0 | Output mismatch, first row 240 |
| Backslash classification | 0 | Output mismatch, first row 32 |
| Wrong placeholder | 0 | Output mismatch, first row 3 |
| Reset sticky NUL flag | 0 | Output mismatch, first row 13 |
| Program/argv[0] pointer alias | **101** | Probe ownership/pointer assertion failed |
| Missing final null pointer | **101** | Probe terminator assertion failed |
| Classification after substitution | 0 | Output mismatch, first row 16 |

Thus **five controls exited normally with mismatched output and two were
caught by assertion failure**. They are not reported as seven normally
exiting behavioral mismatches. Actual physical-pointer assertions were added
**after the source existed**; they are extra ownership controls, not frozen
pre-Rust pointer addresses or independent target-runtime evidence. Raw
compiler/stdout/stderr results stay under ignored work; durable hashes and
observed outcomes are retained in `validation.json`.

The inspected host build, Linux x86-64 release-library build and Clippy logs
all finished successfully. The Linux artifact is an rlib, inspected as
ELF64 x86-64 relocatable members; it was not linked into or executed as a node.
Root publication also observed a separate successful `cargo fmt --check`;
its empty successful log is hash-bound in `validation.json`. Parent publication
performs its applicable final repository checks.

## Static evidence and reproduction

Five complete FDE exports total **3344 bytes / 823 instructions**: the two
command helpers, the two CString helper contexts and the actual higher-level
caller context. Export sizes are not reconstructed or matched byte totals.
`records.json` binds exact bodies, actual FDE/CIE bytes, LSDA addresses,
81 calls, 130 branches and encountered relocation writers. It retains dynamic
edges and unclosed allocator/growth/caller behavior.

GNU objdump, LLVM objdump and Capstone agree on complete instruction-byte
partitions; GNU readelf independently confirms all five extents. The focused
verifier rejected **16 actual instruction-anchor mutations, one placeholder
mutation and two wrong/truncated capture controls**. Narrow anchor checks are
performed independently of the whole-file identity guard. No additional
relocation-mutation controls or whole-program helper closure are claimed.

From repository root with the pinned local toolchain:

```sh
python3 -B research/work-items/RE-012-command-construction-115/verify.py
python3 -B research/work-items/RE-012-command-construction-115/qualify.py work/fresh-command-qualification
cargo +1.95.0 build --offline --locked --manifest-path src/node115-command-construction/Cargo.toml
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-command-construction/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-command-construction/Cargo.toml -- -D warnings
```

Only independently authored Rust probes execute. No captured binary,
instruction interpreter, process launcher, filesystem or network action was
used. No native struct equivalence, environment/stdio setup, executable
resolution, spawning, exit-status semantics, allocator/unwind equivalence,
hosted CI, container or whole node is established. All 92 component gates
and registered byte-comparison totals remain unchanged.
