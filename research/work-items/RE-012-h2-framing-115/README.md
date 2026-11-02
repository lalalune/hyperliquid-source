# RE-012: node115 H2 length framing

This packet reconstructs the length-decoder state machine and its actual H2
constructor in independently authored, dependency-free Rust. It establishes
header/data admission, byte order, maximum-before-adjustment checks, distinct
arithmetic failure boundaries, skip and split consumption, and the H2 payload
limit/continuation relation. It does not implement asynchronous I/O or a node.

Target: Linux x86-64 node115,
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Task/component: RE-012 APIs/runtime dependency integration, with RE-005 framing.

The actual constructor uses a three-byte big-endian payload length, adds nine
bytes, skips zero and admits a configured maximum of16,384..16,777,215. Thus
three available bytes can enter Data state before the complete nine-byte H2
header arrives. A completed frame includes that header. The generic decoder
also preserves the different behavior of Head and Data states and empty frames.

Eight complete FDEs total4,613 bytes /1,067 instructions; the three primary bodies
total2,079 bytes. Fresh GNU/LLVM byte boundaries agree with Capstone. Thirty-seven
selected writers, actual data/source descriptors, 31 LSDA call-site rows and
seven selected direct/slot incoming sites are retained. The precise scope and
helper/memory premises are in [CONTRACT.md](CONTRACT.md).

The new [Rust component](../../../src/node115-h2-framing/README.md) is an executable
value projection over synthetic byte slices. Before its source was created,
28,360 expectations were frozen using independent integer/byte formulas. Four
Rust builds (1.94.1/1.95.0, opt0/opt3) match113,440 observations. Twelve compiled
mutants return normally and differ observably; four Rust unit tests pass.
Retained command logs are a replay of those observations, not a fresh build or
captured-node execution. Fresh own-Rust qualification is explicitly available.

Official pinned Tokio0.7.13/0.7.16 source functions are equal for six inspected
operations. Official h2 source corroborates the integration and maximum range.
Full sources and MIT notices are retained separately. These comparisons do not
identify an exact original vendored version, fork patch set or compiler recipe.
No historical94 source/artifact is a runtime dependency, and no unlicensed
inferred source was copied. Own ELF reader code was adapted from the earlier
CPU115 contribution and included locally; generic active tools are reused.

Eight focused methods pass both with bytecode disabled and under ordinary Python. Independent peer review rederives all28,360 cases and freshly checks all eight complete ELF bodies, 37 writers, 144 internal branches and31 LSDA rows without importing the author collector or oracle. Its exact62-member bundle and original ancillary failures are retained in the raw archive. It performs no new compiler or target run. Final repository check outcomes are in `validation.json`.
The full repository sweep passes on source head `cccf04c183363a2142b655956645ca8d9bd00d0e`: 77 files, 390 reported tests, three optional skips, exit0 in 890.510s. Test hashes are unchanged. The optional HL_RE014_LIBCORE and HYPERLIQUID_NONCE_RING_RUSTC qualifications were not supplied; the detected JDK has no separate nested JRE. Those three skips are not passed qualifications. Exact inventory and stdout/stderr are retained in the raw archive. Initial FDE schema-key and
Rust extern library-filename failures are retained, not hidden as successful
runs. No hosted CI, compiled-target byte match or progress-gate advance is claimed.

```sh
python3 -B -O research/work-items/RE-012-h2-framing-115/verify.py
python3 -B -m unittest tests.test_h2_framing_115 -v
python3 -B tools/h2_framing_115_static.py --export NEW_DIRECTORY
```

The packet verifier enforces a closed file/directory inventory, authenticated
target, exact native exports, source/fixture hashes and all retained own-program
outputs. No captured code or emulator, live socket, chain action or key operation
is performed. New code/docs: MIT, author 신준; coordinating attribution:
openai / gpt-6-astra / Codex0.166.0.
