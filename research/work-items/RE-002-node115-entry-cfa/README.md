# RE-002: how often does canonical frame setup predict RBP-based unwind state?

In node #115, 1,142 of 135,313 unwind ranges start with a push of RBP immediately followed by a move of RSP into RBP, allowing one leading ENDBR64. Every one of the 1,142 has an RBP-based canonical frame address (CFA) at the next instruction. The pattern detects 1,142 of 1,629 ranges that use an RBP-based CFA anywhere. The full entry survey therefore answers the local machine-code question without identifying the original Rust frame-pointer flag.

The [prior census](../RE-002-node115-cfa-frame-policy/README.md) independently reconciled GNU and LLVM CFA rows across all ranges and disassembled seven selected intervals. The [build-provenance record](../RE-002-build-provenance/provenance-115.json) asks for a prologue survey. This packet joins the entry instructions of **every** frame description entry (FDE) to the CFA states for that same FDE. It also measures whether one compiler flag can produce ambiguous machine evidence using independently authored Rust code.

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base: `2da45cb0a761cff6b478e40421699857d87a94df`.

| Entry instructions after optional ENDBR64 | Never RBP CFA | RBP CFA somewhere |
|---|---:|---:|
| Push RBP, then immediately set RBP from RSP | 0 | 1,142 |
| Push RBP without immediate setup | 37,537 | 96 |
| Other entry | 96,147 | 391 |
| Total | 133,684 | 1,629 |

The 1,142 matches comprise 832 plain and 310 ENDBR64-prefixed setups. Of the 487 RBP-CFA ranges missed by the prefix, 365 already have an RBP-based CFA at their first PC. The other 122 develop it later. For example, the range at `0x5d16b00` starts with a push but no immediate setup. The range at `0x5d3521c` already has an RBP-based CFA before its first decoded instruction. [survey.json](survey.json) retains one example per observed category, with entry bytes, VAs and first RBP CFA row, and hashes the complete ordered per-record classifications.

**Predicate.** From the FDE start, Capstone decodes at most three x86-64 instructions within the interval. It accepts one optional ENDBR64, then requires the decoded instructions `push rbp` and `mov rbp, rsp` in Intel operand order. An intervening NOP, reversed move or move split by the FDE end fails the predicate. Both equivalent MOV encodings pass the unit control; only `48 89 e5` occurred here. The implementation authenticates the ELF, independently parses each FDE and its CIE binding, checks that native CFA records have the same offsets and VAs, and reproduces every aggregate cell in the prior CFA/saved-RBP census before accepting the join. It maps loaded VAs to executable section file offsets. The CFA at the instruction following setup is the latest defined state at that PC.

## Controlled compiler experiment

Cross-compile two known Rust inputs to Linux x86-64 object files with pinned rustc 1.95.0, changing only `-C force-frame-pointers=no/yes` for each pair. The GNU ELF relocation for the sole FDE binds it to the named complete code section. [control.json](control.json) contains the exact compiler arguments, emitted instruction bytes, full-object hashes and unwind-state rows.

| Source | Flag off | Flag on |
|---|---|---|
| A rotate followed by wrapping addition | 9-byte leaf, RSP-based CFA | 14-byte leaf, RBP-based CFA after setup |
| A 64-byte-aligned local array whose address is passed to an external declaration | 51-byte body with frame setup and stack realignment | Same complete relocatable object, SHA-256 `8d5f4d9be966f1442cfd3a324983c14f6ac6d916fd01385978be1d8e1e654e26` |

The aligned-buffer case produces identical evidence under opposite flag values even with the source, compiler and target known. The ordinary leaf shows that the compiler did honor the switch for the other input. Neither fixture corresponds to a node function, and the external declaration is never linked or called. Ranges can describe fragments, alternate entries or non-Rust code. This evidence establishes no object ownership, function-count denominator, original compiler settings, performance, or first-party coverage.

## Replay

From this packet directory with the authenticated node materialized, GNU binutils, Python and Capstone 5.0.7 available, and rustup 1.95.0 with its x86_64-unknown-linux-gnu standard library installed:

```sh
export PYTHONDONTWRITEBYTECODE=1
python3 survey.py
python3 control.py
python3 test_classifier.py
```

The recorded run used arm64 macOS, Python 3.14.3, GNU binutils 2.47.20260726, Capstone 5.0.7 and rustc commit `59807616e1fa2540724bfbac14d7976d7e4a3860`. Both analysis commands accept `--readelf` for installations with a non-default GNU tool path. The survey creates a temporary full native unwind export; the compiler control creates four temporary ELF objects. The captured target and compiler outputs are read as data. Five focused tests check instruction semantics and the entry/end boundaries.
