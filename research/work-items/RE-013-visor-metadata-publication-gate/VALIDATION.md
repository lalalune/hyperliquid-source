# Static validation

`validation-normal.json` and `validation-optimized.json` are identical results
from `python3 -B verify.py` and `python3 -B -O verify.py`. Each records:

- 10,455 selected target bytes and 1,878 instruction boundaries, fully matched
  by GNU and LLVM with no masking or prefix normalization.
- 72 negative controls: 46 fixed witnesses, one table, 18 call-slot RELA
  bindings, one imported symbol, four FDE extents, one structural nonvacuity
  control and one freshly native-decoded flag-store bypass.
- Two complete regenerated trees matching all 16 retained evidence files.
- All 256 raw-byte gate predicates, four paired equality-lane cases and
  65,536 sixteen-bit masks checked by finite algebra.

The 70 witness/table/RELA/symbol/FDE controls run below the whole-image digest
gate. They establish sensitivity of explicit bindings, not execution of the
mutated machine. The fresh-native control replaces bytes at VA `0x41654e`
with a jump to `0x416767` plus two NOPs, decodes that changed image with GNU,
checks its complete byte partition, and rejects the resulting ordinary-return
path because it bypasses the bit/error-store cutset. The separate synthetic
RET-at-entry graph control rejects a vacuous certificate.

The eight structural cutsets are nonvacuous in an overapproximating graph;
they do not evaluate registers, memory, branch predicates or helper behavior.
Finite algebra checks the manual XOR and paired-mask lemmas. Neither kind of
check substitutes for the producer dataflow, memcpy/preservation premises,
source/ABI identity, runtime reachability or cryptographic/filesystem policy.

GNU version: `GNU objdump (GNU Binutils) 2.47.20260726`. LLVM version:
`Apple LLVM version 21.0.0`. Native export input is one temporary read-only
snapshot, verified against the complete target SHA-256 before and after tools.
Only native decoders and Python parsers/graph/algebra operations execute.
No captured execution, emulator, instruction interpreter, project installer,
network behavior or full repository test suite is used.
