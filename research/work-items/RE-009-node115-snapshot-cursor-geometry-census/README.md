# RE-009: snapshot cleanup cursor geometry census

The two cursor layouts in #7183 and #7186 are members of a broader compiler-emitted family in the pinned #115 image. A 27-byte entry signature matches 211 sites. Each maps to an FDE start with length 938. Within that denominator, 83 sites also match all five instruction prefixes at the exact offsets used by this cursor form. Those sites contain 34 distinct operand tuples. The retained table records the key count offset, selected successor slot displacement, parent index offset and two release-size operands.

The first two mapped shapes differ at every selected field. The other 128 sites remain unclassified because at least one of the selected instruction forms differs. A prefix match establishes a candidate and FDE boundary, but neither it nor five matching opcodes establishes complete behavioral identity, call reachability or the semantics of other fields.

From the repository root, run python3 research/work-items/RE-009-node115-snapshot-cursor-geometry-census/verify.py with llvm-dwarfdump on PATH and compare stdout with geometry.tsv. The five negative controls change the source opcode at each of the selected positions and require rejection. No target instructions execute.
