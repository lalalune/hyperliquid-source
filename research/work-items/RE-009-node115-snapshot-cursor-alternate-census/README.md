# RE-009: classify the remaining snapshot cursor operand forms

The first cursor census in #7187 classified 83 of 211 FDE-bound candidates. Applying that same detector alongside two additional forms separates the remaining 128 into 123 shifted-opcode sites and five short-displacement sites. Every prefix-matched candidate has exactly one matching form. The new TSV contains only the 128 previously unclassified sites with the five concrete geometry operands. Example entries 0x166cfe0 and 0x244dbc0 check the shifted and short forms, respectively.

The census validates those selected operands and function boundaries. It does not establish whole-body equivalence or reachability. Run python3 research/work-items/RE-009-node115-snapshot-cursor-alternate-census/verify.py with llvm-dwarfdump on PATH and compare stdout to geometry.tsv. Ten negative controls reject opcode mutations over the new forms. No captured instructions execute.
