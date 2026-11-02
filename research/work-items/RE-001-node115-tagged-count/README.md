# RE-001: migrate the tagged-count search lead to node #115

- Target: node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source lead: PR #2022 at `d70f538728d2cee6e09ca912f09bd7b1ea5dd18c`.
- New observed ranges: `0x1531940..0x1531985`, `0x1768140..0x1768185`,
  `0x2b77ea0..0x2b77ee5`. Each is a complete 69-byte FDE with no LSDA.
- Scope: the identical scalar value relation only. No caller, object identity,
  original Rust type, ABI, whole-node equivalence or component gate is claimed.

The submitted byte pattern was a search lead. Each match was independently read
from the authenticated #115 binary and checked against its own FDE. The three
bounded GNU exports preserve all instructions. No old address was reused.

The full-width `test rax,rax` selects the zero arm. Otherwise `cmp eax,1`
tests only the low 32 bits. The one arm zeroes RAX, performs unsigned subtraction
in RCX and conditionally moves that result with `cmovae`, so borrow produces
zero. Every arm compares the selected result against the word at offset 0x28
and uses `cmovb` for unsigned minimum. The paths terminate at their own `ret`.
The bodies contain no calls; native object validity remains a precondition.

`vectors.tsv` was frozen before the Rust source existed. Its 2,058 rows exercise
zero, one, high-word-set tags, underflow, unsigned extremes and the cap boundary.
The independent Rust API accepts raw values, not a native object pointer.

```sh
python3 tools/node115_tagged_count.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-tagged-count/Cargo.toml
```

The original submitted #94 caller census is not adopted. Identical local bodies
do not establish shared callers or meaning in three different object contexts.

Fresh validation: **2,058 frozen cases at both opt-level 0 and 3**, with zero
mismatches. Compiled full-width-tag and wrapping-subtraction mutants both
fail the fixture test. `migration-validation.json` records this run. Reproduce
with `python3 tools/node115_tagged_count.py --build-dir work/tagged-count-check`.
