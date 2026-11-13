# Observed local validation

Execution `8943ff0f9fe8d195521677571066b29a` on pinned base
`a8616af9432b8d8517b2af677880e117b7c28ef3`:

- `python3 -B research/work-items/RE-012-tcp-transform-error-cleanup-115/verify.py`:
  actual capture authenticated; all 10 selected clause groups, 3 FDE/CIE
  records and 2 unique relocation writers passed.
- `python3 -B -m unittest discover -s tests -p test_tcp_transform_error_cleanup_115.py -v`:
  all 6 test methods passed in 4.443 seconds. Subtests cover 10 clause-byte
  corruptions, 3 FDE corruptions, 3 CIE corruptions and 2 relocation corruptions;
  CIE tests include the shared CIE once for each associated owner.
- `make doctor`: passed; analysis_ready=true, exact_rebuild_ready=false.
- `make verify catalogue-check`: passed before addition of the final packet
  manifest; post-manifest verification is run separately below.
- `make reproduce`: passed; reproduced node115 and visor static inventories.
- Python 3.11.11; GNU binutils 2.40; no captured binary executed.

Earlier execution `057cca41c3437ef04c5a2de630800526` passed the original five
methods before CIE controls and explicit relative-destination decoding were
added. It is not the final proof result.

Final local execution `4c2bcc8073ad1f09ad158f81047aaa25`:
- `make catalogue` regenerated only research inventory counts (3706 -> 3707),
  not implementation/component gates;
- post-manifest `make verify catalogue-check` passed (3728 manifests,
  29758 entries, zero dangling rows);
- all 6 scoped test methods passed again in 4.514 seconds;
- `git diff --check HEAD` reported no whitespace errors.

Independent reconstruction/validation and the full root suite remain pending.
Local tooling success is not target execution, native equivalence, hosted CI,
maintainer acceptance or a completed component gate.
