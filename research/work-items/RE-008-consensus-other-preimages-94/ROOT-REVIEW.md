# Independent integration review

The root reviewer read the conditional native proof, expectation generator,
protocol, real package graph, production module, driver and tests. A separate
peer reviewed the complete native bodies and independently reconstructed all
534 preimages, then reviewed the source and retained build streams. The missing
ordinary memcpy copy/frame premise was corrected transparently in
`POST-FREEZE-PROOF-CORRECTION.json`; no expectation was changed.

The author freeze is `490ecd132a6a684a4019a71e5b36864299b35e78185b8aaa02dff1a034168be2`.
Its original 115-entry manifest was
`9a0c93a1491ec8bbcd196c5b81f68ba31db750f59c70e80db2f971809e95b73a`.
The root checked every entry and all six owned source hashes before adding this
review and its receipts to the final manifest. Author and pre-code freezes remain
unchanged; root additions are later integration evidence.

## Actual independent rerun

Root ran `verify.py --out NEW_DIR` and `build.py --out NEW_DIR` separately from
the author. The static receipt is byte-identical to `validation.json`: 38 full
FDEs, 19,172 bytes, 4,655 rows, 619 instruction/eight data obligations, two
regenerations, 55 rejected controls. The Rust results are identical except for
the documented public toolchain-path substitution. All 12 compressed and raw
result streams match the retained author streams byte-for-byte.

Both debug and release return all 534 expected preimages, sizes and digests.
The actual crate tests pass 37 unit, nine existing evidence and seven new
integration tests per profile; doc tests contain zero cases. Clippy passes
with `-D warnings`. Every one of the 46 root commands exits zero. Root's actual
normalized command streams are retained in `root-rust-commands.json.gz`.

Root also independently compiles and runs all ten release mutants. Their
mismatch counts are 203, 203, 25, 533, 143, 8, 92, 143, 3 and 116 in the order
listed in `VALIDATION.md`. These are mismatches against the frozen mathematical
expectations, not observations of an executed captured node. No target code,
instruction evaluator, signing, networking or chain action was run.

`make doctor verify catalogue-check reproduce` subsequently exits zero on the
integration checkout with pinned Rust and GNU tools plus explicit LLVM objdump.
Doctor reports analysis ready and exact rebuild not ready. The imported refined
counts remain grounded822/drift60/notes116/late1/unanchored386/partial56/case11.
The unrestricted test suite includes captured-instruction evaluators and was
not run. Hosted CI and full component completion are not claimed.

## Concurrent contribution and distinct result

The final live audit found [PR #1444](https://github.com/lalalune/hyperliquid-source/pull/1444),
head `bf42b0fbe481c5198c5e8bf6e0bee10aeec49e6d`, which independently documents the
same timeout tag-2 writer/sizer projection. That static timeout result overlaps
and is explicitly credited; it is not claimed here as an exclusive discovery.
A read-only comparison of its proof, 19 selected spans, 18 owner hashes,
FDE/CIE records, transfers, ten RELA records and data against the authenticated
ELF found no conflicting field/order/limb/stride/status/size assertion. Its
serialized-size equation equals this packet's timeout preimage length minus29.
No external contribution code was executed or copied.

This contribution adds the actual three-message Rust value API to the existing
component, complete heartbeat and acknowledgement projections, explicit claimed
signers, size equations and prefix/multiblock hash composition, with one shared
pre-code oracle and independently repeated native Rust qualification. PR1444
does not add Rust or close the hash composition. Keeping this family together
provides a reviewable implementation result without another timeout-only PR.
There is no dependency on PR1444, unmerged QC-vote PR1391 or bincode-wrapper
PR1365. Existing baseline providers and their conditional native Keccak identity
remain explicitly credited. The existing authenticator trait is unchanged.

The live audit retained full changed-path lists for all 46 other PRs1420–1466,
plus earlier campaign snapshots; this does not claim absence of private work.
The post-freeze proof, final source and all expectations stayed unchanged during
these checks. Stable memory/tree metadata, exact-copy and allocation/frame
premises remain material; no signature recovery, native tree construction,
original ABI or unconditional permutation-equivalence result is implied.
