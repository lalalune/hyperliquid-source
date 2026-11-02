# Client batch and retained buffer implementation

The actual baseline `node94-consensus-admission` crate gains a complete typed
batch verifier and persisted buffer operation. It uses existing admission rules
and baseline MIT Keccak, with a required time-bearing authentication adapter.
Failed proof validation preserves the appended block and advanced receive counter;
a successful flush confirms and clears pending before ordered sink attempts.
Closure retains an accepted prefix while dropping the returned item and remainder.
The prior direct-call `0x1a` unreachability inference is corrected by the frozen
empty-stake two-call witness (`0x28`, then `0x1a`, with no authenticator calls).

Review the active contract and limits in [PROOF.md](PROOF.md), the source mapping
in [SOURCE-PROOF.md](SOURCE-PROOF.md), and the input-only protocol in
[PROTOCOL.md](PROTOCOL.md). Bulk native exports and raw execution streams support
those documents. This is one project's evidence; multiple decoders or reviewers
do not make the native correspondence unconditional or independently sourced.

The original 53-file pre-Rust freeze and independently frozen 221 input/expected
cases are unchanged. Both first source builds stopped at command13 with `E0308`:
the existing Keccak API returns `ConnectionId`, while the new code assumed a raw
array. No first-attempt tests or values ran. The additive
[amendment](amendment-1/AMENDMENT.md) preserves both complete failed receipts and
original source, client and harness. Six public `as_bytes()` projections correct
that type assumption; no expected byte, calculation, native proof or API contract
was changed. The correction and new runner were frozen and reviewed before rerun.

The amended author run passed 158 commands: 150 exit0 and eight expected exit2
parser/argument rejections. Both debug and release passed 37 library tests and
10 new integration tests, followed by exact agreement for all 221 frozen outputs.
A clean same-path repeat matched both value streams and all six raw artifact
identities (admission rlib, dependency rlib and client in each profile). The parent
comparator rejected eight corruptions; the client rejected seven malformed inputs
and an extra argument and accepted the empty input stream. Clippy passed over the
actual targets. The old `evidence_contract` runtime test and the full repository
suite were not run by this focused harness.

All 20 independently compiled behavioral faults differed from the expected
transcript in both profiles. Each mutant completed normally with all 221 outputs;
no compilation failure or crash was counted as detection. Mismatching case counts
are equal across debug/release:

| Fault | Cases |
|---|---:|
| Untimed signer | 202 |
| Permit an earlier proof | 5 |
| One-sided QC round check | 1 |
| Invent first-parent anchor | 9 |
| Invent consecutive batch rounds | 12 |
| Compare only31 transaction digest bytes | 1 |
| Count before transaction hashing | 1 |
| Ignore transaction order | 1 |
| Check only first time word | 8 |
| Omit last digest repeat | 115 |
| Omit child digest repeat | 32 |
| Wrap child successor | 1 |
| Roll back receive counter on error | 3 |
| Clear pending on error | 3 |
| Permit101 unconfirmed rows | 2 |
| Apply proofless limit to proof flush | 1 |
| Confirm after sends | 7 |
| Retain pending during flush | 7 |
| Ignore closed sink | 4 |
| Verify proof QC before child | 115 |

[AUTHOR-RECHECK.json](rust-validation/AUTHOR-RECHECK.json) independently recounts
44 complete value runs and all 316 stdout/stderr references (91 unique streams).
Exact raw bytes are retained; only command/environment metadata uses logical
paths. The first failed runs retain another 52 references. The 97-file toolchain
pin set, copied graph, original precode, selected linker/SDK inputs and actual
source admission were checked before/after the amended run. The full host OS and
SDK are not hermetic, and a same-path repeat does not establish different-directory
raw binary identity.

The [coordinator replay](rust-validation/ROOT-COMPARISON.json) completed the same
158-command qualification in a different directory. All 44 value streams and
mutant mismatch counts matched the author. It rehashed all 684 raw references
across both failed and both amended runs, plus 264 retained build artifacts.
Admission rlib, dependency rlib and client bytes **differed across the author and
coordinator directories in both profiles**. Each run's same-path repeat matched.
The inequalities are retained without normalization or an established cause.
The packet includes complete author raw streams and both failed raw archives;
the coordinator comparison records its separate command/result hashes.

[DISTRIBUTION.json](DISTRIBUTION.json) records the authorized final application of
exact corrected module bytes to the real crate after both build outcomes. The
final actual 28-file graph matches the effective amended source freeze. No
recompilation is asserted or needed for this byte-identical distribution step.

Final reproduction uses the frozen `build_amended.py` entry point and
`SOURCE-FREEZE-2.json` SHA256
`f3c47e8257eaada2f227b7710cad612fc9146086b2dffe7c3ba9eb932f3fe9f9`:

```sh
python3 -B build_amended.py --toolchain <PINNED_1.94.1_ROOT> \
  --out /tmp/client-batch-amended-reproduction \
  --source-freeze-sha f3c47e8257eaada2f227b7710cad612fc9146086b2dffe7c3ba9eb932f3fe9f9 \
  --private-map <FRESH_PRIVATE_PATH_OUTSIDE_PACKET>
```

The runner admits exactly the original or declared public-corrected module,
reconstructs the archived original real graph, then applies the pinned type patch
to each build copy. It therefore reproduces from a clean public checkout with the
corrected crate. Original `build.py` and its source freeze are historical artifacts.
No captured binary, instruction evaluator or emulator runs. Full block preimages,
cryptographic recovery/proposer selection, competing failing TC children, outer
poll reset/reconnect reachability, native channel linearizability and unwind or
allocation-failure equivalence remain outside the conditional native contract.
