# Owned comparator footprint guard repair

The inherited decimal interpreter reload/spill methods access synthetic memory
directly. Overriding only load/store did not guard those paths. At the original
node115 instruction0x2d1d7c1 (4989442428, MOV[R12+28],RAX), an intentionally
out-of-footprint synthetic state pointer wrote8bytes into the comparator's
dictionary instead of failing. The original capture itself was never written
or executed; this is an owned verification-harness defect, not a node security
report. Exact prior head81b99d0c and source hash/before-after result are in
guard-review.json; original lossless logs remain external.

Both methods now use the existing footprint check. A regression interprets
that actual store instruction and tests direct spill/reload rejection before
any synthetic memory change. Valid native8952input/full/semantic streams and
coverage remain identical after the change. All18existing actual corruption
controls still pass, including the15semantic/3width-only distinction.
Explicit image cleanup also removes the independently reported unclosed-file
ResourceWarnings. Owned Rust and frozen original expectations are unchanged.

Six focused tests PASS2.125s; canonicalnative replay+tests exit0/16.662s.
This followup is part of PR2327, not a new contribution counter increment.
The exact-head full suite on separatePR2334/eb0b4600 completed77files/389
reported cases/0failed with2optional skip reports. All76common baseline test
source hashes and the tools tree match here, but that receipt is not an exact
full-suite execution on this different packet/head. The six focused tests and
current packet/catalogue checks are separate observed results.

Run python3 tools/verify_packets.py from repository root for these repository-
relative manifest entries. Running sha256sum from the packet subdirectory
without changing its root does not resolve those paths; the independent
review's resulting missing-file errors are not evidence of hash corruption.
