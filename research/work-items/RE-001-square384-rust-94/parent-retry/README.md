# Complete optimized retry after storage recovery

At the parent's request, the implementation worker ran the unchanged committed
validator in a fresh directory with Python `-O`. The exact command, tested
commit, unchanged source/oracle/freeze/verifier hashes and exit0 are retained in
`record.json`. This is a complete worker retry after the interrupted independent
parent run, not a claim that the parent's interrupted process completed.

All9,592 cases matched in each of four opt0/opt3 correct builds and repeats:
38,368 full register/word/image/status outputs. All35 compiled mutants exited
normally and differed. All178 static, five comparator and two archive controls
passed, with identical repeated build artifacts.

`result.json`, `commands.json` and `qualification.log` preserve this run's result,
exact compilation commands and raw completion log. Its result JSON and complete
39-stream raw archive are byte-identical to the original complete qualification.
The archive is retained once at `../native/raw-streams.json.gz`; both this run's
39 exact stdout streams and the reconstructed shared archive were checked before
deduplication. `record.json` binds that shared archive's SHA-256. No source,
oracle, fixture, static binding or validator change was needed.
