# Historical compiler-input boundary

The selector was compiled at commit `54735068738b50c515b09550b78164c12762107d`
against freeze `3474586b1550900b5fc8f4edaa10c78d0c733d256abfaf8933a177a86503f146`.
Its original report, all actual streams, inputs, expected outputs and selected
Rust module remain unchanged. The report SHA256 is still
`dd21ad34cbdcda443e9582fb34247e8d6bd959976aedb47c2305456a991b39d5`.

The next RE-007 task adds the actual fixed20 hash module and its library export.
With only those two source changes, the previous whole-component current-tree
test failed before any new hash behavior was compared:

```text
python3 -B -m unittest discover -s tests -p test_row_selector_rust94.py -k exact_current -v
exit 1: live component has missing/additional source inputs
output SHA256 286dfafb49639fecf5ed1047d9cb81b79fd91471c0eab957af06ef8412cf44dc
```

This was a test-boundary blocker for active node reconstruction. Replacing the
old fixture with the new component would have silently refreshed its evidence.
Instead, `observed/source-snapshot.json.gz.b64` losslessly retains all74 original
snapshot files. The decoded JSON payload SHA256 is
`fbbc0b084be5dfa7aeb16fe175536db5777fe4c2bdebb325c0cee9b634e4439c`.
Each path, byte length and hash is checked against the original freeze; the
archived FREEZE.json must also reproduce the original freeze digest and object.
Reconstruction needs no Git history or installed compiler.

The old tests now validate this immutable historical snapshot. Their source,
input, expected-output and extra-file corruption controls still operate on that
same74-file tree. The actual-output comparator, source mutants and894/7 case
denominators are unchanged. New hash source has a separate source-tree receipt;
this packet supplies no evidence for that added module or new composition.

The packet manifest checks current support-file integrity. The original
compiler-tree identities remain in the unchanged archived historical freeze.
