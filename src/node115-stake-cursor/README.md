# Node115 stake cursor observations

Independent Rust for RE-001/exchange's cursor prefix and an independently fresh
post-helper arithmetic point. This is an owned logical API, not the original
iterator ABI, requirement units or a complete staking policy.

`cursor_prefix` checks both unsigned additions before the cursor store. It
records the actual stored cursor, terminal old index or numeric-helper request.
It never executes or supplies a result for that numeric helper. Terminal status
is raw AL2; it does not yield a requirement. Diagnostic observations stop before
the opaque call and do not assume safe rejection or a diagnostic return.

`post_helper` accepts a freshly supplied word/bonus and qualified index/column.
The four observed columns are a scope premise: `ObservedColumn::new(4)` rejects
our API domain, not an asserted native error. The original context byte's valid
range, enum and caller provenance remain unclosed. Values outside these four
columns are not reconstructed or reduced modulo4. Index3 actually aliases the
index0 row in the signed-relative table; there are three distinct data rows.

The word-plus-bonus saturates before checked multiplication by the observed
constant. Successful paths execute real native C5 cleanup CALL/RET in the
reference replay. Overflow with old tag1a2 orC5 writes rawC5 and returns AL0;
other old tags stop before their unresolved cleanup. Rust's boundary labels
are new analysis types; they do not name original Rust variants. Inactive
failure RDX is excluded from the logical comparison, while the interpreter
separately checks it against the observed old index.

Use Python/Capstone5.0.6 and Rust1.94.1 from the repository root:

```sh
python3 research/work-items/RE-001-stake-cursor-115/build.py \
  --rustc /absolute/path/to/rustc --output work/stake-cursor-owned
python3 -m unittest discover -s tests -p test_node115_stake_cursor.py -v
```

The output directory must be new. Only input words reach the owned client;
expected observations remain comparator-side and under cfg(test). Clients run
in an empty cwd. Both optimization profiles, ordinary source tests and compiled
semantic variants are actually run. Original bytes are data for an explicitly
bounded Python instruction evaluator, never a captured ELF process or Unicorn.
Research builds run on macOSarm64, with no original ABI, Linux-node build or
byte-equivalence claim. New work MIT. Existing #2239 mapping is credited;
all full-scope component gates remain false.
