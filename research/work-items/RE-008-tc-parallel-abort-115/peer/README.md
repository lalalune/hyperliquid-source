# Independent review records

The peer inspected fixed commit `2b0e3087ea11904aa9fa45a8f058f4fa76e4d523`.
The exact portable archive contains 91 entries, including its fresh full-body
GNU exports, selected readelf frame records, independently authored static and
value calculations, retained-native audit and original reviewer-only failures.
Only absolute reviewer-root prefixes in failure diagnostics were normalized;
original SHA256 and size are preserved by the archive. Its SHA256 is
`e25cf2c4311a66f201b57ce1da44fdb26fd3af437d6e1a147bddfaa103492e57`.

All archive members were decoded and hash/length checked during incorporation.
The three standalone scripts and review summary are copied byte-for-byte from
that archive. No source, oracle or qualification fixture changed for review.
The author also ran the unchanged reviewer value script and retained the exact
15,412-row match in `author-replay-of-reviewer-oracle.json`.

From the repository root, with a new ignored output directory:

```sh
python3 -B research/work-items/RE-008-tc-parallel-abort-115/peer/independent_oracle.py . NEW_RESULT.json
python3 -B research/work-items/RE-008-tc-parallel-abort-115/peer/independent_static.py . NEW_DIR
python3 -B research/work-items/RE-008-tc-parallel-abort-115/peer/audit_recorded_native.py research/work-items/RE-008-tc-parallel-abort-115 NEW_RESULT.json
```

The static reviewer uses installed GNU tools at their recorded local executable
paths; adapt only those tool paths if necessary. Address selections and author
source/proof were supplied before review. This is independent checking, not
blind discovery or a new compiler/native qualification. Opaque helper effects,
scheduler behavior and original public-source/compiler provenance are not proved.
