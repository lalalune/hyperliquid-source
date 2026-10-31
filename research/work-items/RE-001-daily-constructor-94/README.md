# RE-001 / foundation: daily-liner constructor edge-byte and state map

Question: what does the daily-liner-linked constructor actually accept at its
input slice edges, and which bytes does its normal-return path initialize?
This packet maps one constructor, not log rotation, flushing or filesystem
behavior. Independent main base `1f8c67c63ca4794c9689235471c60297f8a5c985`.

Input `artifacts/node/94/hl-node`,91774280bytes,SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The exact FDE is `0x1402050..0x14023ba`:874bytes,exclusive end,file offset
`0x1401050`. Range hash,actual control/literal bytes and relocation identities
are in `observed/records.json`; raw objdump/FDE/RELA exports accompany it.
No operands or instructions are normalized.

Location slot `0x5668d70` RELATIVE-binds to `0x1eb8d4`, containing the exact
embedded upstream path `/home/ubuntu/hl/code_Mainnet/base/src/daily_liner.rs`.
The reference remains pinned at `999556f6e0a474b8312db96ec3149e1c44e97c23`;
no implementation or comments from the unlicensed inferred source are copied.

## Observations

- RDI is preserved as the output object pointer; RSI/RDX form an incoming
  pointer/length pair. A helper call through `0x576e8a0` occurs before the
  slice-edge checks. Its actual RELA target is `0x151cba0`.
- At `0x1402086`, zero length skips both edge-byte reads. For nonempty input,
  the last and then first byte are compared with `0x2f`. Either equality
  selects `0x14022da`, which formats a source-bound diagnostic. Interior slash
  bytes are not checked by this local predicate; no path normalization or
  complete accepted-path syntax is established.
- A shared object is loaded through `0x576e928 -> 0x577b288`. Its dword+0x50
  chooses a helper/rejoin route; the common formatting path uses object+0x18.
  The resulting formatted value is passed to `0x576efa0 -> 0x14396c0` with
  an independently bound11-byte literal `daily_liner` at `0x21845c`.
  Exact resulting text and the helper's operation remain unknown.
- The staged value reaches `0x576eac0 -> 0x13d1720`. This is a callee identity,
  not another claim to recover that helper's initializer semantics.
- Before returning, a second call uses the same `0x576e8a0` slot. The tail
  writes three input-related words at output+0,+8,+0x10; three16-byte chunks
  at +0x18,+0x28,+0x38; five16-byte chunks at +0x48..+0x88; a first captured
  dword at +0x98; and12later captured bytes at +0x9c..+0xa7.
- Single-byte stores set output+0xa8 and output+0xaa to zero. No store in the
  decoded normal-return tail covers +0xa9. Across these sixteen tail stores,
  exactly170distinct bytes are written. The final `mov %rbx,%rax` returns the
  output pointer. The observations do not identify the complete Rust layout,
  prove an object allocation size, or assign meaning to untouched bytes.

## Relationship to existing work and limits

Open PR #121 maps a different FDE, `0x14019b0`, and its aggregate-return caller.
Open PR #349 maps writer/rotation bodies `0x1401d40` and `0x14023c0`.
This constructor at `0x1402050` is not among those selected intervals. Shared
data/callees are recorded as dependencies rather than repeated claims to their
behavior. Open PR #43 separately maps callee `0x13d1720`; no unmerged packet is
imported or required by this independent branch.

The embedded name supports a daily-liner association. It does not prove full
date/time units or consistency between the two capture calls, full formatting,
file/directory creation, open flags, I/O, ownership, cleanup/LSDA behavior or
caller-wide correctness. Zero flag values and the unwritten byte are raw layout
observations, not a named enum, undefined-behavior claim or recovered Rust API.
No captured executable/emulator or filesystem operation is run.

## Reproduce

Ubuntu24.04/WSL2,Python3.12.3,GNU readelf/objdump2.42(default AT&T).

```text
make doctor verify test catalogue-check reproduce
python3 tools/daily_constructor_static.py
python3 tools/daily_constructor_static.py --output work/repeat
diff -ru work/daily-constructor-94 work/repeat
```

Full input size/SHA is checked before analysis. Six focused tests include nine
actual instruction-range corruptions,two literal corruptions,six RELA retargets,
independently decoded empty/edge-byte branch destinations,all256byte encodings
per comparison,and sixteen decoded normal-tail stores with their widths and
exact170-byte write set. Local examples distinguish empty,edge and interior
slashes without claiming actual filesystem behavior. Lower-level corruption
controls deliberately operate below the complete-file identity gate.

See `validation.txt` and `required-checks.log` for observed required checks;
four exports reproduce byte-identically in an author rerun,not independent
peer review. `manifest.sha256` binds source,tests,documentation and evidence.
No imported input,pin,generated catalogue/progress or component gate changes.
No Rust implementation/build,runtime equivalence or hostedCI claim.
Next close the input transformations and typed callers before reconstructing
the constructor's string/object API.
