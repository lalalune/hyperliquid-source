# RE-001 / foundation: restart-command token filter

Question: does the reference-labelled child-command builder append backup flags,
or does its token pipeline remove them? Scope: tool, controls and this packet.
This is partial static research; no command is executed and no gate is changed.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Unlicensed reference lead: can1357-hl
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `base/production.rs`.
Its append narrative is treated as an unverified lead, not copied source.

## Observations

ELF virtual addresses, no masks. Complete FDE/CIE exports:

| Owner | End exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Caller 0x1438e90 | 0x143900c | 380 | 88 |
| Token iterator 0x13df3c0 | 0x13df5ed | 557 | 145 |
| Collector 0x13df5f0 | 0x13df766 | 374 | 97 |
| Join helper 0x14b1090 | 0x14b14b3 | 1059 | 265 |

Total **2,370 bytes / 595 instructions**, full hashes in `records.json`.
This denominator describes complete exports, not full semantic recovery of all
helper branches. Only the selected ASCII token protocol is modeled.

The caller passes `--restart-style LoopParent` with length 26 to `0x1440df0`,
then tests AL and branches to a captured assertion on zero. The Location resolves
to `base/src/production.rs:101:9`. On the normal route, `LoopParent` length 10
and `LoopChild` length 9 are arguments to `0x1441520`. Those upstream helpers'
contains/replacement algorithms remain unclosed. The model starts with the
replacement helper's returned buffer, not the original input command.

The caller constructs a token-iterator descriptor, collects it via `0x13df5f0`
and passes the resulting slice to `0x14b1090`. Its join-separator pointer is
`0x219581`, whose surrounding rodata reads ` --backup-logs`, but its supplied
length is **1**. The separator is only byte `0x20`. The join dispatch table's
entry 1 reaches `0x14b135f`, and `0x14b1398/0x14b139b` copy one separator byte.
The longer surrounding literal is not an appended suffix.

For ASCII codepoints, `0x13df3ef` loads mask `0x100003e00`. The compare/BT
branch at `0x13df519..0x13df526` recognizes separators 9,10,11,12,13,32.
Empty segments are skipped by the iterator. At `0x13df5b5` only a 13-byte
token enters the exact filter: overlapping qwords at token offsets 0 and 5
are XORed against rodata at `0x219582` and `0x219587`. OR-zero branches at
`0x13df5d3` back into the iterator, skipping precisely **`--backup-logs`**.
Other tokens are yielded to the collector. Thus the normal ASCII downstream
pipeline removes those exact tokens and joins the remaining tokens with spaces.
It does not parse shell quoting or remove embedded/prefixed/suffixed matches.

## Inferences and unknowns

Child-command naming is inferred from argument text and source context.
The bounded model is conditional on a returned replacement buffer and normal
iterator/collector/join execution. Upstream contains/replacement effects, Unicode
character classification, allocation limits, source lifetimes, ownership/drop,
unwinding and process behavior remain unclosed. The full output for an original
command is therefore not claimed. No runtime command, process, user state or
configuration is accessed. This neither copies Rust nor requests a progress gate.

Before: the reference inferred appending the whole nearby backup string. After:
literal lengths, the exact-token skip, ASCII mask and one-byte join are bound
to actual caller/helper bytes. Next question: close the upstream replacement
helper and Unicode classification before claiming a full command transform.

## Reproduction and controls

Python 3.12.14, static stdlib ELF readers. Optional complete export: Capstone
5.0.6, x86-64 Intel, contiguous bodies. No captured binary executes.

```
python tools/restart_token_filter.py --out research/work-items/RE-001-restart-token-filter-94/records.json
python research/work-items/RE-001-restart-token-filter-94/export_disassembly.py
python -m unittest tests.test_restart_token_filter -v
```

Six focused methods pass in 1.232 seconds: all 128 ASCII separator classes,
3,328 single-byte token mutations (including unchanged-byte cases), repetition,
quotes, lookalikes and empty synthetic downstream buffers. Some buffers need not
be reachable from the original caller; these are explicitly conditional tests.
Changing the actual mask or rodata changes model results and bindings reject it.
Other real-capture controls change calls, lengths, filter offsets/branches,
one-byte join dispatch/store, source record, four FDE extents and target digest.
Make is unavailable, so the required Python commands were run directly. Full
suite: **363 tests in 107.548 seconds; 7 failures, 16 errors, 21 skips**.
All six new methods pass. Existing Windows newline/POSIX-path/native-tool
constraints remain failures; this independent base excludes unmerged #227.
Doctor reports missing prerequisites. Eight artifact sizes/digests pass before
missing GPG prevents signature verification. Imports reject the Windows reference
checkout; catalogue-check rejects backslash paths. Reproduce stops at artifact
verification. No full-suite, signature, hosted-CI or native-equivalence success.
