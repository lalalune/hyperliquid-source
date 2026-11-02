# RE-012: node115 keepalive continuation and ownership

Node115's two complete keepalive helpers stop at the first failed option,
but their actual server/client callers continue after normal error logging.
Unlike the historical inline cleanup, both callers now invoke an outlined
error-drop body. This packet closes the reached packed-error branch and binds
the new caller fields, tracing gates, import slots and source Locations.
It is static source-reconstruction research, not a working socket runtime.

Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Addresses are linked ELF VAs.

| Complete FDE | Role | Bytes |
| --- | --- | ---: |
| `0x5c68520..0x5c68603` | first keepalive helper |227 |
| `0x5c68610..0x5c686f3` | second keepalive helper |227 |
| `0x2e6ba40..0x2e6c57d` | accepted-connection caller context |2,877 |
| `0x2e7db50..0x2e7e7ed` | client caller context |3,229 |
| `0x2e6b0c0..0x2e6b18e` | first outlined error-drop context |206 |
| `0x2e7bdd0..0x2e7be9e` | second outlined error-drop context |206 |

All 6,972 bytes / 1,444 instructions are retained in fresh GNU/LLVM exports,
with FDE/CIE bytes, unique helper imports, actual whole-text direct caller
census, selected relocation writers and initial metadata. Both decoders agree
on every instruction boundary without display joins. The two direct helper
callers are actual E8 instructions; no helper-entry RELATIVE slot was found.
Context bytes do not count as whole-caller implementation or component coverage.

[CONTRACT.md](CONTRACT.md) proves unsigned clamping, exact duration/tag gates,
exact -1 failure, errno packing, short circuits and the conditional continuation.
Both outlined drop entries return before any pointee access for these tag2
errors. Arbitrary custom-error cleanup remains open. Logging must return
normally and preserve its borrowed error word; the packet does not infer
those effects from an opaque callback. The server logs only at level0, the
client at unsigned levels0..3, subject to their further interest gates.

The new actual Locations still name vendored socket2-0.5.7 and0.4.10 files,
but the server now names unversioned `z_vendor/hyper`. The private client's
`z_forks/hyper-fork` path is not public-source permission or exact upstream
attribution. Historical node94 addresses, old inline drop boundaries and old
version labels are not inherited. No old target artifact or retired task tree
is required to replay this packet.

## Licensed candidate comparison

[Source provenance](source-provenance.json) pins reused, previously measured
public socket2 0.4.10/libc0.2.149 and socket2 0.5.7/libc0.2.150 builds. The
licensed archive retains whole original objects, build commands/results,
source manifest, licenses, initial build streams and nonmatching optimized
symbol probes. Four complete official crate archives authenticate all506
original source files. Public Hyper 0.14.29 bytes are separate structural
corroboration; they do not identify the private fork or unversioned vendor.

The actual candidate compiler was Rust1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, macOS arm64 host/Linux x86-64
output. The node115 `.comment` rustc1.95.0 label is not an original-build
attestation. No new compiler build or independent reproduction is claimed:
old opt0/opt3 repeats and optimized-symbol absence remain recorded observations.
At opt3 the public wrapper includes SO_KEEPALIVE and is a different boundary;
no subset of that wrapper is compared to a captured helper.

The current comparison re-extracts each entire418-byte internal FUNC, binds its
unique PC32 FDE and CIE encoding, all14 source relocations and95 instructions,
and compares it against both complete227-byte node115 bodies. All4 alternatives
over2 unique target intervals are unmatched. There is no normalization,
truncation, padding, byte transplantation or inferred original version assignment.
Calls remaining in the opt0 candidate are not treated as closed target behavior.

Two `extent-mismatch` dependency rows register the complete comparisons.
Their two version alternatives are preserved explicitly; identical candidates
add no duplicate target credit. Existing aligned totals and acceptance gates
stay unchanged. This active registration initially failed because the current
allowlist omitted socket2; the exact failure is retained. The only shared-tool
change adds that dependency identifier. No general registry redesign is included.

## Verification and limits

```sh
python3 -O -B research/work-items/RE-012-keepalive-source-115/verify.py
PYTHONPATH=tests python3 -B -m unittest -v test_keepalive_source115
```

The verifier checks a closed regular-file/directory inventory, hashes, fresh
static records, all retained decoder instruction partitions, licensed archive
members, complete source manifests/objects, source-ELF corruption controls,
whole-body comparison controls and registration alternatives. The finite
`protocol_relation.py` supports counterexamples from literal event expectations;
it is a mathematical proof aid, not captured execution, a libc mock presented
as equivalence, or independently authored production Rust.

Actual commands/results and failures are recorded in `validation.json` and its
lossless log archive. The 13 new focused methods and 23 existing FDE/catalogue
tests passed. Optimized packet replay passed with 113 licensed archive entries,
506 source-file hashes, eight source-ELF controls and four whole-body comparator
controls. `make doctor verify catalogue-check reproduce` passed. Initial
new-worktree verification lacked the six pinned
submodules; exact local pinned checkouts were materialized and their official
origins restored without pin/global-config changes. The catalogue also rejected
a stale provenance pin after command-path sanitization; refreshing that pin
restored the check without changing source objects or comparison results.
Absolute local prefixes in retained command records are explicitly normalized;
original stream hashes and ignored originals remain recorded. Full `make test`
passed on unchanged source commit `463982631d98d782ffce7bfef4791e4e5d66b564`: 77 files,
395 reported tests, zero failed files, three explicit skips, 1038.609 seconds.
The skips are the optional pinned-libcore check, optional nonce-ring Rust
qualification, and a nested-JRE host condition. Exact streams, inventory and
result are retained under `full-suite/` in the log archive. The independent
review of that commit found no blocker; its exact 25-member portable bundle is
also retained as `peer/portable-review.json.gz`. This later update changes only
README/validation evidence and the manifest. No hosted-CI, integrated node,
original source/build or complete network compatibility result is claimed. Captured binaries, instruction emulators,
Linux objects, socket services and chain actions were never executed.

`research-sources.json`, `research-claims.jsonl` and `countersearch.json` carry
the installed insane-research handoff: primary target measurements, public
source provenance, competing interpretations and explicit independence limits.
New analysis code/documentation is MIT. Public source/material retains its
upstream MIT/Apache notices in the archive. No unlicensed inferred source was
read or copied. Attribution: OpenAI / gpt-6-astra / Codex0.166.0, as supplied by
the coordinating session.
