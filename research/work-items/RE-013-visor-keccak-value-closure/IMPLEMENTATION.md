# Existing Keccak provider: actual qualification

The unchanged merged MIT `src/node94-action-signable::keccak256` provider now
has a supplied-byte correspondence argument and actual host qualification for
the four Visor bodies in this packet. No production function, wrapper or API was
added. The native proof establishes rate136, delimiter1, final bit128 and the
24-round Keccak permutation, resolving the older SHA256 inference for this
specific helper. The prior prose and all31 pre-code files remain unchanged.

Start with `CONTRACT.md` and `PROOF.md` for native premises, then
`rust-validation/SOURCE-PROOF.md` for the existing provider and
`rust-validation/BRIDGE.md` for the actual build graph and retention rules.
The new input-only client calls the existing exported function directly; only
the comparison harness can read the independently frozen expectations.

## Observed author results

`rust-validation/AUTHOR-QUALIFICATION.json` and the exact files under
`rust-validation/qualification-author/` record the completed run:

| Observation | Actual result |
|---|---|
| Child commands |190:171 exit0 and19 expected exit2 refusals|
| Raw child streams |380 references,98 distinct stored gzip files|
| Full value streams |50 streams, each with all2,000 ordered output frames|
| Baseline/rebuild streams |Six, all byte-identical to frozen expectations|
| Existing unit tests |14 passed in each debug/release profile|
| Source-copy mutants |22 in each profile, all compiled and produced complete differing streams|
| Comparator controls |10 detected corruptions|
| Client controls |18 malformed batches and an extra argument refused; empty stdin accepted|
| Source observations |25 across24 physical roots; source/client copies rehashed|
| Private compiled artifacts |100 rlib/client identities, exact retained bytes rehashed|

The same-path clean repeat produced identical rlibs and clients in both
profiles. Across distinct clean directories, both rlibs and the release client
were identical; the debug client differed. These are exact byte comparisons,
with no masks, normalization or established explanation for the difference.

The least broadly distinguished mutant omitted the final block for an empty
remainder:54 of2,000 results differed in each profile. Skipping complete blocks
and replacing absorption XOR each differed on1,168 results; dropping the final
remainder byte differed on1,454. Every other admitted mutant differed on all
2,000 results. A compiler failure, panic or truncated stream was never counted
as a semantic detection. There were no failed required commands in this run.

The actual six preparation commands and12 raw stream references are separately
retained in `rust-validation/preparation-author/`. These were version queries,
formatting/check and offline locked metadata, before compilation. Structured
command paths use the logical mapping described in BRIDGE; raw child streams
are unchanged. `rust-validation/author-launch/` retains the successful outer
launcher result and its raw stdout/stderr.

## Reproduction and chronology

The original pre-code freeze is `12263950e60ce1b78ec3bb6d44c619ada9baad1b4f742b396e2fd1cdb2fea26c`.
The later source freeze is `3fc525fa171896efefc87b5c4c43149c25d6b615f13ecf9b3105c38bc984ffa8`.
The latter binds the unchanged11-file provider, the real external1,008-row test
fixture, seven qualification inputs and all31 pre-code files. It precedes the
actual author run. Separate root/peer reviews admitted the source and build
graph before compilation. The new final author freeze records completed
evidence without rewriting either earlier phase.

After reading the source and harness, the complete isolated replay is:

```sh
python3 -B rust-validation/build.py \
  --toolchain /absolute/path/to/1.94.1-aarch64-apple-darwin \
  --out /tmp/a-fresh-visor-keccak-build \
  --private-map /absolute/private/path/visor-keccak-build-map.json \
  --source-freeze-sha 3fc525fa171896efefc87b5c4c43149c25d6b615f13ecf9b3105c38bc984ffa8
```

Use the canonical harness path from this packet directory. The exact installed
toolchain payloads, source graph, fixture, ancestor configuration and workspace
rules must pass admission. Before compilation, the harness copies exactly the
31 pre-code files to a separate directory and runs the immutable static
verifier there. This respects its original client-absence guard. Directly
running that pre-code-only verifier in the extended packet is not the final
post-source replay path.

`IMPLEMENTATION-MANIFEST.sha256` identifies this complete author delivery;
the old `MANIFEST.sha256` remains the historical pre-code manifest. Compiled
rlib/client bytes stay in private archives because they can contain local
paths. Their public hashes do not assert public availability. Runtime caches
are excluded. Raw command output passed a private-home-path inspection before
publication; no stream was redacted to obtain a match.

These results qualify the existing host provider and the new input adapter.
They do not execute the captured ELF, prove its imported reader/error/cleanup
behavior, reproduce its compiler or ABI, or establish cryptographic security.
The native valid-memory, external-frame, red-zone and normal-return premises
remain unchanged. Finite tests supplement the manual complete value argument.
