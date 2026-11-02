# Submission scope and current related work

The implementation qualifies the supplied Reader operation at node94
`0x4674820..0x4674b45` and the EDX=0 projection of `0x471b880`.
Its 30-body closure, canonical Reader-state premises, active returned values and
ownership relation are fixed by the original pre-code proof. The new Rust uses
only the merged `hl-bincode-varint` library. It does not depend on a pending PR.

The original README and source-validation README are preserved phase snapshots.
Their pre-code and planned-build wording records what existed when their hashes
were frozen. [IMPLEMENTATION.md](IMPLEMENTATION.md) gives the subsequent actual
source qualification and reproduction entry point. The original 165 files and
source/harness freeze remain unchanged.

## Related work checked before submission

The following heads were read directly on 2026-11-02, including complete changed
paths, explicit review-request endpoints, reviews and head-pinned scope files.
The five drafts remain reserved. Their aggregate roots and the maintainer's
transport work are outside this contribution.

| PR | Observed head | Related scope retained by that contribution |
| --- | --- | --- |
| [#1706](https://github.com/lalalune/hyperliquid-source/pull/1706) | `4b859510984d14a18c270ab338797033db3477c0` | Draft three-byte transport request writer and caller/frame composition, including `0x28c14f0`. |
| [#1723](https://github.com/lalalune/hyperliquid-source/pull/1723) | `72b7a41d30b40ef105c9fec5a713f6726162e5cb` | Draft response-envelope relation at `0x25618f0` and `0x28bdc00`. |
| [#1742](https://github.com/lalalune/hyperliquid-source/pull/1742) | `1e71cca655a54190a5d140a0ef890250025ed820` | Draft mode-1 signature-value relation at `0x25587d0` and `0x2558ee0`. |
| [#1779](https://github.com/lalalune/hyperliquid-source/pull/1779) | `cf7e74e68e58ed05817ea6f536d76ee4f306a453` | Draft mode-1, limit-1000 map relation at `0x2890b60` and its own insertion closure. |
| [#1816](https://github.com/lalalune/hyperliquid-source/pull/1816) | `fd5a8af5a4c3f4985ddeabff116cb9a632d63290` | Draft inline three-record relation at `0x21cca20`; distinct output ownership and readers. |
| [#1818](https://github.com/lalalune/hyperliquid-source/pull/1818) | `b01cbf3c5c80391cdb9ee963d5d483039868e563` | Maintainer request/reply frame exchange, stacked on #1778. Its API preserves the response payload and leaves semantic decoding unresolved. |

Across 1,200 complete FDE comparisons and 180 comparisons with explicitly
unresolved decoder leads, the only intersections are four already credited
scalar/error bodies: `0x466d850..0x466d975`, `0x466d980..0x466dabc`,
`0x466dac0..0x466dace` and `0x466dad0..0x466dc0c` (939 unique bytes).
The original README already credits the merged varint, slow-width and Reader
work and the related wrapper-state study in #1365. Neither this contribution
nor the newer drafts newly owns those shared dependencies.

The related PRs share logical themes, which does not establish interchangeability
of their different native instantiations. In particular, this reader has not
been shown to parse the reply expected by #1818. No transport integration,
authentication, initial exchange, alternate aggregate recovery or encoding
completion follows from this library. The earlier protected drafts #1672,
#1685 and #1697 also retain their scopes. This bounded ownership review is not
a maintainer approval or a claim of future exclusivity.

## Revision and validation basis

The actual two Rust qualifications and repository checks ran on
`966865f1637a29ce75b019e1bf11d5529cc6f519`. Before submission the checkout moved
to current main `e5c9b6436876b2a4a39daef813171f9879317699` by fast-forward.
That transition changes three unrelated node-accounting evidence documents;
no executable, test, dependency, captured input, contribution instruction or
catalogue configuration changed. Every frozen source, provider, harness,
context and original pre-code file was rehashed unchanged. Those facts preserve
the observed qualification basis; they do not turn upstream test claims into
tests performed by this contribution.

## Additional late intake

The saved late intake contains 127 unique PRs, #1706 through #1832. The six
related entries above were reviewed separately. All remaining 121 complete
bodies and 1,090 changed filenames were read. For the relevant exact heads,
35 scope-file Git blobs across 32 PRs were authenticated, with 294 selected
node94 FDEs compared against the 30 greeting bodies: 8,820 comparisons and no
intersections. Three node115 intervals were kept separate. The older head
embedded in #1718's body was not substituted for its current head.

The bounded [coordinator scope record](OWNERSHIP-REVIEW.json) preserves the
review receipt identities, census and limitations. The complete API responses
remain private research records. This intake did not validate other authors'
tests, establish a repository-wide absence of overlap or reserve future work.

## Final publication refresh

At 08:10:52 UTC on 2026-11-02, a final live intake added PRs #1833 through
#1846. All 14 full bodies and 182 changed filenames were read. Eleven relevant
current heads and scope-file identities were checked; 128 declared native
extents produced 3,840 comparisons with the 30 greeting bodies and no
intersections. The TWAP reader/writer family in #1839 and snapshot-admission
implementation in #1845 are distinct. Drafts #1840, #1841 and #1842 also remain
reserved. Main was still `e5c9b6436876b2a4a39daef813171f9879317699`.
The scope record binds this addendum and retains the same bounded-review limits.
