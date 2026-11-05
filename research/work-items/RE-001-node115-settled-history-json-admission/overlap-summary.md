# Settled-history JSON outer reader: overlap assessment

The proposed node #115 question is a complete, bounded outer admission contract for the five `soh` fields. It covers selected map and sequence forms, duplicate and missing-field order, unknown-key handoff, JSON whitespace, nesting limit and the later closing/error precedence. It binds the parent `soh` branch and the call to reader `0x1e8c2c0`; child-value grammars and the unknown-value walker are dependency boundaries. Full native closure and the parent/output identity must be demonstrated by the packet before publication. No complete round trip or runtime state restoration is implied.

The proposed input/error grammar is separate from candidate 87's successful text writer: output field order alone does not determine what a reader accepts or how malformed input fails. Each can stand alone if complete; neither should be divided into isolated field or branch packets. A combined writer/reader packet would also be coherent.

Prior work to credit and avoid re-owning:

- #1674 maps a node #94 spot-metadata writer and selected reader. #1875 studies a separate #94 13-field OutcomeTracker codec and selected reader, leaving child codecs open. Neither is established as this five-field history object.
- #2149 and #2227 cover selected node #115 state-loader `locus`/`ctx`/height paths in different reader formats, not this outer reader.
- Candidate 87 covers the #115 successful `soh` text projection. It expressly excludes reader errors, defaults and round trips.
- The only apparent old corpus hit for one candidate FDE address occurs as an unrelated hash substring in #2110's LZ4 packet, not an ownership claim.

Searches of the November 5 all-state listing, retained historical descriptions and available patches did not reveal a prior owner of this specific outer reader contract. This is a conditional finding, not a guarantee: 32 old PRs are unavailable live, API patches may be omitted or truncated, a historical PR reached the file-list cap, and unpublished work may exist. The recorded audit is `/private/tmp/hl91-history-reader-scope-audit.json`; its census is `/private/tmp/hl88-pr-census.json`. Recheck GitHub before publication.

The scope also includes the parent’s absent-whole-`soh` route through `0x1d79180`, contrasting its empty collection/queue initialization with the required fields of a present child. The targeted search found no owner of that same parent default in the available material. #1674’s #94 `ta2` absence case is a distinct spot-metadata field default and should remain credited as an analogue, not recast as this result. Native proof of the parent branch, empty lengths and constructor’s TLS-dependent state remains essential.
