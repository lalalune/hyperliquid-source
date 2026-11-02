# Node #115 research status

Only node #115 is an active implementation target. Current scope, component
gates and compared bytes are generated in [PROGRESS](../docs/PROGRESS.md).
Retired-release artifacts, unsupported implementations and their dedicated
research tooling have been removed from the active tree and remain in Git.

The migration retains five existing #115 Rust components and adds validated
unsigned128-to-binary64 and tagged-count migrations. Shared analysis helpers remain only because
the #115 validators depend on them. Their old target-specific entry points have
been removed. [Migration provenance](migration.json) records the source hashes.

No full node build, current-network compatibility, whole-ELF equivalence or
complete component gate is claimed.
