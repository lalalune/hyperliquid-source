# Reproducibility

`make verify` authenticates every retained artifact and detached signature,
checks imported file hashes and public repository pins, and verifies evidence
packet manifests. It does not execute the captured node or visor.

`make reproduce` regenerates the node #115 inventory and the optional visor
smoke-fixture inventory using the preserved inventory parser, then compares the
results with the imported records. No retired-release input is required.

`make catalogue-check` regenerates scope and progress in memory, authenticating
the target and every registered source excerpt. Committed generated files must
match exactly. Acceptance gates remain separate from selected byte windows.

Use `make test` for the retained static checks and the component README commands
for actual Rust builds. Record compiler version, target, flags, source hashes,
output hashes and negative controls. Prior receipts remain historical evidence;
a different current source hash requires a new validation record.
