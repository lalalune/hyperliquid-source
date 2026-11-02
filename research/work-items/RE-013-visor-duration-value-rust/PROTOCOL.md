# Input-only value protocol

Each ASCII record is `ID<TAB>BITS<LF>`. Both fields are exactly16 lowercase hexadecimal digits. ID is opaque, unique in a stream and affects only the echoed identifier. BITS is one raw u64 encoding; every value is admitted. Empty input produces empty output.

Each output is `ID<TAB>SECONDS<TAB>NANOSECONDS<LF>`. The two numbers are canonical unsigned decimal without leading zeros exceptzero. Seconds fits u64; nanoseconds is below1,000,000,000. Exact ordered bytes and line counts must match. No NaN-class normalization or sorting is permitted.

The future client reads only stdin and links the actual component. It must not read expectations, provenance, oracle files, case labels or fixture-derived lookup values. The outer comparison harness alone receives expected outputs. The client rejects malformed/non-ASCII text, missing final LF, duplicate IDs, noncanonical hex and extra/missing fields with nonzero exit and no partial successful stdout. Any command-line argument is rejected. Input/IO/allocation error behavior belongs to this new host protocol, not a recovered native error ABI.

The frozen corpus stores IDs/input words separately from expected pairs and explanatory provenance. Baselines, rebuilds and compiling semantic mutants must emit their own entire output stream. Public source must remain absent at the pre-code gate; later replay will expose an explicit optional source-absence check rather than making the final checkout unusable.
