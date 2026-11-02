# Frozen-before-source observer protocol

Only `inputs.tsv.gz` is supplied to the future Rust client. Each decompressed
line is opaque ID `C` followed by six decimal digits, one tab, a lowercase
hexadecimal frame and LF. IDs are unique. Names, domain labels and expectations
are in separate files that the client must never receive. There is no filename,
shell command, real clock or filesystem operation in this protocol.

All integers below are little-endian. `bytes` means a u32 length and exactly
that many arbitrary bytes; `option` is u8 zero or one. Every frame is consumed
exactly, with no trailing bytes. Generic description bytes must be canonical
UTF-8; request/cleanup payloads are opaque and may contain NUL or invalid UTF-8.
Input caps are explicit new client resource policy: at most 1MiB per decoded
frame, 65,536 bytes per byte field, 256 delays, 256 attempt responses and
1,024 sleep responses. These are transport limits, not native length claims.

| Order | Value |
|---|---|
|1|ASCII magic `VR01`; mode u8:0 generic retry,1 owned caller|
|2|request identity label u64; request bytes; terminal identity label u64|
|3 generic|description bytes; delay option; if present u32 count then that many raw u64 words|
|3 owned|cleanup option; if present cleanup identity u64 and bytes; cleanup-error option; if present cleanup-error label u64|
|4|attempt count u32; each response is u8:0 success,1 followed by error label u64|
|5|sleep count u32; each response is signed i32 code, signed i64 remaining seconds, signed i64 remaining nanoseconds|

The generic mode transmits no cleanup fields. The owned mode transmits no
description/delay fields because the operation fixes these to the native
description and raw [1,3,10] list. A cleanup-error response may be supplied
even when cleanup is absent; it remains unused, and no resource is created.
All response prefixes denote total supplied functions: unlisted attempts
return success, and unlisted sleeps return code0 with zero fields. A suffix
can contain semantically invalid sleep replies without being reached.
Parsing the transport does not call callbacks or construct tracked resources.

Output is the same ID, tab, compact JSON and LF. The harness compares complete
decoded values and the exact canonical baseline streams. JSON keys are sorted;
hex strings are lowercase. Every output has exactly `code`, `outcome`,
`terminal`, `terminal_identity`, `trace`. Outcome is `succeeded`, `exhausted`,
`invalid_remainder` or `unexpected_sleep_code`; code is null except for the
last outcome, where it is the actual signed code. Terminal is the supplied
label only on exhaustion, otherwise null. Terminal identity is true only on
exhaustion and must be checked using the actual returned allocation, not
inferred from its numeric label. Traces use the following arrays in order:

| Event | Fields after event name |
|---|---|
|attempt|request label, payload hex, actual request identity true, prior error alive true or null on first attempt|
|attempt_success|none|
|create_error / drop_error|creation serial starting at0, supplied error label|
|sleep|requested seconds, nanoseconds, raw clock1, flags0|
|sleep_result|raw signed code, raw signed seconds, raw signed nanoseconds|
|terminal|description UTF-8 hex, complete selected raw words as16-digit hex strings, last-error serial, last-error label, last error alive true|
|create_terminal|supplied terminal label|
|drop_command|owned command label and payload hex|
|cleanup|cleanup label, payload hex, actual cleanup identity true, terminal alive true or null when no terminal exists|
|create_cleanup_error / drop_cleanup_error|supplied cleanup-error label|
|drop_cleanup|cleanup label and payload hex|

Each tracked error allocation has its own creation serial even when labels
repeat. Weak identity witnesses and destruction records must establish the
boolean fields; copying labels into a substitute object is insufficient.
The returned terminal is held while the operation trace is observed. Its
later caller-owned destruction is outside that boundary. Generic request
ownership likewise remains outside the operation. No trace event may be
filtered from actual client stdout to obtain a match.

Malformed input causes a diagnostic on stderr and exit2; the driver buffers
the entire output batch and emits no stdout prefix if any line is malformed.
This is new transport policy. The library's refusal variants are successful
value outputs, not malformed input, and remain separately labelled in corpus
provenance. A process failure or incomplete mutant stream cannot count as a
semantic difference. All policy limits and complete-output rules are fixed
before source/client authorship.
