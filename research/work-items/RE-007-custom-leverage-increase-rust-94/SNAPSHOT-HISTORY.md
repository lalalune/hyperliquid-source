# Historical compiled source boundary

At draft #1460 head `1e78e5ac1e1e7b6a2812a413f03e97cfe8c45470`, the
35-file compiled snapshot describes 23 component files and 48 Cargo tests per
profile. Its immutable archived `src/lib.rs` SHA-256 is
`ffb0ba0d512c6158b691870b230c531fdeb137edc504e5136629322ac4820908`.
The original source, expected values, actual streams and archive are unchanged.

Adding the selected isolated-decrease module, export and tests makes the old
test's strict current-component equality fail. The preserved initial test exit
is 1, with empty stdout and stderr SHA-256
`84a7158594a2978a171498b6df4a0faa90003885da63f011de33549717b52455`.
The error is `current component differs from frozen build`.
The actual failed command receipt and raw stdout/stderr are retained under
[historical-boundary-failure/](historical-boundary-failure/).

The focused test now uses the existing historical default replay. It still
checks all archived source hashes and actual outputs, and binds unchanged
current support sources except the shared export file and evolving auditor.
New controls pin the original compiled export file and reject a changed current
increase implementation. The optional `--current-component` audit remains
strict and rejects the expanded component. A separate new compiled receipt
qualifies the combined component; this old receipt is not reinterpreted as a
build of that tree. Manifest export pins describe current support-file integrity,
not a replacement of historical compiler inputs.
