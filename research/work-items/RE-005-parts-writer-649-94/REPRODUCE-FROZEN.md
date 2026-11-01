# Reproduce the frozen independent authorities

The retained scripts and results describe the original pre-Rust chronology. A
replay verifies those immutable records; it does not create a fresh pre-source
independence claim. The final v2 freeze is authoritative. The earlier v1 freeze
is retained as metadata; its three exact byte prefixes are derived from v2 using
v1 lengths and SHA256 values rather than duplicated in this packet.

On a fresh scratch host, stage the historical scripts' required layout:

```sh
python3 stage_frozen_authority.py --packet /absolute/path/to/RE-005-parts-writer-649-94 --scratch /tmp/writer649-authority-replay
python3 /tmp/writer649-authority-replay/audit_protocol.py
python3 /tmp/writer649-authority-replay/challenge_native.py
```

The staging helper refuses to overwrite either scratch output or the historical
native-input directory `/tmp/hl-resume-20261101/root-parts-next`. That fixed path
belongs to the original unmodified challenge script. It receives only retained
649-byte body/listing, root admission/proof and decimal authority records. The
root admission includes outer602 supporting intake; only its writer649/literal/
RELA fields are credited here. No outer602 implementation or semantic claim is
introduced by staging it. The original generator and auditors are retained
byte-for-byte. Do not regenerate or overwrite their published receipts.

`authority.jsonl.zlib` and the decimal table transport decode without
normalization; original lengths/hashes are checked before staging. Only the
small v1 FREEZE file is physically retained, and all three recreated v1 files
must match their original hashes. The staging helper is task-local reproduction
support for these frozen script layouts; it does not execute any script,
compiler, library, captured bytes or instruction evaluator itself. It has only
been syntax checked in the author's environment; the original directories are
preserved there. The peer's original full sequential audit is retained as the
actual authority result.

The source runner is reproduced separately at its exact recorded source head
and with the admitted official research provider. Its production input client
receives only the eleven-field raw `inputs.tsv` path; authority/expected records
are external. `ACTUAL-RAW-TRANSPORT.json` and the failed-preparation transport
expand every original recorded runner stream and audit map byte-for-byte.
`tools/retain_parts_writer649_outputs.py --verify --public-root <packet> --output
<transport>` verifies that transport without executing compiled programs. Only
the two explicit independent input/expected paths may be external references.

The independent replay receipt records `debug.stdout.gz`, `debug.stderr.gz`,
`optimized.stdout.gz` and `optimized.stderr.gz`. Their exact original gzip bytes
are retained under the same names plus `.gzip-bytes` in `review/independent-replays/`;
remove only that suffix in a scratch copy to use ordinary gzip tooling. The
original replay script requires its adjacent raw input/expected files and the
recorded existing compiled clients. Stage those from this packet and a genuine
reproduction build; no executable artifact is shipped.
