# RE-017 · Emit typed #115 action entries in replica Full responses

The existing [replica response writer](../RE-017-node115-replica-response-source/README.md) emits the Full arrays but leaves their action entries to a callback. The [action response trace](../RE-017-node115-replica-action-response-status/README.md) and [success dispatch](../RE-017-node115-replica-success-dispatch/README.md) identify the native entry's field order and variant split. This packet supplies a typed callback in the Rust writer and binds selected nested output fields and string escaping to the captured instructions.

The outer entry writer emits `user` before `res`. The user adapter selects `null` for an absent user and a fixed 20-byte lowercase hexadecimal address for a present one. The result writes `status` followed by `response`. Tag 15 yields `err` with a quoted text response. The error field writer calls the native escaper. Its 256-byte lookup table leaves UTF-8 bytes and slash unchanged and distinguishes the short escapes from lowercase `\u00xx` forms.

The selected successful response variants include `default` without a data member, `validatorVote` with a Boolean data member, and distinct `token` and `spot` names with unsigned decimal data members. The latter two variants share their value writer and use distinct relocated descriptors for `type`.

The `entry::write_entry` callback feeds the existing `write_response` emitter. The fixtures check exact JSON bytes for a Full row containing both an error and a success, including a distinguished final address byte, preserved non-ASCII text, short escapes and a lowercase control escape. A second fixture checks both Boolean values and the full unsigned decimal width. The callback encodes the supported result variants only. Its result content is supplied as offline fixture data.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replica-response-entry/verify.py
cargo test --locked --offline --manifest-path src/node115-replica-response-json/Cargo.toml
```

The [raw offline log](offline-log.txt) records the verifier and crate tests.
