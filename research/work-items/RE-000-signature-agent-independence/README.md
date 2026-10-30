# RE-000: static signature checks without agent autostart

- Component: offline input verification/tooling, no component gate requested.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Inputs: all three pinned captures and detached signatures in provenance/artifacts.json:
  - node94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
  - node115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`;
  - visor `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Public signer fingerprint: `CF2C2EA3DC3E8F042A55FB6503254A9349F1820B`.
- Scope: importing the pinned public verification key and verifying its signatures
  in a fresh temporary GPG home. No private keys, signing, captured execution,
  binary reconstruction, runtime equivalence, or gate completion.

## Observed failure and change

With native GnuPG 2.5.24 and an unavailable agent, the existing import exits 2
after importing the correct public key. `verify_signatures()` aborts before
checking any capture. This was also observed in this session's restricted
local environment. Public signature checking need not launch a secret-key
helper. Use GPG's documented `--no-autostart` option for this public-only flow.
The three actual signatures still verify. The expected fingerprint check and
GPG's cryptographic failure status remain required.

[The GnuPG manual](https://gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html)
defines this option as suppressing automatic startup of gpg-agent/dirmngr.
It does not guarantee that GPG never attempts an existing connection, and this
packet makes no such claim. The isolated home and `--no-options` are retained.

## Reproduce

Materialize pinned LFS captures/submodules. On macOS26.4 arm64 with Python3.12.14
and GnuPG2.5.24:

```sh
HL_GPG_TEST_BINARY=/absolute/path/to/native/gpg python3 -B tests/test_signature_agent_independence.py
python3 -B -m unittest discover -s tests -p test_artifacts.py
make doctor verify test catalogue-check
```

The optional `HL_GPG_TEST_BINARY` selects a native GPG, avoiding a shell wrapper
already configured with `--no-autostart`; otherwise the test uses PATH GPG.
A test-local launcher executes that real GPG with its documented
`--agent-program` option naming an absent helper, making the availability
condition deterministic without mocking GPG, keys, signatures or results.
Only its PATH entry and owned temporary files are changed. It uses fresh homes
and the pinned public key, never personal configuration or keyrings.

On base, the real positive verification and wrong-fingerprint control error
at key import. After the change, all three tests pass: all three valid
signatures, a wrong expected fingerprint, and a one-byte-modified copy of node94
with its original detached signature. The latter explicitly requires GPG's
`BADSIG` status, so a key-import or unrelated setup failure cannot satisfy the
corruption control. Repository captures/signatures and source pins remain
unchanged.

No function-address coordinates apply: this corrects the authenticity preflight
rather than interpreting code. No target or imported source code is run.
GnuPG versions may differ in whether they attempt an agent during public-key
import; the base failure was observed on 2.5.24 and is not claimed for every
version. The next question is whether other static subprocess checks likewise
require unnecessary writable state or background helpers.
