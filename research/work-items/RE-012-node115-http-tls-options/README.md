# HTTP client TLS defaults and connection option lowering

Target Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. Partial HL115-082 / RE-012 research; the captured program was not executed or emulated.

One first-party HTTP-client construction path creates a TLS context with the default trust-path call and peer verification enabled, and stores three selected option bytes in the constructed client. Separately, the TLS connection adapter shows how those option bytes control SNI, certificate-name/IP parameters and an optional override of peer verification. The dataflow connecting this particular client object to a particular live request or named service remains open; the two observations are not presented as a proven end-to-end service policy.

## Prior work and scope

[#3137](https://github.com/lalalune/hyperliquid-source/pull/3137) maps SSL context result representation and partial construction cleanup. `RE-012-tls-connect-bio-handoff-115` and `RE-012-tls-handshake-resume-115` own the subsequent BIO/handshake result boundaries. `RE-014-host-ip-gates-115` and `RE-012-ipv6-groups-115` study the two IP parsing helpers. This packet uses those boundaries, rather than reconstructing their leaf algorithms or a TLS library.

The new observations are the concrete first-party client constructor's default-byte preparation and storage, the context verification calls, and the separate per-connection lowering of three input option bytes into actual imported OpenSSL calls. No complete TLS trust, certificate acceptance, peer identity, reconnect, or whole-service policy is claimed.

## One client constructor's defaults

`0x15a02d0` has a Location in `base/src/http_client.rs:29`. It writes the little-endian dword `0x00010000` into configuration offsets `+0x40..+0x43` and calls `0x475c2e0` at `0x15a03af`; those first three bytes are therefore `0, 0, 1`. The builder calls `TLS_method` and `0x5babea0`. On the selected normal success continuation, the latter calls imported `SSL_CTX_set_default_verify_paths`, then calls imported `SSL_CTX_set_verify(context, 1, NULL)` after its intervening configuration succeeds. Its non-success/error branches remain part of the recorded body; no inference is made that default paths exist or contain a particular certificate.

On this selected successful builder path, `0x475c692..0x475c6b7` copies input bytes `+0x42/+0x41/+0x40` respectively into result bytes `+0x10/+0x11/+0x12`. Thus the actual values are `1, 0, 0`. The caller takes the successful result payload, builds its connector record, and calls `0x15c86f0`; that helper copies the 32-byte connector into the constructed client at `+0x88..+0xa7`. The Location binds first-party source context but does not identify a specific remote service or prove how a later request retrieves this stored connector.

## Separate per-connection lowering

For a valid options object supplied to `0x2631730`, the adapter takes its bytes at `+8`, `+9`, and `+0xa`. It copies the first unchanged to a temporary, XORs the second with 1, and, if the third is nonzero, calls imported `SSL_set_verify(ssl, 0, NULL)`. It then passes that SSL pointer, the two lowered bytes and the caller's supplied name pointer/length to `0x2cd83b0` → `0x5bac020`. These facts describe the input object at this separate boundary; equality to the constructed client's stored object is not assumed.

In `0x5bac020`:

- If the first lowered byte is nonzero, the two existing IPv4/IPv6 parsers are tried. On the selected non-IP branch, the name is passed to `0x5bab7f0`, which supplies it to imported `SSL_ctrl` with command `0x37`, zero third argument, and the copied name pointer. Complete-IP parser success with no remainder bypasses this SNI call.
- If the second lowered byte is nonzero, the adapter gets the parameter object through `SSL_get0_param`, supplies host flag 4, and selects imported `X509_VERIFY_PARAM_set1_host` for the non-IP branch or `X509_VERIFY_PARAM_set1_ip` for the parsed IP branches. On a nonpositive result it invokes error-collection helper `0x5bad380` and tests the helper’s tagged result; the sentinel branch can still reach the success continuation.
- Zero lowered bytes bypass their respective steps. A nonzero third original byte's `SSL_set_verify(...,0,NULL)` is distinct from the hostname/IP parameter switch; neither should be silently inferred from the other.

The observed default byte triple would lower to SNI enabled, hostname/IP parameter setting enabled, and no peer-verification override **if** that same triple reaches this separate adapter unchanged. The needed client-to-request binding and the supplied name's origin are not established here. OpenSSL version/configuration, environment trust store, parser edge cases, callbacks, handshake and certificate-match results are outside this static packet. In particular, this is not evidence that any specific endpoint is trusted or rejected.

## Validation

The verifier binds eight complete windows, 4,314 bytes / 996 instructions, 89 facts and 78 altered-instruction controls to the complete target digest. Imported symbol facts are read from dynamic relocation and symbol tables. The checks establish selected code/data bindings; the static dataflow interpretation and normal-return premises require independent review.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-012-node115-http-tls-options/verify.py --target /path/to/original/hl-node
```
