# RE-002: qualify Ubuntu OpenSSL 3 providers for node #115

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Coordinates are GNU dynamic version indexes 6 and 7. No executable code was run.

The target lists OPENSSL_3.0.0 under both libssl.so.3 and libcrypto.so.3. The verifier retains the GNU version index and joins each undefined symbol to the correct provider before comparing the symbol name, version, and ELF type. Both Ubuntu base suites supply 30/30 libssl imports and 28/28 libcrypto imports. A wrong-version control fails for a selected import of each provider in each suite. This closes the selected provider symbol-availability question left by target-only inventory. It establishes neither runtime compatibility nor the historical deployment's OpenSSL version.

Place the following files in a local cache. Paths are relative to https://archive.ubuntu.com/ubuntu/:

| File in cache | Archive path |
| --- | --- |
| jammy.InRelease | dists/jammy/InRelease |
| jammy.Packages.xz | dists/jammy/main/binary-amd64/Packages.xz |
| jammy.deb | pool/main/o/openssl/libssl3_3.0.2-0ubuntu1_amd64.deb |
| noble.InRelease | dists/noble/InRelease |
| noble.Packages.xz | dists/noble/main/binary-amd64/Packages.xz |
| noble.deb | pool/main/o/openssl/libssl3t64_3.0.13-0ubuntu3_amd64.deb |

From the repository root, with the Ubuntu archive keyring and Python 3.9+, GNU readelf, ar, zstd and gpgv available, run:

```sh
python3 research/work-items/RE-002-node115-openssl-provider/verify.py /path/to/cache /path/to/ubuntu-archive-keyring.gpg
```

The retained run used GNU readelf 2.42 and the Ubuntu 2018 signing fingerprint F6ECB3762474EDA9D21B7022871920D1991BC93C. The checker verifies the release signatures and signed index hashes, then follows the package stanza hash before reading the two library objects. The log records the selected package revisions and digests. No progress gate changes.
