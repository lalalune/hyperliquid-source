# RE-002: qualify Ubuntu glibc providers for node #115

Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. No captured code or shared libraries are executed. No gate changes.

Jammy matches 249/255 libc imports and lacks four GLIBC_2.38 ISO C23 entry points and two GLIBC_2.39 pidfd entry points. Noble matches all 255. Both supply all five libm imports and the loader import. The comparison treats a defined IFUNC as supplying a FUNC import, without running its resolver.

Place the following files in a local cache. Paths are relative to https://archive.ubuntu.com/ubuntu/:

| File in cache | Archive path |
| --- | --- |
| jammy.InRelease | dists/jammy/InRelease |
| jammy.Packages.xz | dists/jammy/main/binary-amd64/Packages.xz |
| jammy.libc6.deb | pool/main/g/glibc/libc6_2.35-0ubuntu3_amd64.deb |
| noble.InRelease | dists/noble/InRelease |
| noble.Packages.xz | dists/noble/main/binary-amd64/Packages.xz |
| noble.libc6.deb | pool/main/g/glibc/libc6_2.39-0ubuntu8_amd64.deb |

From the repository root, with the Ubuntu archive keyring and Python 3.9+, GNU readelf, ar, zstd and gpgv available, run:

```sh
python3 research/work-items/RE-002-node115-glibc-provider/verify.py /path/to/cache /path/to/ubuntu-archive-keyring.gpg
```

The retained run used GNU readelf 2.42 and the Ubuntu 2018 signing fingerprint F6ECB3762474EDA9D21B7022871920D1991BC93C. The checker verifies the release signatures and signed index hashes, then follows the package stanza hash before reading the two library objects. The log records the selected package revisions and digests. No progress gate changes.
