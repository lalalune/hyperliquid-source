# RE-002: qualify Ubuntu unwinder providers for node #115

Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. No captured code or shared libraries are executed. No gate changes.

The target imports 14 versioned unwinder entry points under three GCC version nodes. Both the Jammy GCC 12 provider and Noble GCC 14 provider supply all 14 names at the required versions and ELF types. Each rejects a wrong-version control for _Unwind_Backtrace. The result qualifies symbol availability without establishing runtime unwind equivalence.

Place the following files in a local cache. Paths are relative to https://archive.ubuntu.com/ubuntu/:

| File in cache | Archive path |
| --- | --- |
| jammy.InRelease | dists/jammy/InRelease |
| jammy.Packages.xz | dists/jammy/main/binary-amd64/Packages.xz |
| jammy.libgcc.deb | pool/main/g/gcc-12/libgcc-s1_12-20220319-1ubuntu1_amd64.deb |
| noble.InRelease | dists/noble/InRelease |
| noble.Packages.xz | dists/noble/main/binary-amd64/Packages.xz |
| noble.libgcc.deb | pool/main/g/gcc-14/libgcc-s1_14-20240412-0ubuntu1_amd64.deb |

From the repository root, with the Ubuntu archive keyring and Python 3.9+, GNU readelf, ar, zstd and gpgv available, run:

```sh
python3 research/work-items/RE-002-node115-libgcc-provider/verify.py /path/to/cache /path/to/ubuntu-archive-keyring.gpg
```

The retained run used GNU readelf 2.42 and the Ubuntu 2018 signing fingerprint F6ECB3762474EDA9D21B7022871920D1991BC93C. The checker verifies the release signatures and signed index hashes, then follows the package stanza hash before reading the two library objects. The log records the selected package revisions and digests. No progress gate changes.
