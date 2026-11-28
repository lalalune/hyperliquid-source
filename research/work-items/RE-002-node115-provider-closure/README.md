# RE-002: qualify node #115 Ubuntu provider dependency closure

Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The target requires seven SONAMEs. For each signed Ubuntu archive snapshot, the verifier follows all seven and checks every internal DT_NEEDED edge against the extracted provider set and every associated version-need node against the neighbor's ELF version definitions. The log separately reports the target root version needs. Both provider sets close internally across 11 Jammy edges and 12 Noble edges. The Jammy root is missing GLIBC_2.38 and GLIBC_2.39 from libc.so.6. Noble satisfies all root version nodes. Mixing Noble libstdc++ with the Jammy providers leaves that library without GLIBC_2.36 and GLIBC_2.38 from libc.so.6. Individual symbol checks are covered by prior provider packets. This packet verifies version-node closure only.

Place these files in the offline cache under the names used by the verifier. Paths are relative to https://archive.ubuntu.com/ubuntu/.

| Cache naming | Archive path |
| --- | --- |
| <suite>.InRelease | dists/<suite>/InRelease |
| <suite>.Packages.xz | dists/<suite>/main/binary-amd64/Packages.xz |
| jammy.libc6.deb | pool/main/g/glibc/libc6_2.35-0ubuntu3_amd64.deb |
| noble.libc6.deb | pool/main/g/glibc/libc6_2.39-0ubuntu8_amd64.deb |
| jammy.libgcc.deb | pool/main/g/gcc-12/libgcc-s1_12-20220319-1ubuntu1_amd64.deb |
| noble.libgcc.deb | pool/main/g/gcc-14/libgcc-s1_14-20240412-0ubuntu1_amd64.deb |
| jammy.libstdcxx.deb | pool/main/g/gcc-12/libstdc++6_12-20220319-1ubuntu1_amd64.deb |
| noble.libstdcxx.deb | pool/main/g/gcc-14/libstdc++6_14-20240412-0ubuntu1_amd64.deb |
| jammy.deb | pool/main/o/openssl/libssl3_3.0.2-0ubuntu1_amd64.deb |
| noble.deb | pool/main/o/openssl/libssl3t64_3.0.13-0ubuntu3_amd64.deb |

With Python 3.9+, GNU readelf 2.42, ar, zstd, gpgv and the Ubuntu archive keyring, run from the repository root.

```sh
python3 -B research/work-items/RE-002-node115-provider-closure/verify.py /path/to/cache /path/to/ubuntu-archive-keyring.gpg
```

The verifier checks the 2018 Ubuntu archive signing key, the signed index hash and the package hashes before looking at ELF metadata. It does not run the captured node or any shared object.
