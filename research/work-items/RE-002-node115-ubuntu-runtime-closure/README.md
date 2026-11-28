# RE-002 · one Ubuntu amd64 package set for the node #115 loader dependency graph

The Ubuntu Noble base archive supplies a consistent set of providers for the linked ELF imports in node #115. All seven directly named libraries and all 19 dependency edges resolve using payloads from the same signed release. Across those edges, all 112 requested GNU version-node entries and all 1,401 versioned dynamic-symbol entries occur at their named providers. Of these symbol entries, 498 belong to the node and 903 belong to its dependencies. Each edge counts a caller's requirements separately.

| Single base release | Distinct providers | DT_NEEDED edges | Requested symbol entries | Missing at named provider |
| --- | ---: | ---: | ---: | ---: |
| Ubuntu 24.04 Noble | 7 | 19 | 1,401 | 0 |
| Ubuntu 22.04 Jammy | 7 | 18 | 1,367 | 6 |

Both package sets supply the seven SONAMEs. Jammy lacks libc version nodes GLIBC_2.38 and GLIBC_2.39. All six missing imports are direct node requirements. Its libraries satisfy their own versioned requirements within that release. Noble's extra dependency edge is from libgcc_s.so.1 to ld-linux-x86-64.so.2. Private ABI requirements between libm, libc and the loader also resolve within the Noble package set.

## Interpreter and package ownership

The node's PT_INTERP value is `/lib64/ld-linux-x86-64.so.2`. In Noble, **base-files** supplies `/lib64 → usr/lib64`; **libc6** supplies `/usr/lib64/ld-linux-x86-64.so.2 → ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` and the final regular file. Omitting the base-files symlink leaves the interpreter pathname unresolved even when every DSO is present. Jammy's libc6 ships the interpreter symlink directly at the requested path.

The remaining Noble providers come from libc6 (libc, libm), libgcc-s1, libssl3t64 (libssl and libcrypto), and libstdc++6. Jammy uses libssl3 for its OpenSSL objects. [evidence.json](evidence.json) records all provider bytes by SHA-256, package versions and member paths, each edge's required namespaces, the missing Jammy names, and a digest of each caller's sorted required symbol list.

## Method and scope

Task RE-002, foundation; base `2da45cb0a761cff6b478e40421699857d87a94df`. The target ELF SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. For each release, the verifier checks the pinned InRelease digest and Ubuntu archive signature, the signed main/binary-amd64 index hash and size, and the index's hash and size for each of five .deb packages. It reads regular library members and symlinks directly from the data archives. The control and maintainer scripts are never run.

Starting at the pinned binary, the static traversal follows each DT_NEEDED name once per caller through the package-provided default amd64 library directories. It checks that alternative lookup paths resolve to the same member, the ELF machine and SONAME match, and that the PT_INTERP alias reaches the same loader as the direct dependency. For each caller, a GNU version index identifies the named DSO and namespace. The verifier compares each versioned undefined name against externally visible exports of that owner. The recorded unversioned undefined entries have weak binding and lie outside the versioned denominator.

This qualifies a **candidate layout and exported names**. It leaves the historical machine's installed package revisions, runtime interposition, relocations, IFUNC selection, CPU-specific alternatives, dlopen modules and execution behavior open. Results apply to these two original base releases, independently of subsequent Ubuntu updates.

## Reproduce

Use Python 3.10+, GNU readelf, ar, gpgv, zstd and curl. Supply a trusted Ubuntu archive keyring containing the 2018 automatic signing key, fingerprint `F6ECB3762474EDA9D21B7022871920D1991BC93C`. On Ubuntu the ubuntu-keyring package supplies the path below. All target and package objects are read as data. No root privileges, Linux runtime, target execution or target networking are required.

```sh
packet=research/work-items/RE-002-node115-ubuntu-runtime-closure
cache=$(mktemp -d)
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
python3 -B "$packet/verify.py" --cache "$cache" --keyring "$keyring" --fetch > "$cache/fetched.json"
diff -u "$packet/evidence.json" "$cache/fetched.json"
python3 -B "$packet/verify.py" --cache "$cache" --keyring "$keyring" > "$cache/offline.json"
cmp "$cache/fetched.json" "$cache/offline.json"
```

The 2018 signature and pinned InRelease identify historical evidence. This replay does not use the archives as an up-to-date package source.
