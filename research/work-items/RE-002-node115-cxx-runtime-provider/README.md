# RE-002: qualify two Ubuntu libstdc++ candidates for node #115

**Build decision.** The original Ubuntu Noble amd64 `libstdc++6` package exports all 164 strong and one weak C++ symbol/version/type combinations required by node #115. The original Focal package misses three strong combinations. This rules out the Focal library **by itself** as the complete C++ symbol provider for this artifact. The Noble result qualifies one input for a candidate build image, subject to the other dependencies and runtime testing.

Target: Linux x86-64 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base: `2da45cb0a761cff6b478e40421699857d87a94df`. The [prior import study](../RE-002-node115-versioned-imports/README.md) records the target-side owner of three recent versioned imports. This packet qualifies the complete set owned by `libstdc++.so.6` against real package-side definitions, addressing the public system-library requirement in [#3929](https://github.com/lalalune/hyperliquid-source/issues/3929).

| Base release | libstdc++6 amd64 | Library | Strong matches | Weak matches |
|---|---|---|---:|---:|
| Focal | 10-20200411-0ubuntu1 | libstdc++.so.6.0.28 | 161/164 | 1/1 |
| Noble | 14-20240412-0ubuntu1 | libstdc++.so.6.0.33 | 164/164 | 1/1 |

The target imports 137 functions, 26 objects and two thread-local symbols from this library. Focal exports the same mangled `std::condition_variable::wait(std::unique_lock<std::mutex>&)` at `GLIBCXX_3.4.11`; the node explicitly requests `GLIBCXX_3.4.30`. Noble exports both versions. Focal also lacks the requested `GLIBCXX_3.4.29` exports for `std::__throw_bad_array_new_length()` and the no-argument C++11-ABI `basic_string<char>::reserve()`. All three imports bind globally. Inspect [result.json](result.json) for every required symbol, type, binding, version, package digest and observed candidate versions.

## Chain of evidence

1. Verify the historical base-suite `InRelease` SHA-256 and OpenPGP signatures using Ubuntu's archive keyring. Require the 2018 Ubuntu archive signer fingerprint `F6ECB3762474EDA9D21B7022871920D1991BC93C`. Focal's file also carries the 2012 signature `790BC7277767219C42C86F933B4FE6ACC0B21F32`. These immutable publication snapshots deliberately precede the updates/security pockets.
2. Follow the signed SHA-256 entry for `main/binary-amd64/Packages.xz`, then the sole amd64 `Package: libstdc++6` stanza to the package path, length and SHA-256. Read the regular file named by the package's SONAME symlink, record its hash, and check the ELF's own SONAME.
3. Verify the complete node's digest. Join the undefined dynamic symbols to their version-need owner by version index. Compare only those owned by `libstdc++.so.6` against defined, externally visible dynamic exports with the same name, GNU version and ELF type. A non-default compatibility alias is eligible when it supplies the explicitly requested version. Preserve weak target imports separately.
4. Independently cross-check all versioned name pairs through GNU objdump's BFD dynamic-symbol view, including all three natural Focal negatives. Focused controls also reject a changed package byte and an untrusted archive keyring.

All inputs are read as files. No target, package maintainer scripts or provider code ran. No package or key is vendored. Static symbol coverage does not identify the deployed package, prove behavior, object-layout or loader compatibility, qualify other needed libraries, earn first-party byte credit, or close a component gate.

## Replay

Requirements: Python 3.9+, GNU readelf/objdump, `ar`, `zstd`, `gpgv`, and `curl` for initial acquisition. Use a trusted Ubuntu installation's `/usr/share/keyrings/ubuntu-archive-keyring.gpg` containing both archive keys. On another platform use an equivalent keyring from the [Ubuntu archive-keyring package](https://packages.ubuntu.com/noble/ubuntu-keyring) and check the fingerprints above. Commands run from this packet directory.

```sh
cache=$(mktemp -d)
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
python3 verify.py "$cache" --fetch --keyring "$keyring"
python3 verify.py "$cache" --keyring "$keyring"
PYTHONDONTWRITEBYTECODE=1 python3 test_provider.py "$cache" --keyring "$keyring"
```

The first run downloads the six pinned release/index/package files from `https://archive.ubuntu.com/ubuntu/`. Later runs consume only the cache and compare the complete normalized evidence to the committed result. `--readelf` and `--objdump` accept GNU tool paths on non-Linux hosts. The recorded run used arm64 macOS, Python 3.14.3, GNU binutils 2.47.20260726 and GnuPG 2.5.20. Four focused tests passed. The package sizes are 503,412 and 795,158 bytes respectively. Provider DSOs are 1,952,928 and 2,592,144 bytes.
