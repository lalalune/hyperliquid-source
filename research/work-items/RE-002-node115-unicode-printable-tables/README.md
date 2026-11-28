# RE-002: reproduce node #115 Unicode printable lookup tables

Target Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src archive SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The standard library census identifies the 692-byte `is_printable` body at ELF VA 0x1681aa0 using a published object. This packet rebuilds core from release source with frame pointers enabled and uses six actual PC32 relocation records to compare the complete table sections. The linked target fields point to six byte-equal ranges in .rodata. Their lengths total 1,460 bytes. The verifier rejects a one-byte mutation in each table. The recorded output lists sizes, addresses, and hashes for independent checks.

The result covers only the six table referents. Other relocation targets and full code equivalence remain outside the claim. The capture is not executed and no acceptance gate changes.

From the root, provision the Rust source cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42, run:

```sh
python3 -B research/work-items/RE-002-node115-unicode-printable-tables/verify.py /path/to/cache /path/to/binutils
```

The binutils directory must expose GNU ar, nm-new, objdump and objcopy (nm-new may point to the installed GNU nm). The original run used the target x86_64-unknown-linux-gnu and no network during the build.
