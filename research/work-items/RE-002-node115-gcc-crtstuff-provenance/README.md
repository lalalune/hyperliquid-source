# RE-002 · GCC package provenance for the four startup helpers after the node entry

The authenticated node #115 ELF contains a 185-byte code region after its entry point that the project already maps to the GCC helpers deregister_tm_clones, register_tm_clones, __do_global_dtors_aux and frame_dummy. Ubuntu's signed GCC 13 update supplies a concrete candidate object for this **whole region**, including its alignment bytes and its two array entries. It also carries the exact GCC build stamp recorded by the node.

| Candidate amd64 package | crtbegin.o .text | crtbeginS.o .text | crtbeginT.o .text | crtbeginS.o after linking | Object stamp in node |
| --- | ---: | ---: | ---: | --- | --- |
| Noble update 13.3.0-6ubuntu2~24.04.1 | 166 bytes | 185 bytes | 229 bytes | 185/185 | Yes |
| Noble base 13.2.0-23ubuntu4 | 166 bytes | 185 bytes | 229 bytes | 185/185 | No |

The two crtbeginS.o inputs have identical unlinked code and different complete object hashes. This makes a historical compiler-package identification from the machine code alone ambiguous. The GCC 13.3 stamp supplies a second observation, although some other linked object could also have contributed it.

## Evidence and limits

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The source symbol names refer to public, packaged GCC code. The target virtual interval is `[0x1419330, 0x14193e9)`, including the padding internal to the source object's .text. The ELF symbols have zero declared function sizes, so this comparison uses the complete input section. The historical [finalizer evidence](../RE-001-node115-fini-array-cleanup/README.md) and [initializer census](../RE-001-node115-init-array-census/README.md) supply the earlier mapping. The scalar DT_INIT and DT_FINI routines occupy other sections.

Before linking 141/185 bytes match; the remaining 44 bytes occupy exactly eleven actual four-byte relocations. The replay reads them from the packaged ET_REL object. For each, it writes S + A - P using destinations independently derived from the capture's section boundaries, symbol-bound GOT slots, PLT jump slot or the self-relative DSO handle. All 185 bytes then match. The source's .fini_array and .init_array refer to .text+0x70 and .text+0xb0 respectively. The verifier checks these against the linked array slots. The [measurement](result.json) retains every field, operation, object digest and stamp. Neither the node nor any downloaded code is executed.

## Replay

From this directory, download both unmodified packages or use cached copies. The scanner requires Python 3.10+, ar and zstd.

```sh
pool=https://archive.ubuntu.com/ubuntu/pool/main/g/gcc-13
curl -fLo update.deb "$pool/libgcc-13-dev_13.3.0-6ubuntu2~24.04.1_amd64.deb"
curl -fLo base.deb "$pool/libgcc-13-dev_13.2.0-23ubuntu4_amd64.deb"
python3 -B verify.py update.deb base.deb
```

Both package checksums come from the libgcc-13-dev amd64 stanza of the respective main/binary-amd64/Packages.xz. Use the [May 15, 2026 update snapshot](https://snapshot.ubuntu.com/ubuntu/20260515T000000Z/dists/noble-updates/) and the [Noble base release](https://archive.ubuntu.com/ubuntu/dists/noble/). Authenticate the signed InRelease with the Ubuntu archive keyring, then match the index hash under its SHA256 header and the package hash inside the decompressed index.

| Distribution | InRelease SHA-256 | Packages.xz SHA-256 |
| --- | --- | --- |
| noble-updates snapshot | `304bbe0f194293a7406e0abb3a1e485dcc55620f73e86113f762ad728db784fd` | `72ad6049c31acea6b809d1a28e17dc3365aea00fd3df51127476576dd57486d3` |
| noble base | `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` | `2a6a199e1031a5c279cb346646d594993f35b1c03dd4a82aaa0323980dd92451` |

The tracked files contain measurements and original verification code. GCC package objects retain their upstream terms and are obtained separately. No first-party gate or byte-window coverage changes.
