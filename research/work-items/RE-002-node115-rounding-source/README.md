# RE-002: rebuild node #115 binary64 rounding helpers from Rust release source

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Repository base 2da45cb0a761cff6b478e40421699857d87a94df. Public Rust release source 1.95.0, commit 59807616e1fa2540724bfbac14d7976d7e4a3860, rust-src archive SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The published std census already identified three binary64 math bodies. This packet rebuilds them from release source using the existing compiler-builtins harness, then resolves each linked PC-relative field to its actual constant data.

| Helper | ELF VA | Equal outside PC32 fields |
| --- | --- | --- |
| ceil | 0x63f08e0 | 111/119 |
| floor | 0x63effe0 | 144/148 |
| round | 0x63efe40 | 105/113 |

All five fields are four-byte PC32 relocations with addend -4 in the source object. The computed target referents match all five source constants, including the full 16-byte constants in round. An instruction byte mutation outside the fields fails each body comparison. The log records the coordinates and source hashes. This qualifies these functions under the selected profile and does not recover first-party flags, execute the capture, or update a progress gate.

Provision a cache as described in the sibling RE-002-node115-umodti3-source-build packet. Use Rust and Cargo 1.95.0 with the Linux x86-64 target, Python 3.12+, and GNU ar, nm-new, objcopy and objdump (tested with binutils 2.42). In an installed binutils directory with `nm` rather than `nm-new`, expose it as `nm-new` in the supplied tool directory. After provisioning, run from the repository root:

```sh
python3 -B research/work-items/RE-002-node115-rounding-source/verify.py /path/to/cache /path/to/binutils
```

The build uses the existing harness's opt-level 3, 256 codegen units and offline locked Cargo invocation. Only the reproduced objects are inspected.
