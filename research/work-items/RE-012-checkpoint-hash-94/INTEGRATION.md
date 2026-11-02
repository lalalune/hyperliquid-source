# Integration with current main

The hash implementation was applied to main at
`2c75904241b9165693d40dea8b0d0d340f8e22b3`. All six implementation/test source
hashes in `build-receipt.json` remain identical to the independently tested
source at `a332eefc719978b387ca00e5b3dc09bc525e3b25`.

The new `make verify` packet checker rejected the changed live `Cargo.toml`,
`Cargo.lock` and `src/lib.rs`: the earlier TCP-frame packet still attests their
pre-hash versions. This blocked validation of this active reconstruction task.
The exact prior bytes from the main base commit are therefore preserved under
that packet's `src/node94-tcp-frame/` directory. Its existing relative manifest
entries resolve to these immutable snapshots, with the original digests intact.
`integration-snapshots.json` records each path, size, source commit and digest.

The historical manifest and strict verifier are unchanged. These three files
are historical evidence, not a new buildable workspace. The actual component
still builds from the live `src/node94-tcp-frame/` manifest. No dependency pin,
imported input, progress gate or registered comparison window changed.

Validation of the source commit and validation of this integration remain
separate; a full-suite result for the former is not a full-suite claim for all
later changes on main.
