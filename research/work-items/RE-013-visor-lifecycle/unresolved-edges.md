# RE-013 unresolved lifecycle edges

These are deliberate non-claims, ordered by their value for a later packet.

1. Recover the producer and complete semantics of the quorum flag tested at
   `0x416f47`, including key identities, threshold, replay domain, and error
   precedence.  The current packet proves only that false rejects publication.
2. Resolve the command helper below `0x42a290`: argv/shell construction, output
   capture, exit-status mapping, environment, keyring, and quoting.  The current
   path proves that `gpg --verify` reaches it and its error variant is rejected.
3. Close the async filesystem helpers used by `0x416f30..0x41718a` to exact
   source/destination paths, permissions, fsync behavior, rename order, and
   cleanup after each partial failure.
4. Recover the transport helpers below `0x3d8250` / `0x3d86b0`: URL selection,
   TLS policy, redirects, size bounds, response status checks, timeout units,
   and partial-file behavior.
5. Recover the complete metadata record schema and precedence among publisher,
   index, hardfork, readiness, and binary-version checks.  Current observations
   bind the two metadata filenames and several rejection branches only.
6. Establish the time source and exact comparison behind the one-minute
   readiness override.  The diagnostic and return branches are bound, but the
   clock semantics are not.
7. Recover complete child retry limits/backoff units, inherited file
   descriptors/environment/current directory, and all graceful-termination
   branches before signal 9.
8. Validate observable behavior only in a future safe reimplementation or
   synthetic harness.  This packet intentionally performs no captured-binary,
   network, child-process, or filesystem-effect execution.
