# Reconstruction implementation

New project-authored implementation belongs here. Establish a compilable Cargo
workspace only as actual components are recovered. The reference snapshot has
no Cargo manifests and must not be mistaken for a working implementation.

Current standalone components include:

- `node94-gossip-bid-admission/`: independently authored wrapper gates of the
  node #94 gossipPriorityBid action, replayed over evidence-packet vectors.
- `node94-tcp-frame/`: an independently authored, offline codec for the
  evidence-qualified node #94 TCP frame header, bounds, compression policy,
  LZ4 decode path, writer, chunk calculations, and optional asynchronous frame
  I/O over caller-owned Tokio streams. It contains no sockets or
  live peer transport.
