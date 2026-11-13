# Node #115 raw-map absent-key ring insertion

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Findings are conditional static analysis.

On the non-sentinel branch with lookup result bit 0 set, `0x4dbe436..0x4dbe46c` builds a 24-byte input from the key and 12-byte value and calls `0x57ec710` with the lookup index. At `0x57ec718..0x57ec71f`, that helper checks index <= count; a larger index goes to an indirect error path. If count equals capacity it calls the grow slot before proceeding.

Assuming valid ring metadata and successful growth, the helper computes `count - index`. If this suffix is shorter than the prefix, `0x57ec752..0x57ec781` passes wrapped source and destination positions and the suffix length to `0x58127f0`. Otherwise `0x57ec799..0x57ec7b2` decrements the head modulo capacity and calls the same movement helper for the prefix length. Afterwards `0x57ec7ca..0x57ec7e5` computes the slot, increments count, and writes all 24 input bytes. The call-site passes through the insertion index for its result. This documents the branch and data flow; full movement-helper semantics, failed allocation, invalid rings and real runtime reachability remain outside scope.

Reproduce: `python3 research/work-items/RE-017-node115-raw-map-ring-insert/verify.py` authenticates the target and checks instruction and call anchors with mutation rejection, without executing the target. Exact windows are in `windows.txt`.
