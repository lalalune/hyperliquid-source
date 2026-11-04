# node115 iterator next — owned arena projection

MIT, independently authored from the authenticated original instructions and
pre-Rust observations in `research/work-items/RE-014-tree-next-115/`.
This supplies one previously unclosed dependency of the generic weighted-policy
path; it does not implement the full caller or original Rust collection ABI.

`advance` returns an owned arena item coordinate and updates all nine state
words. State node handles are one-based, while `Node` links are zero-based.
Caller preconditions: a finite acyclic arena with consistent parent/edge links,
keys and values of equal length, at most eleven entries per node, sufficient
children for each traversed level, and in-range ready/lazy node handles and
cursor levels. Those are model inputs, not inferred original type validity.
Malformed links can panic in this safe adapter; the target's panic calls are
unclosed and boundary outcomes do not reproduce their exception behavior.

The packet fixes concrete synthetic byte layouts; Rust owns ordinary Vecs
rather than casting those bytes to original nodes. Returned key/value pointers
are independently observed on the original and projected to item coordinates.
No binary bytes, unlicensed source, external network or captured execution is
used by the Rust library. No Cargo dependency graph is asserted.

From the repository root, using an existing rustc1.94.1 research compiler:

```sh
python3 research/work-items/RE-014-tree-next-115/build.py \
  --rustc /path/to/rustc --output work/tree-next-review
python3 -m unittest discover -s tests -p test_node115_tree_next.py -v
python3 research/work-items/RE-014-tree-next-115/audit.py
```

Output must be new. The builder authenticates and reinterprets original bytes,
compares 3,181 complete transcripts at opt0 and opt3, repeats its own opt3 rlib,
and tests seven separately compiled corruptions against identical inputs.
Raw inputs/expected/actual outputs stay in `work/`; committed hashes and the
62-row target-derived smoke set support review. Compiler1.94.1/LLVM21.1.8 on
macOSarm64 is a research build, not the original Linux node compiler recipe.

Coverage is 121 of126 original iterator instruction addresses. The unvisited
normal-flow jump at0x37c4621 is a gap, alongside two deliberately unexecuted
panic calls and their two UD2s. Deep sparse towers are raw instruction fixtures,
not valid stdBTree occupancy claims. No full component gate is requested.
