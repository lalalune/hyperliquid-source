# node115-vote-choice-weight

A bounded, independently authored `no_std` MessagePack encoding for the
selected node115 choice/weight struct on successful writes. It preserves raw
mode/choice gates; modes outside 0/1 are not asserted to be valid enum values.
It implements neither native growth/error behavior nor a signed action.

Evidence and limits: `research/work-items/RE-005-node115-vote-choice-weight-source/README.md`.
