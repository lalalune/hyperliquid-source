# Node #115 checkpoint clock text

`render_checkpoint_clock` accepts the packed date, seconds-of-day and
fractional words of a restored checkpoint clock. It uses the independently
reconstructed date and time renderers and inserts ASCII `T` between them.
The result is the time string payload. See the
[evidence packet](../../research/work-items/RE-009-node115-render-checkpoint-clock/README.md)
for reproducible checks against the pinned node.

`parse_canonical_checkpoint_clock` reads the formatter's canonical spelling
back into logical year, ordinal, seconds and nanosecond fields. See the
[reader evidence](../../research/work-items/RE-009-node115-canonical-checkpoint-clock-reader/README.md).
