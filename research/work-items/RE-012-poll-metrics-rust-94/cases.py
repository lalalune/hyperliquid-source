"""Finite u64-nanosecond projection of one normal Pending poll."""
import itertools
import random

MODEL = 'connections_accept_metrics_static'
COMPONENT = 'node94-poll-metrics'
OWNERS = [0x203f3e0, 0x2041c60]
OFFSETS = [0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88]
MASK = (1 << 64) - 1
MUTANTS = {
    'idle_includes_equality': ('woke > last_end', 'woke >= last_end'),
    'schedule_without_wake': ('if woke != 0', 'if true'),
    'delay_equality_is_short': ('delay < long_delay', 'delay <= long_delay'),
    'poll_equality_is_fast': ('poll < slow_poll', 'poll <= slow_poll'),
    'first_delay_uses_start': ('increments[7] = now;', 'increments[7] = start;'),
    'delay_uses_wrapping': ('now.saturating_sub(woke)', 'now.wrapping_sub(woke)'),
    'poll_uses_wrapping': ('end.saturating_sub(start)', 'end.wrapping_sub(start)'),
    'counter_add_saturates': ('value.wrapping_add(increment)', 'value.saturating_add(increment)'),
    'last_end_uses_start': ('last_end: end,', 'last_end: start,'),
}


def corpus(data, model):
    model.check_metrics(model.facts(model.Image(data)))
    inputs, expected = [], []

    def add(first, now, woke, last, start, end, long_delay, slow_poll, seed):
        inc, last_result = model.poll_metrics(bool(first), now, woke, last, start, end, long_delay, slow_poll)
        # Separate tuple construction checks the maintained dict-offset model.
        delay, poll = max(now - woke, 0), max(end - start, 0)
        values = [first, int(woke > last), int(woke != 0), int(poll < slow_poll), int(poll >= slow_poll),
                  int(woke != 0 and delay >= long_delay), int(woke != 0 and delay < long_delay),
                  now if first else 0, max(woke - last, 0), delay if woke else 0,
                  poll if poll < slow_poll else 0, poll if poll >= slow_poll else 0,
                  delay if woke and delay < long_delay else 0, delay if woke and delay >= long_delay else 0]
        assert values == [inc.get(off, 0) for off in OFFSETS] and last_result == end
        baseline = [(seed + i) & MASK for i in range(14)]
        totals = [(a + b) & MASK for a, b in zip(baseline, values)]
        inputs.append(' '.join(map(str, [first, now, woke, last, start, end, long_delay, slow_poll, seed])))
        expected.append(' '.join(map(str, values + [end] + totals)))

    points = [0, 1, 2, 3]
    for first, now, woke, last, start, end, long_delay, slow_poll in itertools.product(
            [0, 1], points, points, points, points, points, [0, 1, 3], [0, 1, 3]):
        add(first, now, woke, last, start, end, long_delay, slow_poll, MASK - 3)
    edges = [0, 1, 2, (1 << 63) - 1, 1 << 63, MASK - 1, MASK]
    rng = random.Random(0x203F3E0)
    for _ in range(4000):
        args = [rng.choice(edges) if rng.randrange(2) else rng.getrandbits(64) for _ in range(8)]
        add(rng.randrange(2), *args)
    return '\n'.join(inputs) + '\n', expected
