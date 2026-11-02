"""Conditional branch projection with raw flag values and IEEE comparisons."""
import itertools
import random
import struct

MODEL = 'firewall_update_cycle_static'
COMPONENT = 'node94-firewall-cycle'
OWNERS = [0x28f6960, 0x27cdf00]
MUTANTS = {
    'any_nonzero_skips': ('skip_byte == 1', 'skip_byte != 0'),
    'throttle_equality_runs': ('elapsed > interval', 'elapsed >= interval'),
    'unordered_throttle_runs': ('elapsed > interval', '!(elapsed <= interval)'),
    'missing_timestamp_does_not_run': ('last_word == 0 ||', 'last_word != 0 ||'),
    'throttle_suppresses_compute': ('compute: true,', 'compute: maybe_update,'),
    'wrong_equality_combination': ('!equalities.into_iter().all(|same| same)', '!equalities.into_iter().any(|same| same)'),
    'wrong_loader_flag': ('loader_flag: 1,', 'loader_flag: 0,'),
}


def as_float(bits):
    return struct.unpack('<d', struct.pack('<Q', bits))[0]


def corpus(data, model):
    facts = model.facts(model.Image(data))
    model.check_skip(facts); model.check_compare(facts)
    values = [0, 1, 0x8000000000000000, 0xbff0000000000000, 0x3ff0000000000000,
              0x4007ffffffffffff, 0x4008000000000000, 0x4008000000000001,
              0x7fefffffffffffff, 0x7ff0000000000000, 0xfff0000000000000,
              0x7ff8000000000000, 0x7ff0000000000001, 0xfff8000000000123]
    inputs, expected = [], []

    def add(skip, last, eb, ib, flags):
        elapsed, interval = as_float(eb), as_float(ib)
        equalities = [bool(flags & (1 << i)) for i in range(3)]
        changed = flags != 7
        assert changed == model.changed(*equalities)
        got = model.cycle(skip == 1, last != 0, elapsed, interval, changed)
        # Explicit branch outcomes of the captured equality/ordered-above gates.
        if skip == 1:
            oracle = [0, 0, 0, 0, 0]
        else:
            ran = last == 0 or (elapsed > interval)
            oracle = [int(ran), 1, 1, int(changed), 1]
        assert oracle == [int(got[k]) for k in ['maybe_update', 'compute', 'check', 'update', 'loader_flag']]
        inputs.append(f'{skip} {last} {eb} {ib} {flags}')
        expected.append(' '.join(map(str, oracle)))

    for args in itertools.product([0, 1, 2, 255], [0, 1, 0x80000000, 0xffffffff], values, values, range(8)):
        add(*args)
    rng = random.Random(0x28F6960)
    for _ in range(2000):
        add(rng.randrange(256), rng.getrandbits(32), rng.getrandbits(64), rng.getrandbits(64), rng.randrange(8))
    return '\n'.join(inputs) + '\n', expected
