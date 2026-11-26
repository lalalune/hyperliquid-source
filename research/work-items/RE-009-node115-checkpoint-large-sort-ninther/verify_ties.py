"""Check the source of the returned pivot address on duplicate checkpoint heights."""
import hashlib
from itertools import product
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def check_target():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    text = next(section for section in sections(data) if section["name"] == ".text")
    bias = text["address"] - text["offset"]
    # The helper's complete FDE and the caller's return-to-swap span, in ELF VAs.
    for start, end, digest in [
        (0x1550340, 0x15503e7, "389102665a16da2afd6340e15305bbdd7a091a4cd19485049caffe36239cc798"),
        (0x1550846, 0x1550867, "5068ef5a0b22b3eca3e54394d969429b47da5d94dc04488b867375a0719b307d"),
    ]:
        assert text["address"] <= start < end <= text["address"] + text["size"]
        assert hashlib.sha256(data[start-bias:end-bias]).hexdigest() == digest


def from_conditions(words, slots):
    # SETB records unsigned <. The two CMOVNE instructions select candidate
    # addresses, leaving the second argument in RBX when neither move fires.
    a, b, c = slots
    ab = words[a] < words[b]
    selected = c if (words[b] < words[c]) != ab else b
    return a if (words[a] < words[c]) != ab else selected


def by_rank(words, slots):
    # Equal keys occupy the reverse of their order in this call's arguments.
    return sorted(reversed(slots), key=words.__getitem__)[1]


def pivot(words, choose):
    def select(slots, step):
        if step >= 8:
            step //= 8
            slots = [select((base, base + 4 * step, base + 7 * step), step) for base in slots]
        return choose(words, slots)

    step = len(words) // 8
    return select((0, 4 * step, 7 * step), step)


def main():
    check_target()
    for words in product((0, (1 << 63), (1 << 64) - 1), repeat=3):
        assert from_conditions(words, (0, 1, 2)) == by_rank(words, (0, 1, 2))
    # Initial mixed input: the top-level median value is one at either slot.
    # The first swap moves the zero to the address actually returned.
    words = [1] * 64
    words[0] = 0
    for index in (7, 39, 63):
        words[index] = 2
    observed = pivot(words, from_conditions)
    forward_stable = pivot(words, lambda items, slots: sorted(slots, key=items.__getitem__)[1])
    assert observed == pivot(words, by_rank) == 32
    assert forward_stable == 36 and words[observed] == words[forward_stable] == 1
    swapped = words.copy()
    swapped[0], swapped[observed] = swapped[observed], swapped[0]
    assert swapped[32] == 0 and swapped[36] == 1
    print("27 unsigned triples agree on the returned slot")
    print("N=64: forward-stable slot=36, observed slot=32, pivot=1, zero moved to slot 32")
    for count, expected in [(64, 36), (512, 292), (4096, 2340)]:
        equal = [0] * count
        assert pivot(equal, from_conditions) == pivot(equal, by_rank) == expected
        print(f"N={count}: all equal, selected slot={expected}")


if __name__ == "__main__":
    main()
