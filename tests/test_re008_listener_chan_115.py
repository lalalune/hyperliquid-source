"""Tests for the RE-008 listener channel tool: the pure model, the generators, and the committed evidence files."""

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import re008_listener_chan_115 as tool  # noqa: E402

EVIDENCE = ROOT / "research" / "work-items" / "RE-008-listener-queue-channel-115"
BASE = tool.HEAP_BASE


def fresh(sem=0):
    data = tool.blank_image()
    brk = tool.init_channel(data, tool.Rng(1), sem)
    memory = tool.Image2(data)
    return memory, tool.ChannelModel(memory, brk)


def message(tag, fill=0x11):
    return tag.to_bytes(8, "little") + bytes([fill]) * 56


class ModelSendTests(unittest.TestCase):
    def test_send_stores_message_and_advances_state(self):
        memory, model = fresh()
        memory.put(tool.MSG, message(21))
        self.assertEqual(model.send(tool.SENDER, tool.MSG), 5)
        self.assertEqual(memory.r(tool.CHAN + 0x1C0), 2)
        self.assertEqual(memory.r(tool.CHAN + 0x88), 1)
        self.assertEqual(memory.r(tool.ARC + 0x10), 2)
        self.assertEqual(memory.r(tool.BLOCKS + 0x810), 1)
        self.assertEqual(memory.bytes(tool.BLOCKS, 64), message(21))

    def test_sixty_fourth_message_goes_to_second_block(self):
        memory, model = fresh()
        for number in range(33):
            memory.put(tool.MSG, message(number))
            model.send(tool.SENDER, tool.MSG)
        second = memory.r(tool.BLOCKS + 0x808)
        self.assertEqual(second, tool.BLOCKS + tool.BLOCK_STRIDE)
        self.assertEqual(memory.r(second + 0x800), 32)
        self.assertEqual(memory.r(second + 0x810), 1)
        self.assertEqual(memory.r(tool.BLOCKS + 0x810), 0x1FFFFFFFF)
        self.assertEqual(memory.r(tool.BLOCKS + 0x818), 33)
        self.assertEqual([entry for entry in model.log if entry[0] == "alloc"], [("alloc", second)])

    def test_closed_channel_drops_message_and_returns_zero(self):
        memory, model = fresh(sem=1)
        memory.put(tool.MSG, message(7))
        self.assertEqual(model.send(tool.SENDER, tool.MSG), 0)
        self.assertEqual(model.log, [("drop", message(7).hex())])
        self.assertEqual(memory.r(tool.ARC + 0x10), 1)
        self.assertEqual(memory.r(tool.CHAN + 0x88), 0)

    def test_closed_channel_with_reserved_tag_reports_success_without_drop(self):
        memory, model = fresh(sem=3)
        memory.put(tool.MSG, message(tool.NICHE4))
        self.assertEqual(model.send(tool.SENDER, tool.MSG), 5)
        self.assertEqual(model.log, [])
        self.assertEqual(memory.r(tool.ARC + 0x10), 2)

    def test_semaphore_overflow_aborts_after_the_refcount_bump(self):
        memory, model = fresh(sem=tool.M64 - 1)
        memory.put(tool.MSG, message(1))
        with self.assertRaises(tool.Panicked):
            model.send(tool.SENDER, tool.MSG)
        self.assertEqual(memory.r(tool.ARC + 0x10), 2)

    def test_waker_fires_only_from_state_zero(self):
        for state, fires in ((0, True), (1, False), (2, False), (3, False)):
            memory, model = fresh()
            memory.w(tool.CHAN + 0x110, state)
            memory.w(tool.CHAN + 0x100, tool.VTABLE)
            memory.w(tool.CHAN + 0x108, 0x1234)
            memory.put(tool.MSG, message(1))
            model.send(tool.SENDER, tool.MSG)
            woke = [entry for entry in model.log if entry[0] == "wake"]
            self.assertEqual(bool(woke), fires, state)
            if fires:
                self.assertEqual(woke, [("wake", tool.WAKE_IDS[0], 0x1234)])
                self.assertEqual(memory.r(tool.CHAN + 0x100), 0)
                self.assertEqual(memory.r(tool.CHAN + 0x110), 0)
            else:
                self.assertEqual(memory.r(tool.CHAN + 0x110), state | 2)

    def test_block_index_overflow_panics(self):
        memory, model = fresh()
        memory.w(tool.BLOCKS + 0x800, tool.M64 - 31)
        memory.w(tool.TX + 8, 32)
        memory.put(tool.MSG, message(1))
        with self.assertRaises(tool.Panicked):
            model.send(tool.SENDER, tool.MSG)


class ModelPopTests(unittest.TestCase):
    def push(self, memory, model, count):
        for number in range(count):
            memory.put(tool.MSG, message(number + 16))
            model.send(tool.SENDER, tool.MSG)

    def test_empty_channel_reports_reserved_tag_five(self):
        memory, model = fresh()
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), tool.NICHE5)
        self.assertEqual(memory.r(tool.RX + 0x10), 0)

    def test_closed_empty_channel_reports_tag_four(self):
        memory, model = fresh()
        memory.w(tool.BLOCKS + 0x810, 1 << 33)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), tool.NICHE4)

    def test_fifo_across_block_boundary_and_block_reuse(self):
        memory, model = fresh()
        self.push(memory, model, 70)
        seen = []
        for _ in range(70):
            model.pop(tool.OUT, tool.RX, tool.TX)
            seen.append(memory.r(tool.OUT))
        self.assertEqual(seen, list(range(16, 86)))
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), tool.NICHE5)
        self.assertEqual(memory.r(tool.RX + 0x10), 70)

    def test_reserved_tag_in_a_ready_slot_does_not_advance_the_index(self):
        memory, model = fresh()
        memory.put(tool.MSG, message(tool.NICHE4))
        model.send(tool.SENDER, tool.MSG)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), tool.NICHE4)
        self.assertEqual(memory.r(tool.RX + 0x10), 0)

    def test_tag_three_advances_the_index(self):
        memory, model = fresh()
        memory.put(tool.MSG, message(tool.NICHE4 - 1))
        model.send(tool.SENDER, tool.MSG)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.RX + 0x10), 1)

    def test_ready_bit_uses_the_index_modulo_thirty_two(self):
        memory, model = fresh()
        self.push(memory, model, 33)
        for _ in range(33):
            model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), 48)
        self.assertEqual(memory.r(tool.RX + 0x10), 33)

    def test_released_block_is_recycled_behind_the_tail(self):
        memory, model = fresh()
        self.push(memory, model, 40)
        for _ in range(40):
            model.pop(tool.OUT, tool.RX, tool.TX)
        self.push(memory, model, 60)
        self.assertEqual([entry for entry in model.log if entry[0] == "alloc"],
                         [("alloc", tool.BLOCKS + tool.BLOCK_STRIDE), ("alloc", tool.BLOCKS + 2 * tool.BLOCK_STRIDE)])
        self.assertEqual(memory.r(tool.BLOCKS + 0x800), 64)
        self.assertEqual(memory.r(tool.RX + 8), tool.BLOCKS + tool.BLOCK_STRIDE)


class LocateBoundaryTests(unittest.TestCase):
    """Hand-built chains for the block locate/extend rules."""

    def chain(self, count, base=0):
        memory, model = fresh()
        blocks = [tool.BLOCKS + tool.BLOCK_STRIDE * i for i in range(count)]
        for i, block in enumerate(blocks):
            memory.w(block + 0x800, base + 32 * i)
            memory.w(block + 0x808, blocks[i + 1] if i + 1 < count else 0)
            memory.w(block + 0x810, 0)
            memory.w(block + 0x818, 0)
        model.brk = tool.BLOCKS + tool.BLOCK_STRIDE * count
        return memory, model, blocks

    def test_same_block_needs_no_walk(self):
        memory, model, blocks = self.chain(3)
        for index in (0, 1, 31):
            self.assertEqual(model.locate(tool.TX, index), blocks[0])
        self.assertEqual(model.log, [])

    def test_walk_to_existing_block_does_not_allocate(self):
        memory, model, blocks = self.chain(3)
        self.assertEqual(model.locate(tool.TX, 64), blocks[2])
        self.assertEqual(model.log, [])
        self.assertEqual(memory.r(tool.TX), blocks[0])

    def test_walk_allocates_missing_blocks_in_order(self):
        memory, model, blocks = self.chain(1)
        found = model.locate(tool.TX, 96)
        first = tool.BLOCKS + tool.BLOCK_STRIDE
        self.assertEqual(model.log, [("alloc", first), ("alloc", first + tool.BLOCK_STRIDE), ("alloc", first + 2 * tool.BLOCK_STRIDE)])
        self.assertEqual(found, first + 2 * tool.BLOCK_STRIDE)
        self.assertEqual([memory.r(b + 0x800) for b in (first, first + tool.BLOCK_STRIDE, found)], [32, 64, 96])
        self.assertEqual(memory.r(found + 0x808), 0)
        self.assertEqual(memory.r(found + 0x810), 0)

    def test_new_block_keeps_stale_slot_bytes(self):
        memory, model, blocks = self.chain(1)
        found = model.locate(tool.TX, 32)
        self.assertEqual(memory.bytes(found, 8), bytes([tool.STACK_MARK]) * 8)

    def test_full_block_and_far_target_advances_the_tail(self):
        memory, model, blocks = self.chain(3)
        memory.w(blocks[0] + 0x810, 0xFFFFFFFF)
        memory.w(tool.TX + 8, 70)
        model.locate(tool.TX, 64)
        self.assertEqual(memory.r(tool.TX), blocks[1])
        self.assertEqual(memory.r(blocks[0] + 0x810), 0x1FFFFFFFF)
        self.assertEqual(memory.r(blocks[0] + 0x818), 70)

    def test_partial_block_does_not_advance_the_tail(self):
        memory, model, blocks = self.chain(3)
        memory.w(blocks[0] + 0x810, 0x7FFFFFFF)
        model.locate(tool.TX, 64)
        self.assertEqual(memory.r(tool.TX), blocks[0])
        self.assertEqual(memory.r(blocks[0] + 0x810), 0x7FFFFFFF)

    def test_target_not_far_enough_does_not_advance_the_tail(self):
        memory, model, blocks = self.chain(3)
        memory.w(blocks[0] + 0x810, 0xFFFFFFFF)
        model.locate(tool.TX, 32 + 1)
        self.assertEqual(memory.r(tool.TX), blocks[0])
        memory2, model2, blocks2 = self.chain(3)
        memory2.w(blocks2[0] + 0x810, 0xFFFFFFFF)
        model2.locate(tool.TX, 32)
        self.assertEqual(memory2.r(tool.TX), blocks2[1])

    def test_overflow_check_uses_an_unsigned_compare(self):
        memory, model, blocks = self.chain(1, base=tool.M64 - 31 - 32)
        memory.w(blocks[0] + 0x800, 0xFFFFFFFFFFFFFFE0)
        with self.assertRaises(tool.Panicked):
            model.locate(tool.TX, 0xFFFFFFFFFFFFFFE0 + 32 & tool.M64)
        memory2, model2, blocks2 = self.chain(1)
        memory2.w(blocks2[0] + 0x800, 0xFFFFFFFFFFFFFFC0)
        model2.locate(tool.TX, 0xFFFFFFFFFFFFFFE0)
        self.assertEqual(memory2.r(model2.log[0][1] + 0x800), 0xFFFFFFFFFFFFFFE0)


class PopReleaseTests(unittest.TestCase):
    def chain(self, count):
        memory, model = fresh()
        blocks = [tool.BLOCKS + tool.BLOCK_STRIDE * i for i in range(count)]
        for i, block in enumerate(blocks):
            memory.w(block + 0x800, 32 * i)
            memory.w(block + 0x808, blocks[i + 1] if i + 1 < count else 0)
            memory.w(block + 0x810, 0)
            memory.w(block + 0x818, 0)
        memory.w(tool.TX, blocks[-1])
        memory.w(tool.TX + 8, 32 * count)
        model.brk = tool.BLOCKS + tool.BLOCK_STRIDE * count
        return memory, model, blocks

    def test_head_walk_skips_empty_blocks(self):
        memory, model, blocks = self.chain(4)
        memory.w(tool.RX + 0x10, 96)
        memory.w(blocks[3] + 0x810, 1)
        memory.put(blocks[3], message(77))
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.RX), blocks[3])
        self.assertEqual(memory.r(tool.OUT), 77)
        self.assertEqual(memory.r(tool.RX + 0x10), 97)

    def test_head_walk_stops_at_missing_block(self):
        memory, model, blocks = self.chain(2)
        memory.w(tool.RX + 0x10, 128)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), tool.NICHE5)
        self.assertEqual(memory.r(tool.RX), blocks[1])

    def test_release_requires_the_released_flag(self):
        memory, model, blocks = self.chain(3)
        memory.w(tool.RX, blocks[1])
        memory.w(tool.RX + 0x10, 32)
        memory.w(blocks[0] + 0x810, 0xFFFFFFFF)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.RX + 8), blocks[0])
        self.assertEqual(memory.r(blocks[0] + 0x810), 0xFFFFFFFF)

    def test_release_requires_observed_tail_not_beyond_index(self):
        for observed, released in ((32, True), (33, False)):
            memory, model, blocks = self.chain(3)
            memory.w(tool.RX, blocks[1])
            memory.w(tool.RX + 0x10, 32)
            memory.w(blocks[0] + 0x810, 1 << 32)
            memory.w(blocks[0] + 0x818, observed)
            model.pop(tool.OUT, tool.RX, tool.TX)
            self.assertEqual(memory.r(tool.RX + 8) == blocks[1], released, observed)

    def test_released_block_is_cleared_and_linked_behind_the_tail(self):
        memory, model, blocks = self.chain(3)
        memory.w(tool.RX, blocks[1])
        memory.w(tool.RX + 0x10, 32)
        memory.w(blocks[0] + 0x810, 1 << 32)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(blocks[0] + 0x800), 96)
        self.assertEqual(memory.r(blocks[0] + 0x808), 0)
        self.assertEqual(memory.r(blocks[0] + 0x810), 0)
        self.assertEqual(memory.r(blocks[2] + 0x808), blocks[0])

    def test_release_follows_a_longer_tail_chain_up_to_three_links(self):
        memory, model, blocks = self.chain(5)
        memory.w(tool.TX, blocks[2])
        memory.w(tool.RX, blocks[1])
        memory.w(tool.RX + 0x10, 32)
        memory.w(blocks[0] + 0x810, 1 << 32)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(blocks[4] + 0x808), blocks[0])
        self.assertEqual(memory.r(blocks[0] + 0x800), 32 * 4 + 32)
        self.assertEqual([entry for entry in model.log if entry[0] == "dealloc"], [])

    def test_release_deallocates_after_three_failed_links(self):
        memory, model, blocks = self.chain(6)
        memory.w(tool.TX, blocks[1])
        memory.w(tool.RX, blocks[2])
        memory.w(tool.RX + 8, blocks[0])
        memory.w(tool.RX + 0x10, 64)
        memory.w(blocks[0] + 0x810, 1 << 32)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(model.log, [("dealloc", blocks[0], 0x820)])

    def test_release_without_successor_panics(self):
        memory, model, blocks = self.chain(1)
        memory.w(tool.RX, blocks[0])
        memory.w(tool.RX + 8, blocks[0])
        memory.w(tool.RX + 0x10, 0)
        self.assertEqual(memory.r(tool.RX), memory.r(tool.RX + 8))
        memory.w(tool.RX, tool.BLOCKS + 5 * tool.BLOCK_STRIDE)
        memory.w(tool.BLOCKS + 5 * tool.BLOCK_STRIDE + 0x800, 0)
        memory.w(tool.BLOCKS + 5 * tool.BLOCK_STRIDE + 0x808, 0)
        memory.w(blocks[0] + 0x810, 1 << 32)
        with self.assertRaises(tool.Panicked):
            model.pop(tool.OUT, tool.RX, tool.TX)

    def test_ready_slot_beyond_the_head_block_uses_modulo_index(self):
        memory, model, blocks = self.chain(2)
        memory.w(tool.RX, blocks[1])
        memory.w(tool.RX + 0x10, 32 + 5)
        memory.w(blocks[1] + 0x810, 1 << 5)
        memory.put(blocks[1] + 5 * 64, message(99))
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), 99)
        self.assertEqual(memory.bytes(tool.OUT, 64), message(99))

    def test_not_ready_slot_leaves_the_rest_of_the_output_untouched(self):
        memory, model, blocks = self.chain(1)
        memory.put(tool.OUT, bytes([0x33]) * 64)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.bytes(tool.OUT + 8, 56), bytes([0x33]) * 56)
        self.assertEqual(memory.r(tool.OUT), tool.NICHE5)

    def test_closed_flag_only_applies_when_the_slot_is_not_ready(self):
        memory, model, blocks = self.chain(1)
        memory.w(blocks[0] + 0x810, (1 << 33) | 1)
        memory.put(blocks[0], message(5))
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), 5)
        model.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.OUT), tool.NICHE4)
        self.assertEqual(memory.r(tool.RX + 0x10), 1)


class SemaphoreAndWakerTests(unittest.TestCase):
    def test_semaphore_counts_two_per_message(self):
        memory, model = fresh(sem=10)
        for number in range(5):
            memory.put(tool.MSG, message(number))
            model.send(tool.SENDER, tool.MSG)
        self.assertEqual(memory.r(tool.CHAN + 0x1C0), 20)

    def test_semaphore_just_below_overflow_is_accepted_once(self):
        memory, model = fresh(sem=tool.M64 - 3)
        memory.put(tool.MSG, message(1))
        self.assertEqual(model.send(tool.SENDER, tool.MSG), 5)
        self.assertEqual(memory.r(tool.CHAN + 0x1C0), tool.M64 - 1)
        with self.assertRaises(tool.Panicked):
            model.send(tool.SENDER, tool.MSG)

    def test_closed_check_precedes_the_overflow_check(self):
        memory, model = fresh(sem=tool.M64)
        memory.put(tool.MSG, message(1))
        self.assertEqual(model.send(tool.SENDER, tool.MSG), 0)

    def test_second_send_does_not_wake_again(self):
        memory, model = fresh()
        memory.w(tool.CHAN + 0x100, tool.VTABLE)
        memory.w(tool.CHAN + 0x108, 9)
        for number in range(3):
            memory.put(tool.MSG, message(number))
            model.send(tool.SENDER, tool.MSG)
        self.assertEqual(len([entry for entry in model.log if entry[0] == "wake"]), 1)
        self.assertEqual(memory.r(tool.CHAN + 0x110), 0)

    def test_state_zero_without_waker_pointer_only_clears_state(self):
        memory, model = fresh()
        memory.put(tool.MSG, message(1))
        model.send(tool.SENDER, tool.MSG)
        self.assertEqual(model.log, [])
        self.assertEqual(memory.r(tool.CHAN + 0x110), 0)

    def test_dropped_message_log_carries_all_sixty_four_bytes(self):
        memory, model = fresh(sem=1)
        body = bytes(range(64))
        memory.put(tool.MSG, body)
        model.send(tool.SENDER, tool.MSG)
        self.assertEqual(model.log, [("drop", body.hex())])

    def test_refcount_wraps_like_a_64_bit_word(self):
        memory, model = fresh()
        memory.w(tool.ARC + 0x10, tool.M64)
        memory.put(tool.MSG, message(1))
        model.send(tool.SENDER, tool.MSG)
        self.assertEqual(memory.r(tool.ARC + 0x10), 0)


class SequenceInvariantTests(unittest.TestCase):
    def drive(self, seed, steps):
        rng = tool.Rng(seed)
        data = tool.blank_image()
        brk = tool.init_channel(data, rng)
        memory = tool.Image2(data)
        model = tool.ChannelModel(memory, brk)
        sent, got = [], []
        for step in range(steps):
            if rng.chance(1, 2):
                memory.put(tool.MSG, message(step + 16))
                if model.send(tool.SENDER, tool.MSG) == 5:
                    sent.append(step + 16)
            else:
                model.pop(tool.OUT, tool.RX, tool.TX)
                tag = memory.r(tool.OUT)
                if tag < tool.NICHE4 - 1:
                    got.append(tag)
        return sent, got, memory

    def test_received_is_always_a_prefix_of_sent(self):
        for seed in range(1, 40):
            sent, got, _ = self.drive(seed, 150)
            self.assertEqual(got, sent[:len(got)], seed)

    def test_semaphore_matches_sent_count(self):
        for seed in range(1, 20):
            sent, _, memory = self.drive(seed, 120)
            self.assertEqual(memory.r(tool.CHAN + 0x1C0), 2 * len(sent))
            self.assertEqual(memory.r(tool.CHAN + 0x88), len(sent))

    def test_allocation_count_is_bounded_by_live_window(self):
        for seed in range(1, 20):
            rng = tool.Rng(seed)
            data = tool.blank_image()
            brk = tool.init_channel(data, rng)
            memory = tool.Image2(data)
            model = tool.ChannelModel(memory, brk)
            for step in range(400):
                memory.put(tool.MSG, message(step + 16))
                model.send(tool.SENDER, tool.MSG)
                model.pop(tool.OUT, tool.RX, tool.TX)
            allocs = [entry for entry in model.log if entry[0] == "alloc"]
            self.assertLessEqual(len(allocs), 3, seed)

    def test_model_and_wrong_model_disagree_on_a_long_run(self):
        class NoRelease(tool.ChannelModel):
            def pop(self, out, rx, tx):
                m = self.m
                head, index = m.r(rx), m.r(rx + 0x10)
                if (m.r(head + 0x810) & 0xFFFFFFFF) >> (index & 31) & 1:
                    m.put(out, m.bytes(head + (index & 31) * 64, 64))
                    m.w(rx + 0x10, index + 1)
                else:
                    super().pop(out, rx, tx)

        def run(model_class):
            rng = tool.Rng(3)
            data = tool.blank_image()
            brk = tool.init_channel(data, rng)
            memory = tool.Image2(data)
            model = model_class(memory, brk)
            for step in range(300):
                memory.put(tool.MSG, message(step + 16))
                model.send(tool.SENDER, tool.MSG)
                model.pop(tool.OUT, tool.RX, tool.TX)
            return len([entry for entry in model.log if entry[0] == "alloc"])

        self.assertNotEqual(run(tool.ChannelModel), run(NoRelease))


class RandomStateInvariantTests(unittest.TestCase):
    """Properties of the model over the same random-state generator the evidence uses."""

    def states(self, count):
        for seed in range(1, count + 1):
            rng = tool.Rng(0xABC0000 + seed)
            data = tool.blank_image()
            brk = tool.random_state(rng, data)
            memory = tool.Image2(data)
            yield seed, rng, memory, tool.ChannelModel(memory, brk)

    def test_successful_send_advances_tail_and_semaphore_by_one_message(self):
        checked = 0
        for seed, rng, memory, model in self.states(400):
            before_tail = memory.r(tool.CHAN + 0x88)
            before_sem = memory.r(tool.CHAN + 0x1C0)
            memory.put(tool.MSG, tool.random_message(rng))
            try:
                result = model.send(tool.SENDER, tool.MSG)
            except tool.Panicked:
                continue
            if before_sem & 1 == 0:
                checked += 1
                self.assertEqual(result, 5, seed)
                self.assertEqual(memory.r(tool.CHAN + 0x88), (before_tail + 1) & tool.M64, seed)
                self.assertEqual(memory.r(tool.CHAN + 0x1C0), (before_sem + 2) & tool.M64, seed)
        self.assertGreater(checked, 100)

    def test_closed_send_never_touches_the_queue_state(self):
        checked = 0
        for seed, rng, memory, model in self.states(400):
            if not memory.r(tool.CHAN + 0x1C0) & 1:
                continue
            before = (memory.r(tool.CHAN + 0x88), memory.r(tool.CHAN + 0x1C0), memory.r(tool.TX), memory.r(tool.CHAN + 0x110))
            memory.put(tool.MSG, tool.random_message(rng))
            model.send(tool.SENDER, tool.MSG)
            after = (memory.r(tool.CHAN + 0x88), memory.r(tool.CHAN + 0x1C0), memory.r(tool.TX), memory.r(tool.CHAN + 0x110))
            self.assertEqual(before, after, seed)
            checked += 1
        self.assertGreater(checked, 50)

    def test_pop_never_moves_the_index_backwards_and_advances_by_at_most_one(self):
        checked = 0
        for seed, rng, memory, model in self.states(500):
            before = memory.r(tool.RX + 0x10)
            try:
                model.pop(tool.OUT, tool.RX, tool.TX)
            except tool.Panicked:
                continue
            after = memory.r(tool.RX + 0x10)
            self.assertIn(after - before, (0, 1), seed)
            checked += 1
        self.assertGreater(checked, 300)

    def test_pop_tag_class_decides_the_index_advance(self):
        advanced = held = 0
        for seed, rng, memory, model in self.states(600):
            before = memory.r(tool.RX + 0x10)
            try:
                model.pop(tool.OUT, tool.RX, tool.TX)
            except tool.Panicked:
                continue
            tag = memory.r(tool.OUT)
            after = memory.r(tool.RX + 0x10)
            if after == before + 1:
                advanced += 1
                self.assertLessEqual(tag, tool.NICHE5 - 2, seed)
            elif tag > tool.NICHE5 - 2:
                held += 1
        self.assertGreater(advanced, 20)
        self.assertGreater(held, 20)

    def test_head_pointer_only_moves_along_next_links(self):
        for seed, rng, memory, model in self.states(300):
            reachable = []
            block = memory.r(tool.RX)
            while block and len(reachable) < 8:
                reachable.append(block)
                block = memory.r(block + 0x808)
            try:
                model.pop(tool.OUT, tool.RX, tool.TX)
            except tool.Panicked:
                continue
            self.assertIn(memory.r(tool.RX), reachable, seed)

    def test_locate_result_has_the_requested_start_or_the_chain_end(self):
        found = 0
        for seed, rng, memory, model in self.states(300):
            index = memory.r(tool.TX + 8)
            try:
                block = model.locate(tool.TX, index)
            except tool.Panicked:
                continue
            self.assertEqual(memory.r(block + 0x800), index & ~31 & tool.M64, seed)
            found += 1
        self.assertGreater(found, 150)

    def test_alloc_addresses_are_consecutive_and_unique(self):
        for seed, rng, memory, model in self.states(300):
            memory.put(tool.MSG, tool.random_message(rng))
            try:
                model.send(tool.SENDER, tool.MSG)
            except tool.Panicked:
                continue
            addresses = [entry[1] for entry in model.log if entry[0] == "alloc"]
            self.assertEqual(len(addresses), len(set(addresses)))
            for first, second in zip(addresses, addresses[1:]):
                self.assertEqual(second - first, tool.BLOCK_STRIDE)


class MessageGeneratorTests(unittest.TestCase):
    def test_tags_cover_the_reserved_values(self):
        rng = tool.Rng(99)
        tags = {int.from_bytes(tool.random_message(rng)[:8], "little") for _ in range(400)}
        self.assertIn(tool.NICHE4, tags)
        self.assertIn(tool.NICHE4 + 1, tags)
        self.assertIn(tool.NICHE4 - 1, tags)
        self.assertTrue(any(tag < 16 for tag in tags))

    def test_messages_are_sixty_four_bytes(self):
        rng = tool.Rng(100)
        self.assertTrue(all(len(tool.random_message(rng)) == 64 for _ in range(50)))

    def test_image_helpers_round_trip(self):
        data = tool.blank_image()
        tool.put64(data, tool.CHAN, 0x0123456789ABCDEF)
        self.assertEqual(tool.get64(data, tool.CHAN), 0x0123456789ABCDEF)
        memory = tool.Image2(data)
        memory.w(tool.CHAN + 8, 0x1FFFFFFFFFFFFFFFF)
        self.assertEqual(memory.r(tool.CHAN + 8), tool.M64)
        self.assertEqual(memory.r(tool.CHAN), 0x0123456789ABCDEF)

    def test_init_channel_matches_a_fresh_channel_layout(self):
        data = tool.blank_image()
        brk = tool.init_channel(data, tool.Rng(1))
        self.assertEqual(brk, tool.BLOCKS + tool.BLOCK_STRIDE)
        self.assertEqual(tool.get64(data, tool.TX), tool.BLOCKS)
        self.assertEqual(tool.get64(data, tool.RX), tool.get64(data, tool.RX + 8))
        self.assertEqual(tool.get64(data, tool.ARC + 0x10), 1)


class WrongModelTests(unittest.TestCase):
    """Deliberately wrong restatements must disagree with the right model on the same image."""

    def scenario(self, model_class):
        memory, _ = fresh()
        model = model_class(memory, tool.BLOCKS + tool.BLOCK_STRIDE)
        trace = []
        for number in range(70):
            memory.put(tool.MSG, message(number + 16))
            trace.append(model.send(tool.SENDER, tool.MSG))
        for _ in range(75):
            model.pop(tool.OUT, tool.RX, tool.TX)
            trace.append(memory.r(tool.OUT))
        return trace, bytes(memory.data)

    def test_baseline_is_stable(self):
        self.assertEqual(self.scenario(tool.ChannelModel), self.scenario(tool.ChannelModel))

    def test_wrong_slot_stride_is_detected(self):
        class Stride(tool.ChannelModel):
            def send(self, sender, msg):
                result = super().send(sender, msg)
                self.m.w(tool.CHAN + 0x88, self.m.r(tool.CHAN + 0x88) + 1)
                return result

        self.assertNotEqual(self.scenario(tool.ChannelModel), self.scenario(Stride))

    def test_ignoring_the_closed_bit_is_detected(self):
        class Open(tool.ChannelModel):
            def send(self, sender, msg):
                self.m.w(tool.CHAN + 0x1C0, self.m.r(tool.CHAN + 0x1C0) & ~1)
                return super().send(sender, msg)

        memory, _ = fresh(sem=1)
        model = Open(memory, tool.BLOCKS + tool.BLOCK_STRIDE)
        memory.put(tool.MSG, message(9))
        self.assertEqual(model.send(tool.SENDER, tool.MSG), 5)
        memory2, right = fresh(sem=1)
        memory2.put(tool.MSG, message(9))
        self.assertEqual(right.send(tool.SENDER, tool.MSG), 0)

    def test_pop_that_always_advances_is_detected(self):
        class Greedy(tool.ChannelModel):
            def pop(self, out, rx, tx):
                super().pop(out, rx, tx)
                if self.m.r(out) > tool.NICHE5 - 2:
                    self.m.w(rx + 0x10, self.m.r(rx + 0x10) + 1)

        memory, model = fresh()
        memory.put(tool.MSG, message(tool.NICHE4))
        model.send(tool.SENDER, tool.MSG)
        wrong = Greedy(memory, model.brk)
        wrong.pop(tool.OUT, tool.RX, tool.TX)
        self.assertEqual(memory.r(tool.RX + 0x10), 1)


class GeneratorTests(unittest.TestCase):
    def test_rng_is_deterministic(self):
        first, second = tool.Rng(5), tool.Rng(5)
        self.assertEqual([first.next() for _ in range(20)], [second.next() for _ in range(20)])
        self.assertNotEqual(tool.Rng(5).next(), tool.Rng(6).next())

    def test_random_state_is_reproducible_and_inside_the_image(self):
        for seed in range(1, 40):
            a, b = tool.blank_image(), tool.blank_image()
            brk_a = tool.random_state(tool.Rng(seed), a)
            brk_b = tool.random_state(tool.Rng(seed), b)
            self.assertEqual((brk_a, bytes(a)), (brk_b, bytes(b)))
            self.assertLess(brk_a + tool.BLOCK_STRIDE - BASE, tool.IMAGE_SIZE)

    def test_model_never_leaves_the_image_on_random_states(self):
        outcomes = set()
        for seed in range(1, 300):
            rng = tool.Rng(seed)
            data = tool.blank_image()
            brk = tool.random_state(rng, data)
            memory = tool.Image2(data)
            model = tool.ChannelModel(memory, brk)
            memory.put(tool.MSG, tool.random_message(rng))
            try:
                outcomes.add(("send", model.send(tool.SENDER, tool.MSG)))
            except tool.Panicked:
                outcomes.add(("send", "panic"))
            model.pop(tool.OUT, tool.RX, tool.TX)
            self.assertEqual(len(memory.data), tool.IMAGE_SIZE)
        self.assertIn(("send", 5), outcomes)
        self.assertIn(("send", 0), outcomes)

    def test_expected_outcome_classes_are_all_equivalence_documented(self):
        for (start, va), reason in tool.EQUIVALENT.items():
            self.assertIn(start, (tool.SEND, tool.POP, tool.LOCATE))
            self.assertGreater(len(reason), 20)
            self.assertTrue(va > start)


class EvidenceTests(unittest.TestCase):
    def table(self, name):
        lines = (EVIDENCE / name).read_text().splitlines()
        header = lines[0].split("\t")
        return [dict(zip(header, line.split("\t"))) for line in lines[1:]]

    def test_measure_is_consistent_with_the_tables(self):
        measure = json.loads((EVIDENCE / "measure.json").read_text())
        controls = self.table("controls.tsv")
        equivalent = self.table("equivalent-mutants.tsv")
        self.assertEqual(measure["negative_controls"], len(controls))
        self.assertEqual(measure["negative_detected"], sum(row["detected"] == "1" for row in controls))
        self.assertEqual(measure["equivalent"], len(equivalent))
        self.assertEqual(measure["negative_detected"] + measure["equivalent"], measure["negative_controls"])
        self.assertEqual(measure["fifo_violations"], 0)
        self.assertEqual(measure["cases"], measure["random_cases"] + measure["sequence_cases"])
        self.assertEqual(measure["binary_sha256"], tool.SHA256)

    def test_every_undetected_mutant_has_a_reason_and_vice_versa(self):
        undetected = {(row["function"], row["instruction"]) for row in self.table("controls.tsv") if row["detected"] == "0"}
        listed = {(row["function"], row["instruction"]) for row in self.table("equivalent-mutants.tsv")}
        self.assertEqual(undetected, listed)
        for row in self.table("equivalent-mutants.tsv"):
            self.assertGreater(len(row["reason"]), 20)

    def test_corrupted_measure_is_rejected_by_the_consistency_rule(self):
        measure = json.loads((EVIDENCE / "measure.json").read_text())
        controls = self.table("controls.tsv")
        measure["negative_detected"] += 1
        self.assertNotEqual(measure["negative_detected"], sum(row["detected"] == "1" for row in controls))

    def test_every_function_row_is_a_real_fde_with_executed_below_total(self):
        rows = self.table("functions.tsv")
        self.assertEqual([row["function"] for row in rows], ["send", "pop", "locate"])
        for row in rows:
            self.assertLessEqual(int(row["executed"]), int(row["instructions"]))
            self.assertGreater(int(row["executed"]) * 10, int(row["instructions"]) * 7)
            self.assertLess(int(row["start"], 16), int(row["end"], 16))

    def test_all_sampled_cases_agree(self):
        rows = self.table("cases.tsv")
        self.assertGreater(len(rows), 1000)
        self.assertTrue(all(row["agree"] == "1" for row in rows))
        self.assertEqual({row["op"] for row in rows}, {"send", "pop"})

    def test_outcome_classes_cover_closed_ok_and_panic_sends(self):
        classes = {(row["kind"], row["op"], row["status"], row["value"]) for row in self.table("outcomes.tsv")}
        self.assertIn(("random", "send", "ok", "5"), classes)
        self.assertIn(("random", "send", "ok", "0"), classes)
        self.assertIn(("random", "send", "panic", "-"), classes)
        self.assertIn(("sequence", "pop", "ok", "0"), classes)

    def test_evidence_text_has_no_workspace_paths(self):
        banned = tuple("/" + name + "/" for name in ("ho" + "me", "mn" + "t", "sr" + "v", "ro" + "ot", "tm" + "p", "op" + "t", "va" + "r", "et" + "c"))
        for path in sorted(EVIDENCE.iterdir()):
            text = path.read_text()
            for item in banned:
                self.assertNotIn(item, text, path.name)
        source = (ROOT / "tools" / "re008_listener_chan_115.py").read_text()
        for item in banned:
            self.assertNotIn(item, source)


class MutantPlanTests(unittest.TestCase):
    def test_every_control_patch_changes_exactly_one_byte_inside_a_function(self):
        starts = {"send": (tool.SEND, 0x2CEDC4D), "pop": (tool.POP, 0x2CCED01), "locate": (tool.LOCATE, 0x2CD01C2)}
        controls = EvidenceTests.table(EvidenceTests(), "controls.tsv")
        self.assertGreaterEqual(len(controls), 50)
        for row in controls:
            low, high = starts[row["function"]]
            self.assertTrue(low <= int(row["patched_byte"], 16) < high)
            self.assertTrue(low <= int(row["instruction"], 16) < high)
            self.assertLessEqual(int(row["new_value"], 16), 0xFF)


if __name__ == "__main__":
    unittest.main()
