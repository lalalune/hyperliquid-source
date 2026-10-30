"""Transport tests use real subprocess pipes, without a REA/Ghidra fixture."""
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from mcp_stdio import JsonLineReader


class PipeTests(unittest.TestCase):
    def start(self, program):
        child = subprocess.Popen([sys.executable, '-u', '-c', program],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        reader = JsonLineReader(child.stdout)

        def cleanup():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=10)
            reader.join()
            child.stdout.close()
            child.stdin.close()
            self.assertFalse(reader.thread.is_alive())

        self.addCleanup(cleanup)
        return child, reader

    def test_real_pipe_frames_and_response_selection(self):
        _, reader = self.start(
            "import sys;sys.stdout.buffer.write("
            "b'{\"method\":\"notice\"}\\n{\"id\":9,\"result\":\"ignored\"}\\n'"
            "+ b'{\"id\":1,\"result\":\"ready\"}\\n{\"id\":2,\"result\":42}\\n')")
        self.assertEqual(reader.receive(1, 5), 'ready')
        self.assertEqual(reader.receive(2, 5), 42)

    def test_large_utf8_frame_across_pipe_writes(self):
        value = '\u2603' * 80000
        payload = (json.dumps({'id': 1, 'result': value}, ensure_ascii=False) + '\n').encode()
        _, reader = self.start(
            "import json,sys;payload=(json.dumps({'id':1,'result':'\\u2603'*80000},"
            "ensure_ascii=False)+'\\n').encode();"
            "[(sys.stdout.buffer.write(payload[i:i+17]),sys.stdout.buffer.flush()) "
            "for i in range(0,len(payload),17)]")
        self.assertGreater(len(payload), 65536)
        self.assertEqual(reader.receive(1, 10), value)

    def test_timeout_keeps_partial_frame_for_next_receive(self):
        child, reader = self.start(
            "import sys;sys.stdout.buffer.write(b'{\"id\":1,');sys.stdout.buffer.flush();"
            "sys.stdin.buffer.read(1);sys.stdout.buffer.write(b'\"result\":7}\\n')")
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'deadline exceeded'):
            reader.receive(1, 0.1)
        self.assertLess(time.monotonic() - started, 2)
        child.stdin.write(b'x')
        child.stdin.flush()
        self.assertEqual(reader.receive(1, 5), 7)

    def test_eof_is_not_a_timeout(self):
        _, reader = self.start('pass')
        with self.assertRaisesRegex(RuntimeError, 'server closed'):
            reader.receive(1, 5)

    def test_truncated_frame_is_not_an_accepted_response(self):
        _, reader = self.start("print('{\"id\":1,\"result\":7}',end='')")
        with self.assertRaisesRegex(RuntimeError, 'server closed'):
            reader.receive(1, 5)

    def test_server_error_is_not_a_success(self):
        _, reader = self.start("print('{\"id\":1,\"error\":{\"code\":-1}}')")
        with self.assertRaisesRegex(RuntimeError, 'code'):
            reader.receive(1, 5)
