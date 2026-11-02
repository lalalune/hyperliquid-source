"""Malformed frames must surface as RuntimeError, like every other receive() failure."""
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from mcp_stdio import JsonLineReader


class MalformedFrameTests(unittest.TestCase):
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

    def test_non_json_line_is_a_runtime_error(self):
        _, reader = self.start(
            "import sys;sys.stdout.buffer.write("
            "b'REA server starting\\n{\"id\":1,\"result\":7}\\n')")
        with self.assertRaisesRegex(RuntimeError, 'malformed frame'):
            reader.receive(1, 5)

    def test_non_object_json_line_is_a_runtime_error(self):
        _, reader = self.start(
            "import sys;sys.stdout.buffer.write("
            "b'[1,2]\\n{\"id\":1,\"result\":7}\\n')")
        with self.assertRaisesRegex(RuntimeError, 'malformed frame'):
            reader.receive(1, 5)

    def test_undecodable_line_is_a_runtime_error(self):
        _, reader = self.start(
            "import sys;sys.stdout.buffer.write("
            "b'\\xff\\xfe\\n{\"id\":1,\"result\":7}\\n')")
        with self.assertRaisesRegex(RuntimeError, 'malformed frame'):
            reader.receive(1, 5)

    def test_response_without_result_or_error_is_a_runtime_error(self):
        _, reader = self.start("print('{\"id\":1}')")
        with self.assertRaisesRegex(RuntimeError, 'neither result nor error'):
            reader.receive(1, 5)

    def test_valid_frames_still_select_the_response(self):
        _, reader = self.start(
            "import sys;sys.stdout.buffer.write("
            "b'{\"method\":\"notice\"}\\n{\"id\":1,\"result\":\"ready\"}\\n')")
        self.assertEqual(reader.receive(1, 5), 'ready')


if __name__ == '__main__':
    unittest.main()
