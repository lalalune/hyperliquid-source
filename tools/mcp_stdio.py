"""Deadline-bound JSON-lines reads from an owned subprocess pipe."""
import json
import queue
import threading
import time


class JsonLineReader:
    """Use a blocking pipe reader, since Windows select only accepts sockets.

    The owner must terminate/wait for its subprocess, then join this reader.
    Keeping the blocking read in one thread preserves partial frames on timeout.
    """

    def __init__(self, stream):
        self.lines = queue.Queue()
        self.thread = threading.Thread(target=self._read, args=(stream,), daemon=True)
        self.thread.start()

    def _read(self, stream):
        try:
            while True:
                line = stream.readline()
                if not line or not line.endswith(b'\n'):
                    self.lines.put(None)
                    return
                self.lines.put(line)
        except OSError as error:
            self.lines.put(error)

    def receive(self, request_id, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                break
            if line is None:
                raise RuntimeError('REA stdio server closed; inspect work/rea-smoke/mcp-stderr.log')
            if isinstance(line, OSError):
                raise RuntimeError('REA stdio pipe read failed') from line
            value = json.loads(line)
            if value.get('id') == request_id:
                if 'error' in value:
                    raise RuntimeError(value['error'])
                return value['result']
        raise RuntimeError('REA stdio handshake deadline exceeded')

    def join(self, timeout=10):
        self.thread.join(timeout)
