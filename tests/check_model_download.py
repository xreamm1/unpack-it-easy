"""Local HTTP tests: no model service or target program is contacted."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import model_download

DATA = b'UIE download fixture\x00' * 10000


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        offset = int(self.headers.get('Range', 'bytes=0-')[6:-1])
        self.requests.append((self.path, offset))
        if self.path == '/ignore':
            offset = 0
        self.send_response(206 if offset else 200)
        if offset:
            self.send_header('Content-Range', f'bytes {offset}-{len(DATA)-1}/{len(DATA)}')
        self.send_header('Content-Length', str(len(DATA) - offset))
        self.end_headers()
        body = DATA[offset:]
        if self.path == '/interrupt' and not offset:
            body = body[:70000]
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *args):
        pass


class Downloads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def run_download(self, path, seed=b''):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / hashlib.sha256(DATA).hexdigest()
            partial = destination.with_name(destination.name + '.uie-part')
            partial.write_bytes(seed)
            with patch.object(model_download.time, 'sleep'):
                model_download.download(destination, f'http://127.0.0.1:{self.server.server_port}{path}', {}, len(DATA), 'fixture')
            self.assertEqual(destination.read_bytes(), DATA)
            self.assertFalse(partial.exists())

    def test_resume_previous_run(self):
        self.run_download('/resume', DATA[:31000])
        self.assertIn(('/resume', 31000), Handler.requests)

    def test_interrupted_response_resumes(self):
        self.run_download('/interrupt')
        self.assertTrue(any(path == '/interrupt' and offset > 0 for path, offset in Handler.requests))

    def test_server_ignores_range(self):
        self.run_download('/ignore', DATA[:12345])

    def test_corrupt_complete_partial_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / hashlib.sha256(DATA).hexdigest()
            partial = destination.with_name(destination.name + '.uie-part')
            partial.write_bytes(b'x' * len(DATA))
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                model_download.download(destination, 'http://unused.invalid', {}, len(DATA), 'fixture')
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
