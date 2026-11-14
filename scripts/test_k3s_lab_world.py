"""runtimes/gvisor/lab/cilium/world.py, the k3s Cilium lab's stand-ins, on loopback."""
import http.client
import importlib.util
import socket
import struct
import threading
import time
import unittest
from pathlib import Path

PATH = Path(__file__).resolve().parent.parent / 'runtimes/gvisor/lab/cilium/world.py'


def load():
    if not PATH.exists():
        return None
    spec = importlib.util.spec_from_file_location('world', PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def query(name, qtype, qid=0x1234):
    q = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
    return struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0) + q + struct.pack('>HH', qtype, 1)


class WorldTest(unittest.TestCase):
    def setUp(self):
        self.world = load()
        self.assertIsNotNone(self.world, '%s is not written yet' % PATH)
        self.logged = []
        self.world.log = lambda *parts: self.logged.append(' '.join(str(p) for p in parts))

    def serve(self, server):
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_dns_answers_txt_and_logs_the_name(self):
        name = 'mzxw6ytboi.x1.exfil.warden.test'
        reply = self.world.dns_reply(query(name, 16), ('10.0.0.5', 5353))
        qid, flags, qd, an = struct.unpack('>HHHH', reply[:8])
        self.assertEqual((qid, flags & 0x8000, flags & 0xf, qd, an), (0x1234, 0x8000, 0, 1, 1))
        self.assertIn(self.world.TXT_ANSWER.encode(), reply)
        self.assertEqual(self.logged, ['dns 10.0.0.5 TXT ' + name])

    def test_dns_answers_other_types_nxdomain(self):
        reply = self.world.dns_reply(query('allowed.warden.test', 1), ('10.0.0.5', 1))
        _, flags, _, an = struct.unpack('>HHHH', reply[:8])
        self.assertEqual((flags & 0xf, an), (3, 0))
        self.assertEqual(self.logged, ['dns 10.0.0.5 A allowed.warden.test'])

    def test_dns_ignores_garbage(self):
        for data in (b'', b'\x00' * 11, query('a.b', 16)[:-3], b'\x12\x34\x81\x80' + b'\x00' * 8):
            self.assertIsNone(self.world.dns_reply(data, ('10.0.0.5', 1)), data)

    def test_http_answers_the_body_and_logs_the_host(self):
        port = self.serve(self.world.http_server(('127.0.0.1', 0), 'origin-allowed'))
        c = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        self.addCleanup(c.close)
        c.request('GET', '/x', headers={'Host': 'allowed.warden.test'})
        r = c.getresponse()
        self.assertEqual((r.status, r.read()), (200, b'origin-allowed\n'))
        self.assertEqual(self.logged, ['http 127.0.0.1 allowed.warden.test /x'])

    def test_stream_logs_lines_and_sends_heartbeats(self):
        port = self.serve(self.world.stream_server(('127.0.0.1', 0), 0.02))
        s = socket.create_connection(('127.0.0.1', port), timeout=5)
        s.sendall(b'pod-a 1 100.000\npod-a 2 100.020\n')
        f = s.makefile('rb')
        beats = [f.readline().decode().split() for _ in range(3)]
        self.assertEqual([b[0] for b in beats], ['hb'] * 3)
        self.assertEqual([int(b[2]) for b in beats], [1, 2, 3])
        f.close()  # the file object holds the socket open too
        s.close()
        deadline = time.time() + 5
        while time.time() < deadline and not any(line.startswith('close ') for line in self.logged):
            time.sleep(0.02)
        conn = beats[0][1]
        self.assertEqual(self.logged[0].split()[:2], ['open', conn])
        self.assertIn('rx %s pod-a 1 100.000' % conn, self.logged)
        self.assertIn('rx %s pod-a 2 100.020' % conn, self.logged)
        self.assertTrue(self.logged[-1].startswith('close %s ' % conn), self.logged[-1])


if __name__ == '__main__':
    unittest.main()
