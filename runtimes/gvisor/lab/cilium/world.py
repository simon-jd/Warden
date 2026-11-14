#!/usr/bin/env python3
"""Stand-ins for the "world" of the k3s Cilium lab (scripts/k3s_gvisor_lab.sh up --cilium).

Each runs in its own container on the internal Docker network
warden-k3s-world, which has no route out, and logs one line per event to
stdout, prefixed with the epoch time (container clock = host clock). The live
tests (controlplane/internal/ciliumlab) read them with `docker logs`.

    world.py http BODY      HTTP on :80 and :443 (plain, no TLS), 200 BODY to every GET;
                            the origins and the metadata stand-in
    world.py dns            UDP :53, logs every query; TXT is answered, anything else
                            NXDOMAIN; the resolver an exfiltration would end at
    world.py stream [MS]    TCP :443; per connection it logs every line received and
                            sends a heartbeat line every MS ms (default 20)

Log lines:  <t> http <client> <host> <path>
            <t> dns <client> <type> <name>
            <t> open <conn> <client> | rx <conn> <line> | close <conn> <reason>
Heartbeat:  hb <conn> <seq> <t>
"""
import http.server
import itertools
import socket
import socketserver
import struct
import sys
import threading
import time

TXT_ANSWER = 'warden-lab-exfil-received'
QTYPES = {1: 'A', 16: 'TXT', 28: 'AAAA'}


def log(*parts):
    print('%.3f %s' % (time.time(), ' '.join(str(p) for p in parts)), flush=True)


def dns_reply(data, client):
    """The reply to one DNS query, or None for anything that is not one."""
    if len(data) < 12:
        return None
    qid, flags, qd = struct.unpack('>HHH', data[:6])
    if flags & 0x8000 or qd != 1:
        return None
    i, labels = 12, []
    while True:
        if i >= len(data):
            return None
        n = data[i]
        i += 1
        if n == 0:
            break
        if n > 63 or i + n > len(data):
            return None
        labels.append(data[i:i + n].decode('ascii', 'replace'))
        i += n
    if i + 4 > len(data):
        return None
    qtype, _ = struct.unpack('>HH', data[i:i + 4])
    question = data[12:i + 4]
    name = '.'.join(labels)
    log('dns', client[0], QTYPES.get(qtype, qtype), name)
    rd = flags & 0x0100
    if qtype == 16:
        text = TXT_ANSWER.encode()
        rdata = bytes([len(text)]) + text
        answer = struct.pack('>HHHIH', 0xC00C, 16, 1, 0, len(rdata)) + rdata
        return struct.pack('>HHHHHH', qid, 0x8400 | rd, 1, 1, 0, 0) + question + answer
    return struct.pack('>HHHHHH', qid, 0x8403 | rd, 1, 0, 0, 0) + question


def serve_dns(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(addr)
    while True:
        data, client = s.recvfrom(4096)
        reply = dns_reply(data, client)
        if reply is not None:
            s.sendto(reply, client)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def http_server(addr, body):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def do_GET(self):
            log('http', self.client_address[0], self.headers.get('Host', '-'), self.path)
            data = (body + '\n').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return http.server.ThreadingHTTPServer(addr, Handler)


_conns = itertools.count(1)


def stream_server(addr, every):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            conn = next(_conns)
            log('open', conn, self.client_address[0])
            stop = threading.Event()

            def beat():
                for seq in itertools.count(1):
                    if stop.wait(every):
                        return
                    try:
                        self.wfile.write(('hb %d %d %.3f\n' % (conn, seq, time.time())).encode())
                        self.wfile.flush()
                    except OSError:
                        return

            threading.Thread(target=beat, daemon=True).start()
            reason = 'eof'
            try:
                for line in self.rfile:
                    log('rx', conn, line.decode('ascii', 'replace').strip())
            except OSError as e:
                reason = type(e).__name__
            stop.set()
            log('close', conn, reason)

    return Server(addr, Handler)


def main(argv):
    mode = argv[0] if argv else ''
    if mode == 'http' and len(argv) == 2:
        servers = [http_server(('0.0.0.0', port), argv[1]) for port in (80, 443)]
        for s in servers[1:]:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        log('serving http', argv[1])
        servers[0].serve_forever()
    elif mode == 'dns' and len(argv) == 1:
        log('serving dns')
        serve_dns(('0.0.0.0', 53))
    elif mode == 'stream' and len(argv) <= 2:
        every = int(argv[1]) / 1000 if len(argv) == 2 else 0.02
        log('serving stream every', every)
        stream_server(('0.0.0.0', 443), every).serve_forever()
    else:
        sys.exit(__doc__.strip().split('\n\n')[1])


if __name__ == '__main__':
    main(sys.argv[1:])
