"""TCP connection + UDP datagram firewall for explicitly configured proxy services."""
from __future__ import annotations

import selectors
import socket
import socketserver

from rule_engine import Flow


class TCPProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, service, rules, logger):
        self.service, self.rules, self.logger = service, rules, logger
        super().__init__((service['listen_ip'], service['listen_port']), TCPHandler)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        svc, rules, log = self.server.service, self.server.rules, self.server.logger
        ip, port = self.client_address
        inbound = Flow('in', ip, svc['target_ip'], port, svc['target_port'], 'TCP')
        result = rules.decision(inbound)
        log.flow('connection.allowed' if result['action'] == 'allow' else 'connection.denied', inbound, result)
        if result['action'] != 'allow':
            return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
            # Allocate local ephemeral source port to evaluate egress accurately.
            upstream.bind((self.server.server_address[0], 0))
            source_ip, source_port = upstream.getsockname()
            outbound = Flow('out', source_ip, svc['target_ip'], source_port, svc['target_port'], 'TCP')
            result = rules.decision(outbound)
            log.flow('connection.allowed' if result['action'] == 'allow' else 'connection.denied', outbound, result)
            if result['action'] != 'allow':
                return
            try:
                upstream.settimeout(3)
                upstream.connect((svc['target_ip'], svc['target_port']))
                self.request.setblocking(False)
                upstream.setblocking(False)
                self._relay(self.request, upstream)
            except OSError as exc:
                log.write('proxy.error', protocol='TCP', error_type=type(exc).__name__)

    @staticmethod
    def _relay(client, upstream):
        buffers = {client: bytearray(), upstream: bytearray()}
        peers = {client: upstream, upstream: client}
        reading = {client, upstream}
        with selectors.DefaultSelector() as selector:
            # 10 second idle timeout prevents indefinite test hangs.
            while reading or any(buffers.values()):
                for sock in (client, upstream):
                    events = (selectors.EVENT_READ if sock in reading and len(buffers[peers[sock]]) < 1024*1024 else 0)
                    events |= selectors.EVENT_WRITE if buffers[sock] else 0
                    try:
                        selector.modify(sock, events) if selector.get_key(sock) else None
                    except KeyError:
                        if events: selector.register(sock, events)
                    except ValueError:
                        pass
                    if not events:
                        try: selector.unregister(sock)
                        except (KeyError, ValueError): pass
                events = selector.select(timeout=8)
                if not events:
                    break
                for key, mask in events:
                    sock = key.fileobj
                    if mask & selectors.EVENT_READ:
                        try:
                            data = sock.recv(65536)
                        except (BlockingIOError, InterruptedError):
                            data = None
                        if data is None:
                            pass
                        elif data:
                            buffers[peers[sock]].extend(data)
                        else:
                            reading.discard(sock)
                            if not buffers[peers[sock]]:
                                try: peers[sock].shutdown(socket.SHUT_WR)
                                except OSError: pass
                    if mask & selectors.EVENT_WRITE and buffers[sock]:
                        try:
                            sent = sock.send(buffers[sock])
                            del buffers[sock][:sent]
                            if not buffers[sock] and peers[sock] not in reading:
                                try: sock.shutdown(socket.SHUT_WR)
                                except OSError: pass
                        except (BlockingIOError, InterruptedError):
                            pass


class UDPProxy(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, service, rules, logger):
        self.service, self.rules, self.logger = service, rules, logger
        super().__init__((service['listen_ip'], service['listen_port']), UDPHandler)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, listen_socket = self.request
        svc, rules, log = self.server.service, self.server.rules, self.server.logger
        ip, port = self.client_address
        inbound = Flow('in', ip, svc['target_ip'], port, svc['target_port'], 'UDP')
        result = rules.decision(inbound)
        log.flow('datagram.allowed' if result['action'] == 'allow' else 'datagram.denied', inbound, result, bytes=len(data))
        if result['action'] != 'allow':
            return
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.bind((self.server.server_address[0], 0))
            source_ip, source_port = upstream.getsockname()
            outbound = Flow('out', source_ip, svc['target_ip'], source_port, svc['target_port'], 'UDP')
            result = rules.decision(outbound)
            log.flow('datagram.allowed' if result['action'] == 'allow' else 'datagram.denied', outbound, result, bytes=len(data))
            if result['action'] != 'allow':
                return
            try:
                upstream.settimeout(1.5)
                upstream.sendto(data, (svc['target_ip'], svc['target_port']))
                reply, _ = upstream.recvfrom(65535)
                listen_socket.sendto(reply, self.client_address)
            except socket.timeout:
                log.write('proxy.timeout', protocol='UDP', target_port=svc['target_port'])
            except OSError as exc:
                log.write('proxy.error', protocol='UDP', error_type=type(exc).__name__)
