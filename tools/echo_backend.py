"""Local TCP/UDP echo backends to demonstrate filtering without Internet access."""
from __future__ import annotations

import argparse
import socketserver
import threading


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address=True
    daemon_threads=True

class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        while True:
            try:data=self.request.recv(65536)
            except TimeoutError:break
            if not data:break
            self.request.sendall(data)

class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        sock.sendto(data,self.client_address)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--tcp-port',type=int,default=19080)
    p.add_argument('--udp-port',type=int,default=19053)
    args=p.parse_args()
    with TCPServer(('127.0.0.1',args.tcp_port),TCPHandler) as tcp, \
         UDPServer(('127.0.0.1',args.udp_port),UDPHandler) as udp:
        threading.Thread(target=udp.serve_forever,daemon=True).start()
        print(f'Local backends: TCP 127.0.0.1:{args.tcp_port}, UDP 127.0.0.1:{args.udp_port}',flush=True)
        try:tcp.serve_forever()
        except KeyboardInterrupt:pass
        finally:udp.shutdown()


if __name__=='__main__':main()
