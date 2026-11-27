"""Send real TCP/UDP datagrams through the managed local proxy ports."""
import argparse
import socket


def tcp_roundtrip(host='127.0.0.1',port=18080,message=b'Hello firewall'):
    try:
        with socket.create_connection((host,port),timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(message)
            return sock.recv(65536)
    except (ConnectionResetError,BrokenPipeError,TimeoutError,OSError):
        return b''


def udp_roundtrip(host='127.0.0.1',port=15353,message=b'Hello firewall'):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(message,(host,port))
        try:return sock.recvfrom(65535)[0]
        except TimeoutError:return b''


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--proto',choices=['TCP','UDP'],default='TCP')
    p.add_argument('--port',type=int)
    p.add_argument('--msg',default='Hello firewall')
    args=p.parse_args()
    port=args.port or (18080 if args.proto=='TCP' else 15353)
    msg=args.msg.encode()
    reply=(tcp_roundtrip if args.proto=='TCP' else udp_roundtrip)(port=port,message=msg)
    print(f'{args.proto} request bytes={len(msg)}, response bytes={len(reply)}, '
          f'matched={reply==msg}, response={reply!r}')
    if reply!=msg:print('Blocked or upstream unavailable; inspect logs for reason')


if __name__=='__main__':main()
