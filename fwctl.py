"""Local CLI for authenticated admin API; reads token from a chmod-600 local file."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def api(path, method='GET', body=None, base='http://127.0.0.1:18081', token_file='.firewall/admin.token'):
    token = Path(token_file).read_text('utf-8').strip()
    data = json.dumps(body).encode() if body is not None else None
    req = Request(base + path, data=data, method=method, headers={
        'X-Admin-Token': token,
        'Content-Type': 'application/json',
    })
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.load(resp)
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def main():
    parser = argparse.ArgumentParser(description='Manage firewall rules without restarting service')
    parser.add_argument('--base', default='http://127.0.0.1:18081')
    parser.add_argument('--token-file', default='.firewall/admin.token')
    sub = parser.add_subparsers(dest='cmd', required=True)
    for name in ('status','list','conflicts','reload'): sub.add_parser(name)
    add = sub.add_parser('add')
    add.add_argument('--action', choices=['allow','deny'], required=True)
    add.add_argument('--direction', choices=['in','out'], default='in')
    add.add_argument('--proto', choices=['TCP','UDP'], default='TCP')
    add.add_argument('--src-ip-cidr', default='0.0.0.0/0')
    add.add_argument('--dst-ip-cidr', default='0.0.0.0/0')
    add.add_argument('--src-port', type=int, default=0)
    add.add_argument('--dst-port', type=int, default=0)
    add.add_argument('--priority', type=int, default=100)
    for name in ('enable','disable','delete'):
        p = sub.add_parser(name); p.add_argument('id', type=int)
    evaluate = sub.add_parser('evaluate', help='Simulation only; does not transmit packets')
    evaluate.add_argument('--direction', choices=['in','out'], required=True)
    evaluate.add_argument('--proto', choices=['TCP','UDP'], required=True)
    evaluate.add_argument('--src-ip', required=True)
    evaluate.add_argument('--dst-ip', required=True)
    evaluate.add_argument('--src-port', type=int, required=True)
    evaluate.add_argument('--dst-port', type=int, required=True)
    args = parser.parse_args()
    mapping = {'status':('GET','/status'), 'list':('GET','/rules'),
               'conflicts':('GET','/conflicts'), 'reload':('POST','/reload')}
    if args.cmd in mapping:
        method, path = mapping[args.cmd]; body = {} if method=='POST' else None
    elif args.cmd=='add':
        method,path='POST','/rules';body={k: v for k,v in vars(args).items()
             if k in ('action','direction','proto','src_port','dst_port','priority','src_ip_cidr','dst_ip_cidr')}
    elif args.cmd=='evaluate':
        method,path='POST','/evaluate';body={k:v for k,v in vars(args).items()
             if k in ('direction','proto','src_ip','dst_ip','src_port','dst_port')}
    else:
        method='DELETE' if args.cmd=='delete' else 'PATCH'
        path=f'/rules/{args.id}'
        body=None if method=='DELETE' else {'enabled':args.cmd=='enable'}
    try:
        status, result=api(path,method,body,base=args.base,token_file=args.token_file)
        print(f'HTTP {status}\n{json.dumps(result,ensure_ascii=False,indent=2)}')
    except (URLError,OSError) as exc:
        parser.exit(2, f'Admin API error: {exc}\n')
    if status>=400: parser.exit(1)


if __name__=='__main__': main()
