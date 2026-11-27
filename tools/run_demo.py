"""Self-contained REAL localhost TCP/UDP demonstration (not simulated decisions).

Starts two echo backends and the firewall proxy on ephemeral loopback ports,
toggles rules over authenticated admin API, analyzes generated JSONL logs.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import platform
from pathlib import Path
import secrets
import socket
import tempfile
import threading

from analyze_logs import analyze
from firewall import FirewallRuntime
from fwctl import api
from tools.echo_backend import TCPServer, TCPHandler, UDPServer, UDPHandler
from tools.demo_client import tcp_roundtrip, udp_roundtrip


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]


def run():
    report={'utc':datetime.now(timezone.utc).isoformat(),
            'python':platform.python_version(), 'os':platform.platform(),
            'note':'Executed real TCP/UDP socket calls over 127.0.0.1 (no kernel-wide interception)'}
    with tempfile.TemporaryDirectory(prefix='lr7demo-') as directory:
        root=Path(directory)
        tok=root/'admin.token';tok.write_text(secrets.token_urlsafe(36))
        tcpbackend=TCPServer(('127.0.0.1',0),TCPHandler)
        udpbackend=UDPServer(('127.0.0.1',0),UDPHandler)
        backends=[tcpbackend,udpbackend]
        for srv in backends:
            threading.Thread(target=srv.serve_forever,kwargs={'poll_interval':0.05},daemon=True).start()
        tcpport=port();udpport=port(socket.SOCK_DGRAM);adminport=port()
        conf=root/'config.json'
        log=root/'events.jsonl'
        conf.write_text(json.dumps({
          'admin':{'host':'127.0.0.1','port':adminport},
          'logging':{'path':str(log)},'default_action':'allow',
          'services':[
            {'proto':'TCP','listen_ip':'127.0.0.1','listen_port':tcpport,'target_ip':'127.0.0.1','target_port':tcpbackend.server_address[1]},
            {'proto':'UDP','listen_ip':'127.0.0.1','listen_port':udpport,'target_ip':'127.0.0.1','target_port':udpbackend.server_address[1]}],
          'rules':[]
        }))
        fw=None
        try:
            fw=FirewallRuntime(conf,tok);fw.start()
            url=f'http://127.0.0.1:{adminport}'
            def call(path,method='GET',payload=None):
                status,body=api(path,method,payload,base=url,token_file=tok)
                if status>=400:raise RuntimeError(f'API {status}: {body}')
                return body
            text=b'LR7 local TCP test'
            udptext=b'LR7 local UDP test'
            report['tcp_allow_before']=tcp_roundtrip(port=tcpport,message=text)==text
            report['udp_allow_before']=udp_roundtrip(port=udpport,message=udptext)==udptext
            tcpdenied=call('/rules','POST',{'action':'deny','direction':'in','proto':'TCP',
                                            'src_ip_cidr':'127.0.0.1/32',
                                            'dst_port':tcpbackend.server_address[1]})['rule']['id']
            report['tcp_denied_when_rule_enabled']=tcp_roundtrip(port=tcpport,message=text)==b''
            call(f'/rules/{tcpdenied}','PATCH',{'enabled':False})
            report['tcp_allowed_after_disable']=tcp_roundtrip(port=tcpport,message=text)==text
            call(f'/rules/{tcpdenied}','PATCH',{'enabled':True})
            report['tcp_denied_after_enable']=tcp_roundtrip(port=tcpport,message=text)==b''
            conflict=call('/rules','POST',{'action':'allow','direction':'in','proto':'TCP',
                                          'dst_port':tcpbackend.server_address[1], 'priority':50})
            report['overlap_warning_generated']=any(w['type']=='conflict' for w in conflict['warnings'])
            report['conflicts_count']=len(call('/conflicts')['conflicts'])
            report['tcp_allow_higher_priority']=tcp_roundtrip(port=tcpport,message=text)==text
            # Deny UDP outbound by target port.
            call('/rules','POST',{'action':'deny','direction':'out','proto':'UDP',
                                  'dst_port':udpbackend.server_address[1]})
            report['udp_denied_outbound']=udp_roundtrip(port=udpport,message=udptext)==b''
            report['log_summary']=analyze(log)
            report['pass']=all(report[k] for k in (
               'tcp_allow_before','udp_allow_before','tcp_denied_when_rule_enabled',
               'tcp_allowed_after_disable','tcp_denied_after_enable',
               'overlap_warning_generated','tcp_allow_higher_priority','udp_denied_outbound'))
            report['network']={'tcp_proxy':f'127.0.0.1:{tcpport}',
                               'udp_proxy':f'127.0.0.1:{udpport}',
                               'tcp_backend':f'127.0.0.1:{tcpbackend.server_address[1]}',
                               'udp_backend':f'127.0.0.1:{udpbackend.server_address[1]}'}
        finally:
            if fw is not None:fw.stop()
            for srv in backends:srv.shutdown();srv.server_close()
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--out',default='reports/local-demo.json')
    args=p.parse_args()
    report=run()
    print(json.dumps(report,ensure_ascii=False,indent=2))
    if args.out:
        path=Path(args.out);path.parent.mkdir(exist_ok=True,parents=True)
        path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(f'Report: {path}')
    if not report['pass']:raise SystemExit(1)


if __name__=='__main__':main()
