import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import threading
import unittest

from analyze_logs import analyze
from firewall import FirewallRuntime
from fwctl import api
from tools.echo_backend import TCPServer, TCPHandler, UDPServer, UDPHandler
from tools.demo_client import tcp_roundtrip, udp_roundtrip


def get_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET,kind) as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


class IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.echo_tcp=TCPServer(('127.0.0.1',0),TCPHandler)
        cls.echo_udp=UDPServer(('127.0.0.1',0),UDPHandler)
        for srv in (cls.echo_tcp,cls.echo_udp):
            threading.Thread(target=srv.serve_forever,daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.echo_tcp,cls.echo_udp):
            srv.shutdown();srv.server_close()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.token=secrets.token_urlsafe(36)
        self.tokenfile=root/'admin.token'
        self.tokenfile.write_text(self.token)
        self.admin_port=get_port()
        self.tcp_port=get_port()
        self.udp_port=get_port(socket.SOCK_DGRAM)
        self.logpath=root/'events.jsonl'
        self.config=root/'config.json'
        self.config.write_text(json.dumps({
          'admin':{'host':'127.0.0.1','port':self.admin_port},
          'logging':{'path':str(self.logpath)}, 'default_action':'allow',
          'services':[
            {'proto':'TCP','listen_ip':'127.0.0.1','listen_port':self.tcp_port,
             'target_ip':'127.0.0.1','target_port':self.echo_tcp.server_address[1]},
            {'proto':'UDP','listen_ip':'127.0.0.1','listen_port':self.udp_port,
             'target_ip':'127.0.0.1','target_port':self.echo_udp.server_address[1]}],
          'rules':[]
        }))
        self.runtime=FirewallRuntime(self.config,self.tokenfile)
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        self.api_base=f'http://127.0.0.1:{self.admin_port}'

    def api(self,route,method='GET',body=None):
        return api(route,method,body,base=self.api_base,token_file=self.tokenfile)

    def add_rule(self,**kw):
        return self.api('/rules','POST',kw)

    def test_tcp_roundtrip(self):
        self.assertEqual(tcp_roundtrip(port=self.tcp_port,message=b'hello'),'hello'.encode())

    def test_udp_roundtrip(self):
        self.assertEqual(udp_roundtrip(port=self.udp_port,message=b'hello'),'hello'.encode())

    def test_tcp_denied_inbound(self):
        status,data=self.add_rule(action='deny',direction='in',proto='TCP',dst_port=self.echo_tcp.server_address[1])
        self.assertEqual(status,201)
        self.assertEqual(tcp_roundtrip(port=self.tcp_port,message=b'denied'),b'')
        stats=analyze(self.logpath,action='deny')
        self.assertGreaterEqual(stats['denied_count'],1)
        self.assertEqual(stats['denied_by_direction'],{'in':1})

    def test_tcp_denied_outbound(self):
        status,data=self.add_rule(action='deny',direction='out',proto='TCP',dst_port=self.echo_tcp.server_address[1])
        self.assertEqual(status,201)
        self.assertEqual(tcp_roundtrip(port=self.tcp_port,message=b'no'),b'')
        stats=analyze(self.logpath,action='deny')
        self.assertEqual(stats['denied_by_direction'],{'out':1})

    def test_udp_denied_inbound(self):
        self.add_rule(action='deny',direction='in',proto='UDP',dst_port=self.echo_udp.server_address[1])
        self.assertEqual(udp_roundtrip(port=self.udp_port,message=b'no'),b'')
        stats=analyze(self.logpath,action='deny')
        self.assertEqual(stats['denied_by_protocol'],{'UDP':1})

    def test_udp_denied_outbound(self):
        self.add_rule(action='deny',direction='out',proto='UDP',dst_port=self.echo_udp.server_address[1])
        self.assertEqual(udp_roundtrip(port=self.udp_port,message=b'no'),b'')
        stats=analyze(self.logpath,action='deny')
        self.assertEqual(stats['denied_by_direction'],{'out':1})

    def test_dynamic_enable_disable(self):
        status,created=self.add_rule(action='deny',direction='in',proto='TCP',dst_port=self.echo_tcp.server_address[1])
        rid=created['rule']['id']
        self.assertEqual(tcp_roundtrip(port=self.tcp_port),b'')
        self.assertEqual(self.api(f'/rules/{rid}','PATCH',{'enabled':False})[0],200)
        self.assertEqual(tcp_roundtrip(port=self.tcp_port),b'Hello firewall')
        self.assertEqual(self.api(f'/rules/{rid}','PATCH',{'enabled':True})[0],200)
        self.assertEqual(tcp_roundtrip(port=self.tcp_port),b'')
        self.assertEqual(self.api(f'/rules/{rid}','DELETE')[0],200)
        self.assertEqual(tcp_roundtrip(port=self.tcp_port),b'Hello firewall')

    def test_rules_persist(self):
        self.add_rule(action='deny',direction='in',proto='TCP',dst_port=19080)
        self.assertEqual(len(json.loads(self.config.read_text())['rules']),1)
        self.assertEqual(self.api('/reload','POST',{})[0],200)

    def test_duplicate_409(self):
        args={'action':'deny','direction':'in','proto':'TCP','dst_port':19080}
        self.assertEqual(self.api('/rules','POST',args)[0],201)
        self.assertEqual(self.api('/rules','POST',args)[0],409)

    def test_conflict_endpoint(self):
        self.add_rule(action='allow',direction='in',proto='TCP',dst_port=19080,priority=50)
        status,resp=self.add_rule(action='deny',direction='in',proto='TCP',dst_port=19080,priority=100)
        self.assertEqual(resp['warnings'][0]['type'],'conflict')
        self.assertEqual(len(self.api('/conflicts')[1]['conflicts']),1)

    def test_auth_token_enforced(self):
        import urllib.request
        try:
            urllib.request.urlopen(self.api_base+'/rules',timeout=3)
            self.fail('Must reject missing admin token')
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code,401)
        self.assertEqual(self.api('/rules')[0],200)

    def test_reject_invalid_patch(self):
        status,x=self.add_rule(action='deny',direction='in',proto='TCP')
        self.assertEqual(self.api(f"/rules/{x['rule']['id']}",'PATCH',{'src_port':70000})[0],400)

    def test_reject_malformed_rule(self):
        self.assertEqual(self.add_rule(action='DROP')[0],400)

    def test_simulated_flow_marked_as_simulation(self):
        status,result=self.api('/evaluate','POST',dict(direction='in',src_ip='127.0.0.1',
          dst_ip='127.0.0.1',src_port=40000,dst_port=19080,proto='TCP'))
        self.assertEqual(status,200)
        self.assertIn('simulation',result['note'])


if __name__=='__main__':unittest.main()
