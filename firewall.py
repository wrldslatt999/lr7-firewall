"""Educational IPv4 TCP/UDP application-proxy firewall, admin API on loopback."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
from urllib.parse import urlsplit

from eventlog import EventLog
from proxy import TCPProxy, UDPProxy
from rule_engine import RuleError, DuplicateRule, RuleManager, Flow


MAX_BODY = 16384


def admin_handler(runtime):
    class AdminHandler(BaseHTTPRequestHandler):
        server_version = 'LR7Admin'
        sys_version = ''

        def log_message(self, fmt, *args):
            # Do not log Authorization tokens or HTTP request bodies.
            pass

        def _answer(self, status, body):
            raw = json.dumps(body, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _auth(self):
            actual = self.headers.get('X-Admin-Token', '')
            allowed = bool(actual and secrets.compare_digest(actual, runtime.token))
            if not allowed:
                runtime.log.write('admin.denied', reason='missing_or_bad_token')
                self._answer(401, {'error': 'unauthorized'})
            return allowed

        def _payload(self):
            try:
                n = int(self.headers.get('Content-Length', '0'))
                if not 0 < n <= MAX_BODY:
                    raise RuleError('JSON payload must contain 1..16384 bytes')
                raw = self.rfile.read(n)
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise RuleError('Expected JSON object')
                return body
            except (ValueError, UnicodeDecodeError) as exc:
                raise RuleError('Invalid JSON') from exc

        def _route_id(self):
            path = urlsplit(self.path).path
            if not path.startswith('/rules/'):
                return None
            try:
                n = int(path[len('/rules/'):])
                return n if n > 0 else None
            except ValueError:
                return None

        def do_GET(self):
            if not self._auth(): return
            path = urlsplit(self.path).path
            if path == '/status':
                self._answer(200, {'status': 'running', 'services': runtime.manager.config['services'],
                                   'rule_count': len(runtime.manager.list_rules()),
                                   'default_action': runtime.manager.config.get('default_action', 'allow')})
            elif path == '/rules':
                self._answer(200, {'rules': runtime.manager.list_rules()})
            elif path == '/conflicts':
                self._answer(200, {'conflicts': runtime.manager.conflicts()})
            else:
                self._answer(404, {'error': 'not_found'})

        def do_POST(self):
            if not self._auth(): return
            path = urlsplit(self.path).path
            try:
                if path == '/rules':
                    result = runtime.manager.add(self._payload())
                    runtime.log.write('rule.added', rule_id=result['rule']['id'], warnings=len(result['warnings']))
                    self._answer(201, result)
                elif path == '/reload':
                    runtime.manager.reload()
                    runtime.log.write('rules.reloaded', rule_count=len(runtime.manager.list_rules()))
                    self._answer(200, {'reloaded': True})
                elif path == '/evaluate':
                    req = self._payload()
                    required = {'direction','src_ip','dst_ip','src_port','dst_port','proto'}
                    if set(req) != required:
                        raise RuleError('Flow requires exactly: ' + ', '.join(sorted(required)))
                    flow = Flow(**req)
                    # Validate packet metadata (especially IP and port).
                    import ipaddress
                    for value in (flow.src_ip, flow.dst_ip):
                        if ipaddress.ip_address(value).version != 4:
                            raise RuleError('Only IPv4')
                    for value in (flow.src_port, flow.dst_port):
                        if type(value) is not int or not 0 <= value <= 65535:
                            raise RuleError('Invalid port')
                    if flow.proto not in ('TCP','UDP') or flow.direction not in ('in','out'):
                        raise RuleError('Invalid direction or protocol')
                    self._answer(200, {'note':'simulation only, no network traffic generated',
                                       'decision': runtime.manager.decision(flow)})
                else: self._answer(404, {'error':'not_found'})
            except DuplicateRule as exc:
                self._answer(409, {'error':'duplicate_rule','detail':str(exc)})
            except (RuleError, ValueError) as exc:
                self._answer(400, {'error':'bad_request','detail':str(exc)})
            except OSError:
                self._answer(500, {'error':'config_write_failed'})

        def do_PATCH(self):
            if not self._auth(): return
            rid = self._route_id()
            if rid is None: return self._answer(404, {'error':'not_found'})
            try:
                result = runtime.manager.update(rid, self._payload())
                runtime.log.write('rule.updated', rule_id=rid)
                self._answer(200, result)
            except KeyError: self._answer(404, {'error':'rule_not_found'})
            except DuplicateRule as exc: self._answer(409, {'error':'duplicate_rule','detail':str(exc)})
            except RuleError as exc: self._answer(400, {'error':'bad_request','detail':str(exc)})
            except OSError: self._answer(500, {'error':'config_write_failed'})

        def do_DELETE(self):
            if not self._auth(): return
            rid = self._route_id()
            if rid is None: return self._answer(404, {'error':'not_found'})
            try:
                result = runtime.manager.delete(rid)
                runtime.log.write('rule.deleted', rule_id=rid)
                self._answer(200, result)
            except KeyError: self._answer(404, {'error':'rule_not_found'})
            except OSError: self._answer(500, {'error':'config_write_failed'})

    return AdminHandler


class FirewallRuntime:
    def __init__(self, config_path='config.json', token_path='.firewall/admin.token'):
        self.manager = RuleManager(config_path)
        self.log = EventLog(self.manager.config['logging']['path'])
        self.token = Path(token_path).read_text('utf-8').strip()
        if len(self.token) < 32:
            raise ValueError('Admin token too short; run setup_lab.py')
        host = self.manager.config.get('admin', {}).get('host','127.0.0.1')
        port = self.manager.config.get('admin', {}).get('port', 18081)
        self.api = ThreadingHTTPServer((host, port), admin_handler(self))
        self.servers = []
        try:
            for svc in self.manager.config['services']:
                cls = TCPProxy if svc['proto'] == 'TCP' else UDPProxy
                self.servers.append(cls(svc, self.manager, self.log))
        except Exception:
            self.api.server_close()
            for server in self.servers: server.server_close()
            raise
        self.threads = []

    def start(self):
        for srv in [self.api, *self.servers]:
            t = threading.Thread(target=srv.serve_forever, kwargs={'poll_interval':0.05}, daemon=True)
            t.start()
            self.threads.append(t)
        self.log.write('service.started', services=len(self.servers))

    def stop(self):
        for srv in [self.api, *self.servers]:
            srv.shutdown()
            srv.server_close()
        self.log.write('service.stopped')
        for thread in self.threads: thread.join(timeout=2)


def main():
    ap = argparse.ArgumentParser(description='Educational user-space TCP/UDP filtering proxy')
    ap.add_argument('--config', default='config.json')
    ap.add_argument('--token-file', default='.firewall/admin.token')
    args = ap.parse_args()
    runtime = FirewallRuntime(args.config, args.token_file)
    runtime.start()
    print('Firewall proxy started; admin API at http://127.0.0.1:%s' % runtime.api.server_address[1], flush=True)
    print('Managed proxy listeners:', [(s.server_address, type(s).__name__) for s in runtime.servers], flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print('Stopping proxy...', flush=True)
    finally:
        runtime.stop()


if __name__ == '__main__':
    main()
