"""Validated IPv4 TCP/UDP rule engine with deterministic first-match precedence.

This is a rule engine for *proxied flows*, not a Linux kernel packet firewall.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import ipaddress
import json
import os
from pathlib import Path
import threading


class RuleError(ValueError):
    pass


class DuplicateRule(RuleError):
    pass


FIELDS = {
    'id', 'action', 'direction', 'src_ip_cidr', 'dst_ip_cidr',
    'src_port', 'dst_port', 'proto', 'priority', 'enabled',
}


@dataclass(frozen=True)
class Flow:
    direction: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str


@dataclass(frozen=True)
class Rule:
    id: int = 0
    action: str = 'deny'
    direction: str = 'in'
    src_ip_cidr: str = '0.0.0.0/0'
    dst_ip_cidr: str = '0.0.0.0/0'
    src_port: int = 0
    dst_port: int = 0
    proto: str = 'TCP'
    priority: int = 100
    enabled: bool = True

    @classmethod
    def build(cls, data: dict, rule_id: int = 0) -> 'Rule':
        if not isinstance(data, dict):
            raise RuleError('Rule must be a JSON object')
        unknown = set(data) - FIELDS
        if unknown:
            raise RuleError('Unknown fields: ' + ', '.join(sorted(unknown)))
        if 'id' in data and data['id'] != rule_id:
            raise RuleError('Rule id is managed by the server')
        fields = {k: v for k, v in data.items() if k != 'id'}
        action = fields.get('action', 'deny')
        direction = fields.get('direction', 'in')
        proto = fields.get('proto', 'TCP')
        if action not in ('allow', 'deny'):
            raise RuleError('action must be allow or deny')
        if direction not in ('in', 'out'):
            raise RuleError('direction must be in or out')
        if proto not in ('TCP', 'UDP'):
            raise RuleError('proto must be TCP or UDP')
        fields['action'] = action
        fields['direction'] = direction
        fields['proto'] = proto
        for cidr in ('src_ip_cidr', 'dst_ip_cidr'):
            try:
                parsed = ipaddress.ip_network(fields.get(cidr, '0.0.0.0/0'), strict=False)
                if parsed.version != 4:
                    raise RuleError('Only IPv4 is supported')
                fields[cidr] = str(parsed)
            except (ValueError, TypeError) as exc:
                raise RuleError(f'Invalid {cidr}') from exc
        for port in ('src_port', 'dst_port'):
            value = fields.get(port, 0)
            if type(value) is not int or not 0 <= value <= 65535:
                raise RuleError(f'{port} must be integer 0..65535; 0 means any')
        priority = fields.get('priority', 100)
        if type(priority) is not int or not 1 <= priority <= 1000:
            raise RuleError('priority must be integer 1..1000')
        if type(fields.get('enabled', True)) is not bool:
            raise RuleError('enabled must be boolean')
        return cls(id=rule_id, **fields)

    def asdict(self) -> dict:
        return asdict(self)

    def matches(self, flow: Flow) -> bool:
        return bool(self.enabled and self.direction == flow.direction
                    and self.proto == flow.proto
                    and ipaddress.ip_address(flow.src_ip) in ipaddress.ip_network(self.src_ip_cidr)
                    and ipaddress.ip_address(flow.dst_ip) in ipaddress.ip_network(self.dst_ip_cidr)
                    and (self.src_port == 0 or self.src_port == flow.src_port)
                    and (self.dst_port == 0 or self.dst_port == flow.dst_port))


def sort_key(rule: Rule) -> tuple:
    # Higher precedence is *lower* priority; deny wins equal-priority ties.
    return rule.priority, 0 if rule.action == 'deny' else 1, rule.id


def overlaps(a: Rule, b: Rule) -> bool:
    if a.proto != b.proto or a.direction != b.direction:
        return False
    return (ipaddress.ip_network(a.src_ip_cidr).overlaps(ipaddress.ip_network(b.src_ip_cidr))
            and ipaddress.ip_network(a.dst_ip_cidr).overlaps(ipaddress.ip_network(b.dst_ip_cidr))
            and (0 in (a.src_port, b.src_port) or a.src_port == b.src_port)
            and (0 in (a.dst_port, b.dst_port) or a.dst_port == b.dst_port))


def rules_equivalent(a: Rule, b: Rule) -> bool:
    aa = a.asdict(); bb = b.asdict()
    aa.pop('id'); bb.pop('id')
    return aa == bb


class RuleManager:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.reload(initial=True)

    def _read(self) -> tuple[dict, list[Rule]]:
        obj = json.loads(self.path.read_text('utf-8'))
        if not isinstance(obj, dict) or not isinstance(obj.get('services'), list):
            raise RuleError('Config requires services array')
        admin = obj.get('admin', {})
        if not isinstance(admin, dict) or admin.get('host', '127.0.0.1') != '127.0.0.1':
            raise RuleError('Admin API must bind 127.0.0.1')
        admin_port = admin.get('port', 18081)
        if type(admin_port) is not int or not 1 <= admin_port <= 65535:
            raise RuleError('Invalid admin port')
        logging = obj.get('logging', {})
        if not isinstance(logging, dict) or not isinstance(logging.get('path'), str) or not logging['path']:
            raise RuleError('logging.path is required')
        rules = []
        ids = set()
        for item in obj.get('rules', []):
            if type(item) is not dict or type(item.get('id')) is not int or item['id'] < 1:
                raise RuleError('Persisted rule requires a positive integer id')
            if item['id'] in ids:
                raise RuleError('Duplicate persisted rule id')
            ids.add(item['id'])
            rules.append(Rule.build(item, rule_id=item['id']))
        if obj.get('default_action', 'allow') not in ('allow', 'deny'):
            raise RuleError('default_action must be allow or deny')
        for svc in obj['services']:
            if svc.get('proto') not in ('TCP', 'UDP'):
                raise RuleError('Invalid service proto')
            for k in ('listen_ip', 'target_ip'):
                value = ipaddress.ip_address(svc[k])
                if value.version != 4:
                    raise RuleError('Only IPv4 services supported')
            for k in ('listen_port', 'target_port'):
                if type(svc[k]) is not int or not 1 <= svc[k] <= 65535:
                    raise RuleError('Invalid service port')
        return obj, rules

    def reload(self, initial=False) -> None:
        with self._lock:
            config, rules = self._read()
            if not initial and any(config.get(key) != self.config.get(key) for key in ('services','admin','logging','default_action')):
                raise RuleError('Changes outside the rules table require service restart')
            self.config = config
            self.rules = sorted(rules, key=sort_key)
            self.next_id = max((r.id for r in rules), default=0) + 1

    def _save(self, rules: list[Rule]) -> None:
        newcfg = dict(self.config)
        newcfg['rules'] = [r.asdict() for r in sorted(rules, key=sort_key)]
        # In-memory change only after successful atomic durable config replace.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(self.path.name + '.tmp')
        try:
            with temp.open('w', encoding='utf-8') as f:
                json.dump(newcfg, f, indent=2, ensure_ascii=False)
                f.write('\n')
                f.flush()
                os.fsync(f.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, self.path)
        finally:
            temp.unlink(missing_ok=True)
        self.config = newcfg
        self.rules = sorted(rules, key=sort_key)

    def list_rules(self) -> list[dict]:
        with self._lock:
            return [r.asdict() for r in self.rules]

    def decision(self, flow: Flow) -> dict:
        with self._lock:
            for rule in self.rules:
                if rule.matches(flow):
                    return {'action': rule.action, 'rule_id': rule.id, 'reason': f'matched_rule_{rule.id}'}
            return {'action': self.config.get('default_action', 'allow'),
                    'rule_id': None, 'reason': 'default_policy'}

    def warnings_for(self, new: Rule, omit_id: int = -1) -> list[dict]:
        with self._lock:
            warnings = []
            for old in self.rules:
                if old.id == omit_id or not old.enabled or not new.enabled:
                    continue
                if overlaps(old, new):
                    kind = 'conflict' if old.action != new.action else 'overlap_same_action'
                    warnings.append({'type': kind, 'existing_id': old.id,
                                     'resolution': 'lower priority number wins; deny wins equal-priority ties'})
            return warnings

    def add(self, payload: dict) -> dict:
        with self._lock:
            new = Rule.build(payload, self.next_id)
            if any(rules_equivalent(old, new) for old in self.rules):
                raise DuplicateRule('Exact duplicate rule')
            warnings = self.warnings_for(new)
            self._save(self.rules + [new])
            self.next_id += 1
            return {'rule': new.asdict(), 'warnings': warnings}

    def update(self, rule_id: int, patch: dict) -> dict:
        if not isinstance(patch, dict) or not patch or set(patch) - (FIELDS - {'id'}):
            raise RuleError('Invalid patch fields')
        with self._lock:
            old = next((r for r in self.rules if r.id == rule_id), None)
            if old is None:
                raise KeyError('Rule not found')
            payload = old.asdict()
            payload.update(patch)
            new = Rule.build(payload, rule_id=rule_id)
            if any(rules_equivalent(r, new) for r in self.rules if r.id != rule_id):
                raise DuplicateRule('Exact duplicate rule')
            warnings = self.warnings_for(new, omit_id=rule_id)
            self._save([new if r.id == rule_id else r for r in self.rules])
            return {'rule': new.asdict(), 'warnings': warnings}

    def delete(self, rule_id: int) -> dict:
        with self._lock:
            if not any(r.id == rule_id for r in self.rules):
                raise KeyError('Rule not found')
            self._save([r for r in self.rules if r.id != rule_id])
            return {'deleted_id': rule_id}

    def conflicts(self) -> list[dict]:
        with self._lock:
            res = []
            for i, a in enumerate(self.rules):
                for b in self.rules[i + 1:]:
                    if a.enabled and b.enabled and overlaps(a, b):
                        res.append({'ids': [a.id, b.id],
                                    'type': 'conflict' if a.action != b.action else 'overlap_same_action',
                                    'winner': min((a, b), key=sort_key).id})
            return res
