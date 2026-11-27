import json
import tempfile
from pathlib import Path
import unittest

from rule_engine import Rule, RuleError, RuleManager, DuplicateRule, Flow, overlaps


class RulesTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config=Path(self.tmp.name)/'config.json'
        self.config.write_text(json.dumps({
          'admin':{'host':'127.0.0.1','port':18081},'logging':{'path':'logs/events.jsonl'},
          'default_action':'allow', 'services':[], 'rules':[]}),encoding='utf-8')
        self.m=RuleManager(self.config)

    def base(self,**kw):
        return {**dict(action='deny', direction='in', proto='TCP', dst_port=19080), **kw}

    def test_default_allow(self):
        f=Flow('in','127.0.0.1','127.0.0.1',50000,19080,'TCP')
        self.assertEqual(self.m.decision(f)['action'],'allow')

    def test_deny_matches(self):
        self.m.add(self.base())
        f=Flow('in','127.0.0.1','127.0.0.1',50000,19080,'TCP')
        self.assertEqual(self.m.decision(f)['action'],'deny')
        self.assertEqual(self.m.decision(f)['rule_id'],1)

    def test_outbound_separate(self):
        self.m.add(self.base())
        self.assertEqual(self.m.decision(Flow('out','127.0.0.1','127.0.0.1',50000,19080,'TCP'))['action'],'allow')

    def test_protocol_separate(self):
        self.m.add(self.base())
        self.assertEqual(self.m.decision(Flow('in','127.0.0.1','127.0.0.1',50000,19080,'UDP'))['action'],'allow')

    def test_ip_cidr(self):
        self.m.add(self.base(src_ip_cidr='10.0.0.0/24'))
        self.assertEqual(self.m.decision(Flow('in','10.0.0.8','1.2.3.4',99,19080,'TCP'))['action'],'deny')
        self.assertEqual(self.m.decision(Flow('in','11.0.0.8','1.2.3.4',99,19080,'TCP'))['action'],'allow')

    def test_port_match(self):
        self.m.add(self.base(src_port=1000))
        self.assertEqual(self.m.decision(Flow('in','127.0.0.1','127.0.0.1',1000,19080,'TCP'))['action'],'deny')
        self.assertEqual(self.m.decision(Flow('in','127.0.0.1','127.0.0.1',1001,19080,'TCP'))['action'],'allow')

    def test_priority(self):
        self.m.add(self.base(priority=90))
        self.m.add({'action':'allow','direction':'in','proto':'TCP','dst_port':19080,'priority':10})
        self.assertEqual(self.m.decision(Flow('in','127.0.0.1','127.0.0.1',3,19080,'TCP'))['action'],'allow')

    def test_tie_deny_first(self):
        self.m.add({'action':'allow','direction':'in','proto':'TCP','dst_port':19080,'priority':10})
        self.m.add(self.base(priority=10))
        self.assertEqual(self.m.decision(Flow('in','127.0.0.1','127.0.0.1',3,19080,'TCP'))['action'],'deny')

    def test_duplicate_rejected(self):
        self.m.add(self.base())
        with self.assertRaises(DuplicateRule):self.m.add(self.base())

    def test_conflict_reported(self):
        self.m.add(self.base())
        created=self.m.add({'action':'allow','proto':'TCP','dst_port':19080,'direction':'in','priority':90})
        self.assertEqual(created['warnings'][0]['type'],'conflict')
        self.assertEqual(self.m.conflicts()[0]['winner'],created['rule']['id'])

    def test_overlap_disabled_not_reported(self):
        self.m.add(self.base(enabled=False))
        created=self.m.add({'action':'allow','proto':'TCP','dst_port':19080,'direction':'in'})
        self.assertEqual(created['warnings'],[])

    def test_patch_disable_then_enable(self):
        rid=self.m.add(self.base())['rule']['id']
        f=Flow('in','127.0.0.1','127.0.0.1',3,19080,'TCP')
        self.m.update(rid,{'enabled':False})
        self.assertEqual(self.m.decision(f)['action'],'allow')
        self.m.update(rid,{'enabled':True})
        self.assertEqual(self.m.decision(f)['action'],'deny')

    def test_delete(self):
        rid=self.m.add(self.base())['rule']['id']
        self.m.delete(rid)
        self.assertEqual(self.m.list_rules(),[])
        with self.assertRaises(KeyError):self.m.delete(rid)

    def test_persistence_reload(self):
        self.m.add(self.base())
        self.assertEqual(len(RuleManager(self.config).list_rules()),1)
        self.m.reload()
        self.assertEqual(len(self.m.list_rules()),1)

    def test_bad_ip(self):
        with self.assertRaises(RuleError):self.m.add(self.base(src_ip_cidr='not-IP'))

    def test_bad_port(self):
        with self.assertRaises(RuleError):self.m.add(self.base(dst_port=-1))

    def test_bad_action(self):
        with self.assertRaises(RuleError):self.m.add({'action':'DROP'})

    def test_bad_protocol(self):
        with self.assertRaises(RuleError):self.m.add({'proto':'ICMP'})

    def test_bad_direction(self):
        with self.assertRaises(RuleError):self.m.add({'direction':'both'})

    def test_unknown_field(self):
        with self.assertRaises(RuleError):self.m.add({'hello':'world'})

    def test_bad_enabled_type(self):
        with self.assertRaises(RuleError):self.m.add(self.base(enabled='false'))

    def test_patch_bad_field(self):
        rid=self.m.add(self.base())['rule']['id']
        with self.assertRaises(RuleError):self.m.update(rid,{'id':99})

    def test_overlaps_for_ipv4_networks(self):
        a=Rule.build({'src_ip_cidr':'10.0.0.0/24'},1)
        b=Rule.build({'src_ip_cidr':'10.0.0.4/32'},2)
        c=Rule.build({'src_ip_cidr':'10.1.0.0/16'},3)
        self.assertTrue(overlaps(a,b));self.assertFalse(overlaps(a,c))

    def test_reload_rejects_service_mutation(self):
        obj=json.loads(self.config.read_text())
        obj['services'].append({'proto':'TCP','listen_ip':'127.0.0.1','listen_port':18080,
                                'target_ip':'127.0.0.1','target_port':19080})
        self.config.write_text(json.dumps(obj))
        with self.assertRaises(RuleError):self.m.reload()

    def test_invalid_persisted_id(self):
        obj=json.loads(self.config.read_text())
        obj['rules']=[{'id':0,'action':'deny'}]
        self.config.write_text(json.dumps(obj))
        with self.assertRaises(RuleError):RuleManager(self.config)


if __name__ == '__main__':unittest.main()
