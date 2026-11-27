import tempfile
from pathlib import Path
import unittest

from eventlog import EventLog
from analyze_logs import analyze
from rule_engine import Flow


class LogTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'events.jsonl'
        self.logger=EventLog(self.path)

    def test_filter_by_action_proto_direction(self):
        self.logger.flow('connection.denied',Flow('in','10.0.0.1','127.0.0.1',123,80,'TCP'),
                         {'action':'deny','rule_id':1,'reason':'matched_rule_1'})
        self.logger.flow('datagram.denied',Flow('out','10.0.0.2','127.0.0.1',123,53,'UDP'),
                         {'action':'deny','rule_id':2,'reason':'matched_rule_2'})
        self.assertEqual(analyze(self.path,action='deny',proto='TCP')['denied_count'],1)
        self.assertEqual(analyze(self.path,direction='out')['denied_count'],1)
        self.assertEqual(analyze(self.path,src='10.0.0.0/24')['denied_count'],2)
        self.assertEqual(analyze(self.path,dst='8.8.8.8/32')['denied_count'],0)

    def test_malformed(self):
        self.path.write_text('not json\n')
        self.assertEqual(analyze(self.path)['malformed_lines'],1)

    def test_missing_log(self):
        self.assertEqual(analyze(self.path)['events_total'],0)

    def test_timestamp_filter(self):
        self.logger.write('service.started')
        self.assertEqual(analyze(self.path,since='2099-01-01T00:00:00Z')['events_total'],0)
        self.assertEqual(analyze(self.path,until='2000-01-01T00:00:00Z')['events_total'],0)


if __name__=='__main__':unittest.main()
