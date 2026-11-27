"""Filter JSONL by action/proto/direction/IP/time and summarize blocking reasons."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path


def parse_time(s):
    if not s: return None
    dt = datetime.fromisoformat(s.replace('Z','+00:00'))
    if dt.tzinfo is None:raise ValueError('Timestamp requires UTC offset or Z')
    return dt.astimezone(timezone.utc)


def analyze(path, action=None, proto=None, src=None, dst=None, direction=None, since=None, until=None):
    since, until=parse_time(since),parse_time(until)
    records=[]; malformed=0
    net_src=ipaddress.ip_network(src,strict=False) if src else None
    net_dst=ipaddress.ip_network(dst,strict=False) if dst else None
    source=Path(path)
    if source.exists():
        for line in source.read_text('utf-8').splitlines():
            try:
                r=json.loads(line)
                if not isinstance(r,dict):raise ValueError('not dict')
                dt=parse_time(r['timestamp'])
            except (ValueError,KeyError,TypeError):
                malformed+=1;continue
            if action and r.get('action')!=action:continue
            if proto and r.get('protocol')!=proto:continue
            if direction and r.get('direction')!=direction:continue
            if src and (not r.get('src_ip') or ipaddress.ip_address(r['src_ip']) not in net_src):continue
            if dst and (not r.get('dst_ip') or ipaddress.ip_address(r['dst_ip']) not in net_dst):continue
            if since and dt<since:continue
            if until and dt>until:continue
            records.append(r)
    denies=[r for r in records if r.get('action')=='deny']
    return {
      'events_total':len(records), 'malformed_lines':malformed,
      'by_event':dict(Counter(r.get('event','unknown') for r in records)),
      'denied_count':len(denies),
      'denied_by_protocol':dict(Counter(r.get('protocol','unknown') for r in denies)),
      'denied_by_direction':dict(Counter(r.get('direction','unknown') for r in denies)),
      'denied_by_reason':dict(Counter(r.get('reason','unknown') for r in denies)),
      'top_blocked_sources':Counter(r.get('src_ip','unknown') for r in denies).most_common(5),
      'top_blocked_destinations':Counter(f"{r.get('dst_ip','?')}:{r.get('dst_port','?')}" for r in denies).most_common(5),
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument('path',nargs='?',default='logs/events.jsonl')
    p.add_argument('--action',choices=['allow','deny'])
    p.add_argument('--proto',choices=['TCP','UDP'])
    p.add_argument('--direction',choices=['in','out'])
    p.add_argument('--src',help='Source IPv4/CIDR')
    p.add_argument('--dst',help='Destination IPv4/CIDR')
    p.add_argument('--since',help='ISO8601 UTC datetime')
    p.add_argument('--until',help='ISO8601 UTC datetime')
    p.add_argument('--out')
    args=p.parse_args()
    result=analyze(args.path,action=args.action,proto=args.proto,direction=args.direction,
                   src=args.src,dst=args.dst,since=args.since,until=args.until)
    data=json.dumps(result,ensure_ascii=False,indent=2)
    print(data)
    if args.out:
        path=Path(args.out);path.parent.mkdir(exist_ok=True,parents=True);path.write_text(data+'\n','utf-8')


if __name__=='__main__':main()
