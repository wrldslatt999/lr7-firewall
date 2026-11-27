"""Thread-safe JSON-lines event log, no payload data or credentials."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading


class EventLog:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def write(self, event, **fields):
        row = {'timestamp': datetime.now(timezone.utc).isoformat(), 'event': event, **fields}
        data = json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n'
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.write(data)
            except Exception:
                raise
        return row

    def flow(self, event, flow, decision, **extra):
        return self.write(event, direction=flow.direction, src_ip=flow.src_ip,
                          dst_ip=flow.dst_ip, src_port=flow.src_port, dst_port=flow.dst_port,
                          protocol=flow.proto, action=decision['action'],
                          rule_id=decision['rule_id'], reason=decision['reason'], **extra)
