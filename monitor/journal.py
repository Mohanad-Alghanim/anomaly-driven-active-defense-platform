"""Persistent, read-only system Journal adapter. Never enables a service."""
import json
import os
import selectors
import subprocess
import tempfile
import time
from .adapters import AUTH_IDS, parse_journal
from .core import now


def read_journal(command, limit, timeout=8):
    """Bound output/time; stop at the oldest `limit` records, never tail-skip."""
    records, buffer = [], b''
    total = 0
    issue = ''
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, env={**os.environ, 'LC_ALL': 'C'}) as process:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    deadline = time.monotonic() + timeout
                    finished = False
                    while not finished and len(records) < limit:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            issue = 'Journal read timed out'
                            break
                        if not selector.select(min(remaining, 0.5)):
                            continue
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > 8 * 1024 * 1024:
                            issue = 'Journal batch exceeded 8 MiB; check large records'
                            break
                        buffer += chunk
                        while b'\n' in buffer and len(records) < limit:
                            raw, buffer = buffer.split(b'\n', 1)
                            if raw:
                                records.append(raw.decode('utf-8', errors='replace'))
                        if len(buffer) > 1024 * 1024:
                            issue = 'Journal record exceeds 1 MiB; source needs review'
                            finished = True
                if process.poll() is None:
                    process.terminate()
                try:
                    code = process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    code = process.wait()
                    issue = issue or 'Journal did not stop within timeout'
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            errors.seek(0)
            diagnostics = errors.read(2048).decode(errors='replace').strip()
    # Stopping after a bounded batch is expected, not a source failure.
    if len(records) >= limit and not issue:
        code = 0
    elif code < 0 and not issue and not diagnostics:
        code = 0
    return records, code, issue or diagnostics


def collect_journal(engine, reader=read_journal):
    settings = engine.c['journal']
    if not settings.get('enabled', True):
        return dict(source='systemd Journal', format='journal', available=False, enabled=False, status='Disabled in configuration', last_poll=now())
    saved = json.loads(engine.state('journal_cursor') or '{}')
    base = ['journalctl', '--no-pager', '--quiet', '--output=json',
            '--output-fields=__CURSOR,__REALTIME_TIMESTAMP,SYSLOG_IDENTIFIER,_COMM,_HOSTNAME,MESSAGE']
    for identifier in AUTH_IDS:
        base += ['--identifier=' + identifier]
    if settings.get('kernel_netfilter', False):
        base += ['--identifier=kernel']
    since = saved.get('ts', now()-settings.get('lookback_seconds', 300)) - 2
    position = ['--after-cursor=' + saved['cursor']] if saved.get('cursor') else ['--since=@' + str(since)]
    recovered = False
    try:
        records, code, diagnostic = reader(base + position, engine.c['batch_lines'])
        if code and saved.get('cursor') and 'cursor' in diagnostic.lower() and any(word in diagnostic.lower() for word in ('seek', 'invalid', 'failed', 'not found')):
            # Vacuum/rotation can remove the cursor. Replay a small overlap; cursor IDs deduplicate.
            records, code, diagnostic = reader(base + ['--since=@' + str(since)], engine.c['batch_lines'])
            recovered = True
        rejected = processed = 0
        for line in records:
            record = None
            try:
                record = json.loads(line)
                event = parse_journal(record)
                if event is not None:
                    engine.process(event)
                    processed += 1
            except (ValueError, TypeError, KeyError):
                rejected += 1
            # Event commit precedes cursor commit: crashes replay safely, never skip an uncommitted event.
            if isinstance(record, dict) and isinstance(record.get('__CURSOR'), str):
                try:
                    stamp = int(record['__REALTIME_TIMESTAMP'])/1_000_000
                except (ValueError, TypeError, KeyError):
                    stamp = saved.get('ts', since)
                engine.set_state('journal_cursor', json.dumps(dict(cursor=record['__CURSOR'], ts=stamp)))
        status = 'Available (read-only authentication query)'
        if recovered:
            status += '; expired cursor recovered with timestamp overlap'
        if not records:
            status += '; no matching records (SSH may be inactive)'
        if diagnostic:
            status += '; ' + diagnostic[:300]
        return dict(source='systemd Journal', format='journal', available=code == 0 and not diagnostic,
                    status=status if not code else 'Journal query failed: ' + diagnostic[:300],
                    rejected=rejected, processed=processed, recovered=recovered, last_poll=now())
    except OSError as exc:
        return dict(source='systemd Journal', format='journal', available=False, status=str(exc), last_poll=now())
