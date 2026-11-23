"""SQL injection against the Database service, with a real loopback execution.

Behavioural signal: a Database access with an abnormal response time and payload
size, from an employee who does not normally query the database. Loud by design.

Where the lab web target is running, the script also sends a genuine injection to
its disposable in-memory SQLite catalog (http://127.0.0.1:<web_port>/search) and
reports exactly which rows came back. With the current payload the injected OR clause
is executed but evaluates false (the lab appends %' after the input), so only 'pencil'
is returned — the same as a normal search. That request is logged against 127.0.0.1
and is not attributed to the employee. The employee-attributed signal is the Database
telemetry below.

    python -m monitor.attacks.sql_injection --employee EMP0234
"""
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import base

SERVICE = 'Database'
INJECTION = "pencil' OR '1'='1"


def _web_port():
    try:
        config = json.loads(Path(base.DEFAULT_CONFIG).read_text())
        return int(config.get('lab', {}).get('web_port', 8088))
    except (OSError, ValueError, TypeError):
        return 8088


def action(args):
    port = _web_port()
    url = f'http://127.0.0.1:{port}/search?q=' + urllib.parse.quote(INJECTION)
    # Declare the impersonated device IP so the lab can honour an active-defense block.
    try:
        source_ip = base.device_ip(base.load_directory(), getattr(args, "employee", None))
    except SystemExit:
        source_ip = None
    request = urllib.request.Request(url, headers={'X-Lab-Source': source_ip} if source_ip else {})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return f'BLOCKED by active defense — the lab refused the request from {source_ip} (403)'
        return f'lab returned HTTP {exc.code}; telemetry still emitted'
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f'lab web target not reachable on 127.0.0.1:{port} ({exc}); telemetry still emitted'
    return describe(payload.get('results', []))


def describe(results):
    """State exactly what the lab returned and whether the injection widened the query."""
    from ..lab import CATALOG_ROWS
    names = ', '.join(repr(r) for r in results) or 'none'
    head = (f"injected {INJECTION!r} into the lab catalog; it returned {len(results)} of "
            f"{len(CATALOG_ROWS)} catalog rows: {names}.")
    if set(results) >= set(CATALOG_ROWS):
        return head + ' The injected OR clause widened the query to every row in the catalog.'
    return (head + " The payload broke out of the string literal and the OR clause ran, but the lab "
            "appends %' after the input, so the clause became '1'='1%' (false): the result is the "
            "same as a normal search for 'pencil' and the catalog was not dumped.")


def build(directory, source_ip, person, args):
    ts = base.within_hours_ts(directory, person)
    stamps = base.spaced(ts, args.count, args.interval)
    # Slow, heavy responses typical of an injected query dumping a table.
    return [base.record(source_ip, directory, SERVICE, ts=t, kind='db_query',
                        bytes_in=256, bytes_out=180000, response_time_ms=4200,
                        message="query with ' OR '1'='1 payload") for t in stamps]


SCENARIO = base.Scenario(
    key='sql_injection', title='SQL injection', service=SERVICE,
    signal='abnormal response time and payload on an unusual Database access',
    expected='HIGH', tone='loud', build=build, default_count=1, default_interval=90,
    action=action)
base.register(SCENARIO)


def main(argv=None):
    return base.run_scenario(SCENARIO, argv)


if __name__ == '__main__':
    main()
