"""Out-of-role data snooping: quietly reading files the employee has no business in.

Signal: access to the File Server when it is not part of this employee's baseline,
at an ordinary, small volume. Stealthy by design — it should rely on the destination
being out of role, not on any large transfer, so it may only reach MEDIUM. That is
the honest limit the floor measures, and the point of showing it.

    python -m monitor.attacks.data_snooping --employee EMP0234 [--service "File Server"]
"""
from . import base

DEFAULT_SERVICE = 'File Server'


def cli_extra(parser):
    parser.add_argument('--service', default=DEFAULT_SERVICE,
                        help='Out-of-role service to browse (default: File Server)')


def _before_work_hour(person):
    try:
        return (int(str(person.get('work_start', '08:00')).split(':')[0]) - 1) % 24
    except ValueError:
        return 7


def build(directory, source_ip, person, args):
    service = getattr(args, 'service', DEFAULT_SERVICE)
    # Quiet out-of-role browsing just before the workday starts. Ordinary small reads —
    # nothing a byte threshold catches; the destination being out of role is the signal.
    ts = base.off_hours_ts(directory, person, _before_work_hour(person))
    stamps = base.spaced(ts, args.count, args.interval)
    return [base.record(source_ip, directory, service, ts=t, kind='file_read',
                        bytes_in=1800, bytes_out=300, response_time_ms=60,
                        message='browsing shared folders') for t in stamps]


SCENARIO = base.Scenario(
    key='data_snooping', title='Out-of-role data snooping', service=DEFAULT_SERVICE,
    signal='a destination outside the employee baseline, at small volume',
    expected='MEDIUM', tone='stealthy', build=build, default_count=1, default_interval=300,
    cli_extra=cli_extra)
base.register(SCENARIO)


def main(argv=None):
    return base.run_scenario(SCENARIO, argv)


if __name__ == '__main__':
    main()
