"""Credential misuse: a stolen login used at an hour the real employee never works.

Signal: authentication-style activity against Active Directory at an off-hour, far
from this employee's usual time of day (hour deviation, outside work hours), at
ordinary volume. Stealthy by design — timing is the only tell, so MEDIUM is the
honest expectation.

    python -m monitor.attacks.credential_misuse --employee EMP0234 [--hour 3]
"""
from . import base

SERVICE = 'Active Directory'


def cli_extra(parser):
    parser.add_argument('--hour', type=int, default=3, help='Local hour of the off-hours login (default: 3)')


def build(directory, source_ip, person, args):
    ts = base.off_hours_ts(directory, person, getattr(args, 'hour', 3))
    stamps = base.spaced(ts, args.count, args.interval)
    return [base.record(source_ip, directory, SERVICE, ts=t, kind='auth_success',
                        bytes_in=900, bytes_out=400, response_time_ms=55,
                        message='interactive logon') for t in stamps]


SCENARIO = base.Scenario(
    key='credential_misuse', title='Credential misuse', service=SERVICE,
    signal='activity at an hour outside the employee usual time of day (hour deviation)',
    expected='MEDIUM', tone='stealthy', build=build, default_count=1, default_interval=120,
    cli_extra=cli_extra)
base.register(SCENARIO)


def main(argv=None):
    return base.run_scenario(SCENARIO, argv)


if __name__ == '__main__':
    main()
