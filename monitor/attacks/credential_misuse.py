"""Credential misuse: a stolen login used at an hour the real employee never works.

Signal: authentication-style activity against Active Directory at the hour opposite
this employee's usual time of day (their baseline mean hour + 12 h), on a workday, at
ordinary volume. Stealthy by design — timing is the only tell, so MEDIUM is the
honest expectation. The hour comes from the employee's baseline, not from the clock,
so the scenario behaves the same on any day it is run.

    python -m monitor.attacks.credential_misuse --employee EMP0234 [--hour 3]
"""
from . import base

SERVICE = 'Active Directory'


def cli_extra(parser):
    parser.add_argument('--hour', type=int, default=None,
                        help='Local hour of the login (default: opposite the employee\'s usual hour)')


def build(directory, source_ip, person, args):
    hour = getattr(args, 'hour', None)
    ts = base.off_hours_ts(directory, person, base.opposite_habit_hour(person) if hour is None else hour)
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
