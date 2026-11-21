"""Privilege escalation: reaching for a privileged service the employee never uses.

Signal: access to a service outside the employee's baseline (service rarity), with
ordinary volume. Lands high when the target service is genuinely novel for this
employee; a routine user of that service will score lower — the brain decides.

    python -m monitor.attacks.privilege_escalation --employee EMP0234 [--service "SSH Gateway"]
"""
from . import base

DEFAULT_SERVICE = 'Active Directory'


def cli_extra(parser):
    parser.add_argument('--service', default=DEFAULT_SERVICE,
                        help='Privileged service to reach for (default: Active Directory; e.g. "SSH Gateway")')
    parser.add_argument('--hour', type=int, default=2, help='Local hour of the after-hours escalation (default: 2)')


def build(directory, source_ip, person, args):
    service = getattr(args, 'service', DEFAULT_SERVICE)
    # Reaching an administrative service the employee never touches, after hours.
    # Ordinary volume: service rarity is the signal, the unusual time carries it.
    ts = base.off_hours_ts(directory, person, getattr(args, 'hour', 2))
    stamps = base.spaced(ts, args.count, args.interval)
    return [base.record(source_ip, directory, service, ts=t, kind='directory_bind',
                        bytes_in=2048, bytes_out=900, response_time_ms=140,
                        message='privileged directory operation') for t in stamps]


SCENARIO = base.Scenario(
    key='privilege_escalation', title='Privilege escalation', service=DEFAULT_SERVICE,
    signal='access to a service outside the employee baseline (service rarity)',
    expected='HIGH', tone='loud', build=build, default_count=1, default_interval=120,
    cli_extra=cli_extra)
base.register(SCENARIO)


def main(argv=None):
    return base.run_scenario(SCENARIO, argv)


if __name__ == '__main__':
    main()
