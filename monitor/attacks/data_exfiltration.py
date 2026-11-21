"""Data exfiltration: a large outbound transfer from the File Server.

Signal: bytes_out far above the employee's own normal volume. Loud by design.

    python -m monitor.attacks.data_exfiltration --employee EMP0234
"""
from . import base

SERVICE = 'File Server'
MEGABYTE = 1024 * 1024


def cli_extra(parser):
    parser.add_argument('--megabytes', type=int, default=40, help='Outbound volume per transfer (default: 40)')
    parser.add_argument('--hour', type=int, default=2, help='Local hour of the after-hours pull (default: 2)')


def build(directory, source_ip, person, args):
    # Bulk theft after hours: a large outbound transfer stacks volume with an unusual
    # time of day, which is what carries a single event confidently to HIGH. bytes_out
    # remains the dominant deviation.
    ts = base.off_hours_ts(directory, person, getattr(args, 'hour', 2))
    stamps = base.spaced(ts, args.count, args.interval)
    volume = max(1, int(getattr(args, 'megabytes', 40))) * MEGABYTE
    return [base.record(source_ip, directory, SERVICE, ts=t, kind='file_download',
                        bytes_in=4096, bytes_out=volume, response_time_ms=180,
                        message='bulk file retrieval') for t in stamps]


SCENARIO = base.Scenario(
    key='data_exfiltration', title='Data exfiltration', service=SERVICE,
    signal='bytes_out far above the employee baseline', expected='HIGH', tone='loud',
    build=build, default_count=1, default_interval=120, cli_extra=cli_extra)
base.register(SCENARIO)


def main(argv=None):
    return base.run_scenario(SCENARIO, argv)


if __name__ == '__main__':
    main()
