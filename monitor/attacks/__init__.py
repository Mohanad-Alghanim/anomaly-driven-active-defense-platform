"""Phase 3 insider-attack scenarios (loopback lab only).

Six red-team scripts, one per dataset attack category. Each impersonates a real
employee device (its source IP from Device_Profiles) accessing one of the eight
real services, writes behavioural telemetry to the lab inbox (runtime/lab/telemetry.jsonl)
in the exact schema the live collector reads, and — where a loopback target exists —
performs a real action against it (the lab SQLi catalog, the watched file).

The scripts carry no attack signatures and never touch real infrastructure. They
only produce behaviour; the brain alone decides whether that behaviour is anomalous
and at what level. Expected levels printed by each script are the scenario's design
intent, not a claim about a specific employee: a value far from one employee's own
baseline may be ordinary for another.
"""
from .base import SCENARIOS, Scenario, run_scenario  # noqa: F401
