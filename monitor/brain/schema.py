"""Model-matrix schema and leakage guard.

Only the columns listed here may ever reach the fitted pipeline. Identifiers,
IP addresses, labels, severities, scenario names and provenance are rejected
before fitting or scoring.
"""
import re

# Exactly the 13 columns of the dataset's Model_Features / Normal_Behavior_Learning sheets.
BASE_NUMERIC = (
    'hour_sin', 'hour_cos', 'day_of_week_sin', 'day_of_week_cos',
    'is_weekend_observed', 'within_assumed_work_hours',
    'bytes_in_log1p', 'bytes_out_log1p', 'response_time_ms_log1p',
    'source_events_previous_hour',
)
# destination_port is a service code, not a quantity, so it is one-hot encoded.
BASE_CATEGORICAL = ('protocol', 'destination_service', 'destination_port')
BASE_FEATURES = BASE_NUMERIC + BASE_CATEGORICAL

# Deviation of an event from its own employee's normal baseline.
PERSONAL_FEATURES = (
    'emp_bytes_in_z',        # (bytes_in - employee mean) / employee std, log space
    'emp_bytes_out_z',       # same for bytes_out
    'emp_response_time_z',   # same for response time (missing when not observed)
    'emp_hour_deviation',    # circular distance from the employee's usual hour / usual spread
    'emp_service_rarity',    # -log P(service | employee), Laplace-smoothed
    'emp_activity_z',        # source_events_previous_hour vs. the employee's own usual rate
)

# Context columns used for attribution and grouping only, never as model inputs.
CONTEXT_COLUMNS = ('feature_row_id', 'ts', 'employee_id', 'device_id', 'source_ip')

_FORBIDDEN = re.compile(
    r'(^|_)(id|ip|label|labels|binary|category|severity|scenario|session|attack|'
    r'ground|truth|origin|provenance|evidence|name|hostname|department|status|action|'
    r'event_type|synthetic|target|index)($|_)',
    re.I,
)


def assert_no_leakage(columns):
    """Raise if any column outside the approved feature schema would enter the model."""
    allowed = set(BASE_FEATURES) | set(PERSONAL_FEATURES)
    columns = list(columns)
    unexpected = [c for c in columns if c not in allowed]
    suspicious = [c for c in columns if _FORBIDDEN.search(str(c))]
    if unexpected or suspicious:
        raise ValueError(f'Leakage guard: columns not allowed in the model matrix: {sorted(set(unexpected) | set(suspicious))}')
    return columns
