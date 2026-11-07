"""Safe, repeatable telemetry; no attacks or external operations."""
from .core import now


def events(base=None):
    t = base if base is not None else now() - 70
    result = [dict(ts=t, kind='normal', message='Successful routine activity', source='DEMO', ip='192.0.2.1')]
    for i in range(5):
        result.append(dict(ts=t+i, kind='ssh_failed', ip='192.0.2.10', message='Failed password for student', source='DEMO'))
    for i in range(15):
        result.append(dict(ts=t+i, kind='connection', ip='192.0.2.20', port=8000+i, message='Firewall connection attempt', source='DEMO'))
    result.append(dict(ts=t+20, kind='http', ip='192.0.2.30', message="GET /?q=' OR 1=1", source='DEMO'))
    for i in range(50):
        result.append(dict(ts=t+30+i/10, kind='http', ip='192.0.2.40', message='GET /index', source='DEMO'))
    result += [dict(ts=t+40, kind='file', message='Test configuration content changed', source='DEMO'), dict(ts=t+41, kind='privilege', message='sudo: user not in the sudoers', source='DEMO')]
    return result
