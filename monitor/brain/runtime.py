"""Load the frozen brain artifact for live scoring (cached per file version)."""
import hashlib
from functools import lru_cache
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = ROOT / 'models' / 'ai_engine' / 'insider_brain.joblib'


def load_brain(path=None):
    path = Path(path or DEFAULT_MODEL)
    if not path.is_file():
        raise FileNotFoundError(f'Insider-threat model not found: {path}. Train it with: python -m monitor.brain.train')
    stat = path.stat()
    return _load(str(path.resolve()), stat.st_mtime_ns, stat.st_size)


@lru_cache(maxsize=4)
def _load(path, _mtime, _size):
    brain = joblib.load(path)
    for attribute in ('pipeline_', 'boundaries_', 'employee_boundaries_', 'calibration_scores_'):
        if not hasattr(brain, attribute):
            raise ValueError(f'Model artifact is incomplete (missing {attribute}); retrain it')
    # One event batch at a time: avoid thread start-up cost per collector poll.
    brain.pipeline_.named_steps['forest'].set_params(n_jobs=1)
    brain.version_ = 'insider_brain:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()[:12]
    return brain
