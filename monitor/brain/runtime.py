"""Load the frozen brain artifact for live scoring (cached per file version)."""
import hashlib
import pickle
import pickletools
from functools import lru_cache
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = ROOT / 'models' / 'ai_engine' / 'insider_brain.joblib'
RETRAIN = 'Retrain it with: .venv/bin/python -m monitor.brain.train'


def pandas_references(obj):
    """Pandas modules referenced by the pickle of `obj` (empty = loads on any pandas version).

    The fitted state must be numpy arrays and plain Python containers: a pickled pandas
    object only unpickles on a compatible pandas release (pandas 3 StringDtype cannot be
    read by pandas 2, for example).
    """
    found = set()
    for opcode, arg, _ in pickletools.genops(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)):
        if isinstance(arg, str) and (arg == 'pandas' or arg.startswith('pandas.')):
            found.add(arg.split(' ')[0])
    return sorted(found)


def load_brain(path=None):
    path = Path(path or DEFAULT_MODEL)
    if not path.is_file():
        raise FileNotFoundError(f'Insider-threat model not found: {path}. {RETRAIN}')
    stat = path.stat()
    return _load(str(path.resolve()), stat.st_mtime_ns, stat.st_size)


@lru_cache(maxsize=4)
def _load(path, _mtime, _size):
    try:
        brain = joblib.load(path)
    except (ImportError, AttributeError, NotImplementedError, TypeError, ValueError, pickle.UnpicklingError) as exc:
        raise RuntimeError(f'Cannot load {path} with the installed library versions '
                           f'({type(exc).__name__}: {exc}). Install requirements.txt or {RETRAIN}') from exc
    for attribute in ('pipeline_', 'boundaries_', 'employee_boundaries_', 'calibration_scores_'):
        if not hasattr(brain, attribute):
            raise ValueError(f'Model artifact is incomplete (missing {attribute}). {RETRAIN}')
    # One event batch at a time: avoid thread start-up cost per collector poll.
    brain.pipeline_.named_steps['forest'].set_params(n_jobs=1)
    brain.version_ = 'insider_brain:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()[:12]
    return brain
