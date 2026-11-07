"""A real, denied OS capability request from an unprivileged process; no sudo changes."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
from .core import now
from .lab_setup import paths


def probe(root, normal=False):
    uid = os.getuid()
    if uid == 0 or os.geteuid() != uid:
        raise RuntimeError('The permission-boundary probe requires an ordinary non-root process')
    # Never attempt this syscall when CAP_SETUID could actually grant privilege.
    status = Path('/proc/self/status').read_text()
    for name in ('CapEff:', 'CapPrm:'):
        value = next(line.split()[1] for line in status.splitlines() if line.startswith(name))
        if int(value,16) & (1 << 7):
            raise RuntimeError('CAP_SETUID present; refusing the probe')
    if normal:
        message = f'LAB_PRIVILEGE_NORMAL operation=getuid uid={uid} result={os.getuid()}'
        denied = False
    else:
        # CAP_SETUID is absent from both current and permitted sets (checked above).
        # Linux rejects adding a new permitted capability with EPERM. This avoids
        # depending on UID 0 being mapped inside a user namespace.
        class Header(ctypes.Structure):
            _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
        class Data(ctypes.Structure):
            _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
        libc=ctypes.CDLL(None,use_errno=True)
        header=Header(0x20080522,0)
        requested=(Data*2)()
        requested[0].effective=requested[0].permitted=1 << 7
        capset=libc.capset
        capset.argtypes=[ctypes.POINTER(Header),ctypes.POINTER(Data)]
        capset.restype=ctypes.c_int
        result=capset(ctypes.byref(header),requested)
        error=ctypes.get_errno()
        if result==0:
            empty=(Data*2)()
            capset(ctypes.byref(header),empty)
            raise RuntimeError('Unexpected capability grant; probe failed closed')
        if error!=errno.EPERM:
            raise OSError(error,'Capability probe unsupported in this environment')
        message=f'LAB_PRIVILEGE_DENIED operation=capset capability=CAP_SETUID errno={error} uid={uid}'
        denied=True
    event = dict(ts=now(),kind='privilege',message=message,dst_host='local OS permission boundary')
    path = paths(root)['privilege']
    from .lab import append
    append(path,json.dumps(event)+'\n')
    return dict(operation='getuid' if normal else 'capset(CAP_SETUID)',denied=denied,uid=uid)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--normal',action='store_true')
    args=parser.parse_args()
    print(json.dumps(probe(args.root,args.normal)))


if __name__ == '__main__':
    main()
