"""Per-user deployment; preparation never starts or enables a network listener."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

UNITS = ('six-soc-collector.service', 'six-soc-dashboard.service')
ROOT = Path(__file__).resolve().parents[1]


def quote(value, systemd=False):
    value = str(value)
    if any(ord(char) < 32 for char in value):
        raise ValueError('Control characters are not allowed in deployment paths')
    value = value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    if not systemd:
        value = value.replace('`', '\\`').replace('$', '\\$')
    return value


def write_managed(path, text, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() != text:
        backup = path.with_name(path.name + '.backup-' + str(time.time_ns()))
        shutil.copy2(path, backup)
    path.write_text(text)
    path.chmod(0o700 if executable else 0o600)


def prepare(root=ROOT, home=None):
    if os.geteuid() == 0:
        raise RuntimeError('Run setup as the normal Kali desktop user, without sudo')
    root = Path(root).resolve()
    home = Path(home) if home else Path.home()
    python = root/'.venv/bin/python'
    if not python.exists():
        raise RuntimeError('Install project dependencies in .venv first; see README')
    config = root/'config.local.json'
    if not config.exists():
        write_managed(config, (root/'config.example.json').read_text())
    # Existing local configuration content is retained verbatim.
    if config.is_symlink():
        raise RuntimeError('Refusing a symlinked local configuration')
    config.chmod(0o600)
    data = root/'data'
    data.mkdir(exist_ok=True, mode=0o700)
    if data.is_symlink():
        raise RuntimeError('Refusing to change a symlinked data directory')
    data.chmod(0o700)
    for path in data.iterdir():
        if path.is_file() and not path.is_symlink() and (path.name.startswith(('live.db', 'demo.db')) or path.name == 'collector.lock'):
            path.chmod(0o600)
    units = home/'.config/systemd/user'
    values = dict(ROOT=root, PYTHON=python, CONFIG=config, DATA=data)
    for name in UNITS:
        text = (root/'deploy'/f'{name}.in').read_text()
        for key, value in values.items():
            text = text.replace('@'+key+'@', quote(value, systemd=True))
        write_managed(units/name, text)
    entries = {
        'six-soc.desktop': ('Six-Attack SOC', 'firefox --new-tab http://127.0.0.1:8501', 'security-high'),
        'six-soc-activate.desktop': ('Activate SOC Monitoring', f'"{quote(python)}" -m monitor.install --activate-gui', 'system-run'),
        'six-soc-restart.desktop': ('Restart SOC Monitoring', f'"{quote(python)}" -m monitor.install --restart-gui', 'view-refresh'),
        'six-soc-status.desktop': ('SOC Monitoring Status', f'"{quote(python)}" -m monitor.install --status-gui', 'utilities-system-monitor'),
    }
    for name, (title, command, icon) in entries.items():
        text = f'[Desktop Entry]\nType=Application\nName={title}\nComment=Local six-category SOC monitoring\nExec={command}\nPath={root}\nIcon={icon}\nTerminal=false\nCategories=System;Monitor;\n'
        write_managed(home/'.local/share/applications'/name, text, executable=True)
        if (home/'Desktop').is_dir():
            write_managed(home/'Desktop'/name, text, executable=True)
    return units


def systemctl(*args):
    result = subprocess.run(['systemctl', '--user', *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'systemctl failed')
    return result.stdout.strip()


def activate():
    prepare()
    systemctl('daemon-reload')
    systemctl('enable', '--now', *UNITS)
    return systemctl('is-active', *UNITS)


def dialog(text, question=False):
    # Ask explicitly before enabling/restarting the localhost listener.
    if shutil.which('zenity'):
        result = subprocess.run(['zenity', '--question' if question else '--info', '--title=Six-Attack SOC', '--width=520', '--text='+text], check=False)
        return result.returncode == 0
    try:
        import tkinter as tk
        from tkinter import messagebox
        window = tk.Tk()
        window.withdraw()
        try:
            return messagebox.askyesno('Six-Attack SOC', text, parent=window) if question else messagebox.showinfo('Six-Attack SOC', text, parent=window) == 'ok'
        finally:
            window.destroy()
    except (ImportError, RuntimeError) as exc:
        raise RuntimeError('Graphical setup needs a desktop session and tkinter or zenity; see README for terminal setup') from exc
    except Exception as exc:
        # Tk raises TclError if no desktop display is available.
        raise RuntimeError('Cannot open graphical dialog in this session: '+str(exc)) from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true', help='Install user units/launchers without enabling or starting services')
    group.add_argument('--activate', action='store_true', help='Explicitly enable and start both user services (localhost dashboard)')
    group.add_argument('--activate-gui', action='store_true')
    group.add_argument('--status-gui', action='store_true')
    group.add_argument('--restart-gui', action='store_true')
    args = parser.parse_args()
    try:
        if args.prepare:
            print('Prepared user services and graphical launchers in', prepare())
        elif args.status_gui:
            status = subprocess.run(['systemctl', '--user', 'is-active', *UNITS], capture_output=True, text=True, timeout=10)
            dialog('Collector / dashboard service state:\n'+status.stdout.strip()+'\n'+status.stderr.strip()+'\n\nDashboard: http://127.0.0.1:8501')
        elif args.restart_gui:
            if dialog('Restart the background collector and localhost dashboard at 127.0.0.1:8501? Saved events and collection progress are preserved.', question=True):
                systemctl('restart', *UNITS)
                dialog('Services restarted. Open Six-Attack SOC to check source health.')
        elif args.activate_gui:
            if dialog('Enable automatic monitoring after login and start the background collector and dashboard?\n\nThe dashboard listens only at 127.0.0.1:8501. Authentication Journal access is read-only. SSH, firewall rules and packet capture are unchanged.', question=True):
                dialog('Services activated:\n'+activate()+'\n\nOpen Six-Attack SOC from the applications menu.')
        else:
            print(activate())
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        if args.activate_gui or args.status_gui or args.restart_gui:
            try:
                dialog('Setup/status failed:\n'+str(exc))
            except RuntimeError:
                print(str(exc), file=sys.stderr)
        else:
            print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
