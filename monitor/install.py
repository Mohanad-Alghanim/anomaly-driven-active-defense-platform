"""Per-user deployment; preparation never starts or enables a network listener."""
import argparse
import json
import configparser
import shlex
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

LAB_UNIT = 'active-defense-lab.service'
UNITS = ('active-defense-collector.service', 'active-defense-dashboard.service')
ROOT = Path(__file__).resolve().parents[1]


def quote(value, systemd=False):
    value = str(value)
    if any(ord(char) < 32 for char in value):
        raise ValueError('Control characters are not allowed in deployment paths')
    value = value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    if not systemd:
        value = value.replace('`', '\\`').replace('$', '\\$')
    return value


def working_directory(value):
    # WorkingDirectory is a single path directive, not an ExecStart argument.
    # Quotes become literal path characters on the affected Kali systemd version.
    value = str(value)
    if any(ord(char)<32 for char in value):
        raise ValueError('Invalid working directory')
    return value.replace('\\', r'\x5c').replace('"', r'\x22').replace('%','%%')


def render_unit(root, name, config_path=None, data=None):
    root = Path(root).resolve()
    values = dict(ROOT=root, PYTHON=root/'.venv/bin/python', CONFIG=config_path or root/'config.local.json', DATA=data or root/'data')
    text = (root/'deploy'/f'{name}.in').read_text()
    text = text.replace('@WORKDIR@', working_directory(root))
    for key,value in values.items():
        text = text.replace('@'+key+'@',quote(value,systemd=True))
    validate_unit(text)
    return text


def validate_unit(text):
    parser=configparser.ConfigParser(interpolation=None,strict=False)
    parser.read_string(text)
    if not all(section in parser for section in ('Unit','Service','Install')):
        raise ValueError('Unit sections missing')
    directory=parser['Service'].get('WorkingDirectory','')
    if not directory.startswith('/') or directory.startswith(('"',"'")) or directory.endswith(('"',"'")):
        raise ValueError('WorkingDirectory must be an absolute unquoted path')
    if '@WORKDIR@' in text or '@ROOT@' in text:
        raise ValueError('Unexpanded unit template')
    command=shlex.split(parser['Service'].get('ExecStart',''))
    if not command or not command[0].startswith('/'):
        raise ValueError('ExecStart requires an absolute executable')
    if parser['Service'].get('Restart')!='on-failure' or parser['Install'].get('WantedBy')!='default.target':
        raise ValueError('Required lifecycle settings missing')
    return True


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
    for name in UNITS:
        write_managed(units/name, render_unit(root,name,config,data))
    entries = {
        'active-defense.desktop': ('Development of an Anomaly-Driven Active Defense Platform Against Unauthorized Access and Credential Attacks', 'firefox --new-tab http://127.0.0.1:8501', 'security-high'),
    }
    for name, (title, command, icon) in entries.items():
        text = f'[Desktop Entry]\nType=Application\nName={title}\nComment=Local active defense monitoring\nExec={command}\nPath={root}\nIcon={icon}\nTerminal=false\nCategories=System;Monitor;\n'
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
        result = subprocess.run(['zenity', '--question' if question else '--info', '--title=Anomaly-Driven Active Defense Platform', '--width=520', '--text='+text], check=False)
        return result.returncode == 0
    try:
        import tkinter as tk
        from tkinter import messagebox
        window = tk.Tk()
        window.withdraw()
        try:
            return messagebox.askyesno('Anomaly-Driven Active Defense Platform', text, parent=window) if question else messagebox.showinfo('Anomaly-Driven Active Defense Platform', text, parent=window) == 'ok'
        finally:
            window.destroy()
    except (ImportError, RuntimeError) as exc:
        raise RuntimeError('Graphical setup needs a desktop session and tkinter or zenity; see README for terminal setup') from exc
    except Exception as exc:
        # Tk raises TclError if no desktop display is available.
        raise RuntimeError('Cannot open graphical dialog in this session: '+str(exc)) from exc


def prepare_lab(root=ROOT,home=None):
    from .lab_setup import provision
    root=Path(root).resolve()
    home=Path(home) if home else Path.home()
    provision(root)
    # Preserve the repaired, running dashboard/collector units. Add only the new lab unit.
    units=home/'.config/systemd/user'
    write_managed(units/LAB_UNIT,render_unit(root,LAB_UNIT))
    entries={
        'active-defense-lab-start.desktop':('Active Defense Platform — Start Monitoring','--lab-start-gui','system-run'),
        'active-defense-lab-stop.desktop':('Active Defense Platform — Stop Monitoring','--lab-stop-gui','process-stop'),
        'active-defense-lab-restart.desktop':('Active Defense Platform — Restart Monitoring','--lab-restart-gui','view-refresh'),
        'active-defense-lab-status.desktop':('Active Defense Platform — Component Health','--lab-status-gui','utilities-system-monitor'),
    }
    for name,(title,flag,icon) in entries.items():
        command=f'"{quote(root/".venv/bin/python")}" -m monitor.install {flag}'
        text=f'[Desktop Entry]\nType=Application\nName={title}\nExec={command}\nPath={root}\nIcon={icon}\nTerminal=false\nCategories=System;Monitor;\n'
        write_managed(home/'.local/share/applications'/name,text,executable=True)
        if (home/'Desktop').is_dir():
            write_managed(home/'Desktop'/name,text,executable=True)
    return units/LAB_UNIT


def lab_control(args):
    from .lab_readiness import read_target_health
    all_units=(LAB_UNIT,*UNITS)
    if args.lab_status_gui:
        result=subprocess.run(['systemctl','--user','is-active',*all_units],capture_output=True,text=True,timeout=10)
        health=read_target_health(ROOT/'runtime/lab')
        dialog('Lab / collector / dashboard:\n'+result.stdout.strip()+'\n'+result.stderr.strip()+'\n\nTarget health: '+health.get('status','STOPPED')+'\nDashboard: http://127.0.0.1:8501')
    elif args.lab_stop_gui:
        if dialog("Stop this project's lab targets, collector and dashboard? History is preserved; enabled services resume at next login.",question=True):
            systemctl('stop',UNITS[1],UNITS[0],LAB_UNIT)
            dialog('Active Defense Platform monitoring stopped.')
    elif args.lab_start_gui or args.lab_restart_gui:
        if dialog('Start/restart the Active Defense Platform monitoring and enable login startup?\n\nLoopback only: web 8088, isolated SSH 2222, TCP targets 9100–9119, dashboard 8501. No host firewall, SSH or system permissions are changed. No attack tests run automatically.',question=True):
            prepare_lab()
            systemctl('daemon-reload')
            systemctl('reset-failed',*all_units)
            systemctl('enable',*all_units)
            systemctl('restart',*all_units)
            dialog('Active Defense Platform monitoring requested. Open Active Defense Platform — Component Health, then Anomaly-Driven Active Defense Platform.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare-lab', action='store_true', help='Provision lab sources, isolated targets and graphical controls without starting services')
    group.add_argument('--lab-start-gui', action='store_true')
    group.add_argument('--lab-stop-gui', action='store_true')
    group.add_argument('--lab-restart-gui', action='store_true')
    group.add_argument('--lab-status-gui', action='store_true')
    group.add_argument('--prepare', action='store_true', help='Install user units/launchers without enabling or starting services')
    group.add_argument('--activate', action='store_true', help='Explicitly enable and start both user services (localhost dashboard)')
    group.add_argument('--activate-gui', action='store_true')
    group.add_argument('--status-gui', action='store_true')
    group.add_argument('--restart-gui', action='store_true')
    args = parser.parse_args()
    try:
        if args.prepare_lab:
            print('Lab prepared; no services enabled:',prepare_lab())
        elif any((args.lab_start_gui,args.lab_stop_gui,args.lab_restart_gui,args.lab_status_gui)):
            lab_control(args)
        elif args.prepare:
            print('Prepared user services and graphical launchers in', prepare())
        elif args.status_gui:
            status = subprocess.run(['systemctl', '--user', 'is-active', *UNITS], capture_output=True, text=True, timeout=10)
            dialog('Collector / dashboard service state:\n'+status.stdout.strip()+'\n'+status.stderr.strip()+'\n\nDashboard: http://127.0.0.1:8501')
        elif args.restart_gui:
            if dialog('Restart the background collector and localhost dashboard at 127.0.0.1:8501? Saved events and collection progress are preserved.', question=True):
                systemctl('restart', *UNITS)
                dialog('Services restarted. Open Anomaly-Driven Active Defense Platform to check source health.')
        elif args.activate_gui:
            if dialog('Enable automatic monitoring after login and start the background collector and dashboard?\n\nThe dashboard listens only at 127.0.0.1:8501. Authentication Journal access is read-only. SSH, firewall rules and packet capture are unchanged.', question=True):
                dialog('Services activated:\n'+activate()+'\n\nOpen Anomaly-Driven Active Defense Platform from the applications menu.')
        else:
            print(activate())
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        if args.activate_gui or args.status_gui or args.restart_gui or any((args.lab_start_gui,args.lab_stop_gui,args.lab_restart_gui,args.lab_status_gui)):
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
