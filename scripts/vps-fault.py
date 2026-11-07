#!/usr/bin/env python3
"""Owned-VPS carrier fault test. Never changes the host network or SSH service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]

def restart_ssh_evidence(received, ssh_code, restart_events):
    """Check an established SSH stream failed; this does not prove new-request recovery."""
    requests = [x['elapsed_ns'] for x in restart_events if x.get('event') == 'restart_requested']
    restart_at = min(requests) if requests else None
    prefix_correct = bool(received) and [x['seq'] for x in received] == list(range(1, len(received) + 1))
    before_restart = sum(x['elapsed_ns'] < restart_at for x in received) if restart_at is not None else 0
    restart_succeeded = restart_at is not None and any(
        x.get('event') == 'restart_returned' and x.get('exit') == 0 and x['elapsed_ns'] >= restart_at
        for x in restart_events)
    return {
        'ssh_received_prefix_correct': prefix_correct,
        'ssh_lines_before_restart': before_restart,
        'restart_command_succeeded': restart_succeeded,
        'observed_old_ssh_connection_failure': bool(
            ssh_code != 0 and len(received) < 220 and prefix_correct and before_restart and restart_succeeded),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ssh-config', required=True)
    ap.add_argument('--ssh-host', required=True)
    ap.add_argument('--host-key-alias', help='Known management host key name; defaults to the effective SSH config')
    ap.add_argument('--client-config', required=True)
    ap.add_argument('--fault', choices=['blackhole', 'rebind', 'restart'], required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    private = ROOT / '.local' / 'vps-fault' / out.name
    private.mkdir(parents=True, mode=0o700, exist_ok=False)
    config_path = Path(a.client_config).resolve()
    cfg = json.loads(config_path.read_text())
    target = next(x['address'] for x in cfg['endpoints'] if x['network'] in ('quic', 'h3'))
    if a.fault != 'restart':
        cfg['endpoints'] = [dict(x, address='127.0.0.1:16660') if x['network'] in ('quic', 'h3') else x for x in cfg['endpoints']]
    cfg['socks_listen'] = '127.0.0.1:1089'
    for field in ('token_file', 'ca_file', 'ech_config_file'):
        if cfg.get(field):
            cfg[field] = str((config_path.parent / cfg[field]).resolve())
    cp = private / 'client.json'
    cp.write_text(json.dumps(cfg, indent=2))
    cp.chmod(0o600)
    ssh = ['ssh', '-F', str(Path(a.ssh_config).resolve()), '-o', 'BatchMode=yes',
           '-o', 'StrictHostKeyChecking=yes', a.ssh_host]
    # The test tunnels to this same host's loopback SSH port. Reuse the already
    # trusted management host key, rather than looking up the SOCKS destination
    # or silently disabling host verification. Validate before starting a run.
    effective = subprocess.run(ssh[:-1] + ['-G', a.ssh_host], check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sshcfg = dict(line.split(None, 1) for line in effective.stdout.splitlines() if ' ' in line)
    key_alias = a.host_key_alias or sshcfg.get('hostkeyalias')
    if not key_alias or key_alias == 'none':
        hostname, port = sshcfg['hostname'], sshcfg.get('port', '22')
        key_alias = hostname if port == '22' else '[' + hostname + ']:' + port
    with open(private/'ssh-preflight.log', 'wb') as log:
        subprocess.run(ssh[:-1] + ['-o', 'ControlPath=none', '-o', 'HostKeyAlias='+key_alias,
                                  a.ssh_host, 'true'], check=True, stdout=log, stderr=log, timeout=15)
    # Each independent trial starts with a clean prototype server; management
    # SSH, existing reference services and the controlled fixture stay intact.
    subprocess.run(ssh + ['systemctl restart protox.service'], check=True)
    time.sleep(1)
    logs = []
    processes = []
    received = []
    restart_events = []
    epoch = time.monotonic_ns()
    def launch(name, argv):
        log = open(private / (name + '.log'), 'wb')
        logs.append(log)
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=ROOT)
        processes.append(p)
        return p
    try:
        if a.fault != 'restart':
            relay = launch('relay', ['bin/faultrelay', '-listen', '127.0.0.1:16660', '-target', target,
                     '-fault', a.fault, '-after', '8s', '-for', '8s', '-duration', '38s', '-events', str(out/'relay.jsonl')])
        manifest = {
            'fault': a.fault,
            'ssh_host_key_preflight_passed': True,
            'ssh_host_key_alias_source': 'explicit' if a.host_key_alias else 'effective_management_config',
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'binaries_sha256': {name: hashlib.sha256((ROOT/'bin'/name).read_bytes()).hexdigest()
                               for name in ['protox','pxbench','faultrelay']},
            'redacted_config': {key: value for key, value in cfg.items()
                                if not key.endswith('_file') and key not in ['pin_sha256','endpoints','cover_dir']},
        }
        (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        time.sleep(.2)
        client = launch('client', ['bin/protox', 'client', '-config', str(cp)])
        restart_thread = None
        if a.fault == 'restart':
            def restart_server():
                time.sleep(max(0, 8-(time.monotonic_ns()-epoch)/1e9))
                restart_events.append({'event':'restart_requested','elapsed_ns':time.monotonic_ns()-epoch})
                with open(private/'restart.log','wb') as log:
                    p = subprocess.run(ssh + ['systemctl restart protox.service'], stdout=log, stderr=log, timeout=15)
                restart_events.append({'event':'restart_returned','elapsed_ns':time.monotonic_ns()-epoch,'exit':p.returncode})
            restart_thread = threading.Thread(target=restart_server, daemon=True)
            restart_thread.start()
        time.sleep(1)
        argv = ssh[:-1] + ['-o', 'ControlPath=none', '-o', 'HostKeyAlias='+key_alias,
                '-o', 'ProxyCommand=/usr/bin/nc -x 127.0.0.1:1089 -X 5 127.0.0.1 22', a.ssh_host,
                'for i in $(seq 1 220); do printf "%s\\n" "$i"; sleep 0.1; done']
        ssherr = open(private/'ssh.log', 'wb')
        logs.append(ssherr)
        stream = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=ssherr)
        processes.append(stream)
        def read_ssh():
            for line in iter(stream.stdout.readline, b''):
                received.append({'elapsed_ns':time.monotonic_ns()-epoch,'seq':int(line.strip())})
        reader = threading.Thread(target=read_ssh, daemon=True)
        reader.start()
        bench = launch('benchmark', ['bin/pxbench','run','-proxy','127.0.0.1:1089','-duration','30s',
                 '-background','1','-rps','5','-run-id',out.name,'-output',str(out/'bench.jsonl')])
        result = bench.wait(timeout=42)
        ssh_code = stream.wait(timeout=10)
        reader.join(timeout=2)
        if restart_thread is not None:
            restart_thread.join(timeout=1)
        gap = max([(y['elapsed_ns']-x['elapsed_ns'])/1e6 for x,y in zip(received,received[1:])],default=0)
        summary = {'fault':a.fault,'bench_exit':result,'ssh_exit':ssh_code,'ssh_expected_lines':220,
                   'ssh_received_lines':len(received),'ssh_sequence_correct':[x['seq'] for x in received]==list(range(1,221)),
                   'ssh_max_receive_gap_ms':gap,'duration_seconds':(time.monotonic_ns()-epoch)/1e9,
                   'notes':['Actual client-to-authorized-VPS path; no claim about other networks.',
                            'UDP relay applies only to relay trials; TCP/TLS alternate connects directly.',
                            'SSH probe uses one process over one original proxy flow; exit and sequence checks determine success.',
                            ('Prototype server restarted before this trial; restart fault intentionally restarts it again during measurement.'
                             if a.fault == 'restart' else 'Prototype server restarted only before this trial, not during the UDP fault.')]}
        if a.fault == 'restart':
            summary['expected_old_ssh_connection_failure'] = True
            summary.update(restart_ssh_evidence(received, ssh_code, restart_events))
            summary['notes'].append('Restart failure requires a correct nonempty SSH prefix before the restart and a successful restart command; inspect benchmark events separately for new-request recovery.')
            summary['restart_events'] = restart_events
            (out/'restart-events.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in restart_events))
        (out/'ssh-events.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in received))
        (out/'fault-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps(summary),flush=True)
        if a.fault == 'restart':
            if result or not summary['observed_old_ssh_connection_failure']:
                raise SystemExit(1)
        elif result or ssh_code or not summary['ssh_sequence_correct']:
            raise SystemExit(1)
    finally:
        for p in reversed(processes):
            if p.poll() is None: p.terminate()
        for p in reversed(processes):
            try: p.wait(timeout=4)
            except subprocess.TimeoutExpired: p.kill();p.wait()
        for log in logs: log.close()
        clientlog = private/'client.log'
        if clientlog.exists():
            # Publish only carrier lifecycle fields, never configured addresses,
            # credentials or full error strings that can contain the endpoint.
            events=[]
            for line in clientlog.read_text(errors='replace').splitlines():
                try: d=json.loads(line)
                except ValueError: continue
                if d.get('msg') in ['carrier attached','carrier detached']:
                    events.append({k:d[k] for k in ['time','msg','carrier','generation','resumed_flows'] if k in d})
            (out/'client-carriers.json').write_text(json.dumps(events,indent=2)+'\n')

if __name__=='__main__': main()
