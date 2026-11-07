#!/usr/bin/env python3
"""Measure one idle QUIC/H3 client through a relay to its authorized server.

No application target is opened. Credentials and full client logs stay private.
Counts cover UDP payloads observed locally, including setup and shutdown; they
are not Ethernet bytes or a measurement of remote loss.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--client-config', required=True)
    ap.add_argument('--seconds', type=int, default=60)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    if not 10 <= a.seconds <= 3600:
        ap.error('seconds must be 10..3600')
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    private = ROOT / '.local' / 'vps-idle' / out.name
    private.mkdir(parents=True, mode=0o700, exist_ok=False)
    source = Path(a.client_config).resolve()
    cfg = json.loads(source.read_text())
    endpoint = next(e for e in cfg['endpoints'] if e['network'] in ('quic', 'h3'))
    target = endpoint['address']
    cfg['endpoints'] = [dict(endpoint, address='127.0.0.1:16662')]
    for field in ('token_file', 'ca_file', 'ech_config_file'):
        if cfg.get(field):
            cfg[field] = str((source.parent / cfg[field]).resolve())
    cfg['socks_listen'] = '127.0.0.1:1090'
    cp = private / 'client.json'
    cp.write_text(json.dumps(cfg, indent=2))
    cp.chmod(0o600)
    processes, logs = [], []

    def launch(name, argv):
        log = open(private / (name + '.log'), 'wb')
        logs.append(log)
        p = subprocess.Popen(argv, cwd=ROOT, stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        processes.append(p)
        return p

    try:
        relay = launch('relay', ['bin/faultrelay', '-listen', '127.0.0.1:16662', '-target', target,
                                '-fault', 'blackhole', '-after', str(a.seconds+5)+'s', '-for', '1s',
                                '-duration', str(a.seconds+10)+'s', '-events', str(out/'relay.jsonl')])
        time.sleep(.2)
        client = launch('client', ['bin/protox','client','-config',str(cp)])
        try:
            client.wait(timeout=a.seconds)
            raise RuntimeError('idle client exited before the observation ended')
        except subprocess.TimeoutExpired:
            pass
    finally:
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for log in logs:
            log.close()
    events = [json.loads(l) for l in (out/'relay.jsonl').read_text().splitlines()]
    if not events or events[-1]['event'] != 'end' or any(e['event']=='fault_start' for e in events):
        raise RuntimeError('relay observation incomplete or accidentally reached the fault timer')
    attached = []
    for line in (private/'client.log').read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get('msg') == 'carrier attached':
            attached.append({k:e[k] for k in ['carrier','generation','resumed_flows'] if k in e})
    seconds = events[-1]['elapsed_ns']/1e9
    count = events[-1]['counters']
    metrics = {}
    for direction in ['up','down']:
        c = count[direction]['forwarded']
        metrics[direction] = dict(c, payload_bytes_per_second=c['bytes']/seconds,
                                 packets_per_second=c['packets']/seconds,
                                 ipv4_udp_estimated_bytes_per_second=(c['bytes']+28*c['packets'])/seconds)
    result = {'measured_seconds':seconds,'requested_seconds':a.seconds,'application_flows_opened':0,
              'carriers':attached,'directions':metrics,'heartbeat_ms':cfg['heartbeat_ms'],
              'dead_ms':cfg['dead_ms'], 'ech_required':bool(cfg.get('ech_config_file')),
              'web_padding':cfg.get('web_padding') if endpoint['network']=='h3' else None,
              'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'binary_sha256':hashlib.sha256((ROOT/'bin/protox').read_bytes()).hexdigest(),
              'notes':['Counts include this one connection startup and shutdown.',
                       'Relay bytes are observed UDP payloads; IPv4+UDP adds an estimate of 28 bytes per packet.',
                       'No Ethernet, VPN, remote-receipt or mobile-radio energy measurement is implied.',
                       'The configured fault occurs after the observation and must never execute.']}
    (out/'idle-summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
    if len(attached)!=1 or attached[0].get('carrier')!=endpoint['network']:
        raise SystemExit(1)


if __name__=='__main__':
    main()
