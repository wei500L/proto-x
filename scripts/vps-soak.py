#!/usr/bin/env python3
"""Measure an authorized prototype service while running a bounded SOCKS load.

The existing client and controlled fixture must already be running. This script
does not restart services or change networking. Raw SSH stderr stays private.
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
    ap.add_argument('--ssh-config', required=True)
    ap.add_argument('--ssh-host', required=True)
    ap.add_argument('--proxy', default='127.0.0.1:1088')
    ap.add_argument('--seconds', type=int, default=600)
    ap.add_argument('--background-mbps', type=float, default=2.5)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    if not 10 <= a.seconds <= 86400 or not 0 < a.background_mbps <= 20:
        ap.error('seconds must be 10..86400; background-mbps must be >0..20')
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    private = ROOT / '.local' / 'vps-soak' / out.name
    private.mkdir(parents=True, mode=0o700, exist_ok=False)
    ssh = ['ssh', '-F', str(Path(a.ssh_config).resolve()), '-o', 'BatchMode=yes',
           '-o', 'ConnectTimeout=4', a.ssh_host]
    # Only aggregate resource values enter the public evidence directory.
    query = ('systemctl show protox.service --property=MainPID,MemoryCurrent,'
             'MemoryPeak,CPUUsageNSec,NRestarts,ActiveState,SubState')
    start = time.monotonic()
    samples = []
    with open(private / 'ssh.log', 'wb') as errlog:
        def sample():
            item = {'elapsed_seconds': time.monotonic() - start}
            try:
                p = subprocess.run(ssh + [query], stdout=subprocess.PIPE,
                                   stderr=errlog, timeout=8, check=False)
                item['query_exit'] = p.returncode
                for line in p.stdout.decode(errors='replace').splitlines():
                    key, sep, value = line.partition('=')
                    if sep and key in {'MainPID', 'MemoryCurrent', 'MemoryPeak',
                                       'CPUUsageNSec', 'NRestarts', 'ActiveState', 'SubState'}:
                        item[key] = int(value) if value.isdecimal() else value
            except subprocess.TimeoutExpired:
                item['query_timeout'] = True
            samples.append(item)
            with open(out / 'resources.jsonl', 'a') as stream:
                stream.write(json.dumps(item) + '\n')

        sample()
        argv = [str(ROOT / 'bin/pxbench'), 'run', '-proxy', a.proxy,
                '-duration', str(a.seconds) + 's', '-background', '1',
                '-background-mbps', str(a.background_mbps), '-rps', '5',
                '-cold-http', '-run-id', out.name, '-output', str(out / 'bench.jsonl')]
        with open(private / 'benchmark.log', 'wb') as log:
            process = subprocess.Popen(argv, stdout=log, stderr=log, cwd=ROOT)
            try:
                while process.poll() is None:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        sample()
                    if time.monotonic() - start > a.seconds + 30:
                        raise TimeoutError('benchmark exceeded its duration allowance')
                sample()
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    valid = [s for s in samples if s.get('query_exit') == 0 and isinstance(s.get('MemoryCurrent'), int)]
    cpu = None
    if len(valid) > 1:
        dt = valid[-1]['elapsed_seconds'] - valid[0]['elapsed_seconds']
        if valid[0].get('MainPID') == valid[-1].get('MainPID') and dt > 0:
            cpu = (valid[-1]['CPUUsageNSec'] - valid[0]['CPUUsageNSec']) / (dt * 1e9) * 100
    summary = {
        'measured_wall_seconds': time.monotonic() - start,
        'requested_benchmark_seconds': a.seconds,
        'benchmark_exit': process.returncode,
        'resource_samples': len(samples),
        'resource_samples_valid': len(valid),
        'max_sampled_memory_bytes': max((s['MemoryCurrent'] for s in valid), default=None),
        'kernel_recorded_memory_peak_bytes': max((s['MemoryPeak'] for s in valid if isinstance(s.get('MemoryPeak'), int)), default=None),
        'same_pid_all_valid_samples': len({s.get('MainPID') for s in valid}) == 1 if valid else None,
        'restart_count_first_last': [valid[0].get('NRestarts'), valid[-1].get('NRestarts')] if valid else [],
        'mean_cpu_percent_one_core': cpu,
        'benchmark_sha256': hashlib.sha256((ROOT / 'bin/pxbench').read_bytes()).hexdigest(),
        'notes': [
            'One authorized VPS path; no inference about all Russian networks.',
            'Cold HTTP POST creates repeated flows; background source is paced per worker.',
            'Service was not restarted by this script; MemoryPeak may include prior activity.',
            'Resource SSH uses the management path outside the measured proxy.',
            'Completed duration is evidence only for this finite trial, not day-long reliability.'
        ],
    }
    (out / 'soak-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    if process.returncode:
        raise SystemExit(process.returncode)


if __name__ == '__main__':
    main()
