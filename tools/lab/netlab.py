#!/usr/bin/env python3
"""Isolated, packet-level Linux link for PROTO-X / Xray / Hysteria comparison.

Run as root *inside the dedicated lab VM*. No host interface is shaped.
Namespaces retain a separate management/default route for external TLS cover
origins; 10.203.0.0/30 always traverses the impaired veth pair.
"""
import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

CLIENT = "px-client"
SERVER = "px-server"
STATE = Path("/var/lib/protox-lab")
MARKER = STATE / "owned.json"
PROFILE = STATE / "profile.json"
LINKS = {CLIENT: "pxlinkc", SERVER: "pxlinks"}
MGMT_ROOT = {CLIENT: "pxmgmtc", SERVER: "pxmgmts"}


def run(args, ns=None, check=True, capture=True):
    args = [str(x) for x in args]
    if ns:
        args = ["ip", "netns", "exec", ns] + args
    return subprocess.run(args, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def command(args, ns=None):
    return run(args, ns=ns).stdout.strip()


def require_owned():
    if not MARKER.exists():
        raise SystemExit("lab is not initialized; refusing to touch existing namespaces")


def initialize():
    if MARKER.exists():
        raise SystemExit("lab already initialized; use state or cleanup first")
    existing = command(["ip", "netns", "list"])
    if any(x in existing.split() for x in (CLIENT, SERVER)):
        raise SystemExit("namespace name already exists and is not owned by this lab")
    if run(["nft", "list", "table", "ip", "protox_lab"], check=False).returncode == 0:
        raise SystemExit("nft table protox_lab already exists and is not owned by this lab")
    STATE.mkdir(parents=True, exist_ok=True)
    MARKER.write_text(json.dumps({"created_utc": now(), "schema": 1,
                                 "previous_ip_forward": command(["sysctl", "-n", "net.ipv4.ip_forward"])}) + "\n")
    for ns in (CLIENT, SERVER):
        run(["ip", "netns", "add", ns])
        run(["ip", "link", "set", "lo", "up"], ns=ns)
        dns = Path("/etc/netns") / ns
        dns.mkdir(parents=True, exist_ok=True)
        (dns / "resolv.conf").write_text("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
    run(["ip", "link", "add", LINKS[CLIENT], "type", "veth", "peer", "name", LINKS[SERVER]])
    for ns, addr in ((CLIENT, "10.203.0.1/30"), (SERVER, "10.203.0.2/30")):
        dev = LINKS[ns]
        run(["ip", "link", "set", dev, "netns", ns])
        run(["ip", "addr", "add", addr, "dev", dev], ns=ns)
        run(["ip", "link", "set", dev, "mtu", "1500", "up"], ns=ns)
        # A qdisc must see real packet sizes, not huge GSO aggregates.
        run(["ethtool", "-K", dev, "tso", "off", "gso", "off", "gro", "off",
             "tx-udp-segmentation", "off", "tx-gso-list", "off"], ns=ns)
    # Dedicated internet egress path, not the experimental link. Only these
    # task-owned /30 addresses are NATed. Management SSH remains on guest eth0.
    for index, ns in enumerate((CLIENT, SERVER)):
        dev = MGMT_ROOT[ns]
        peer = "pxuplink"
        octet = index * 4
        run(["ip", "link", "add", dev, "type", "veth", "peer", "name", peer])
        run(["ip", "link", "set", peer, "netns", ns])
        run(["ip", "addr", "add", f"10.204.0.{octet+1}/30", "dev", dev])
        run(["ip", "link", "set", dev, "up"])
        run(["ip", "addr", "add", f"10.204.0.{octet+2}/30", "dev", peer], ns=ns)
        run(["ip", "link", "set", peer, "up"], ns=ns)
        run(["ip", "route", "add", "default", "via", f"10.204.0.{octet+1}"], ns=ns)
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    run(["nft", "add", "table", "ip", "protox_lab"])
    run(["nft", "add", "chain", "ip", "protox_lab", "postrouting",
         "{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}"])
    run(["nft", "add", "rule", "ip", "protox_lab", "postrouting",
         "ip", "saddr", "10.204.0.0/29", "masquerade"])
    print(json.dumps({"initialized": True, "client": "10.203.0.1", "server": "10.203.0.2"}))


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def profile(a):
    require_owned()
    if min(a.up, a.down) <= 0 or a.rtt < 0 or a.jitter < 0 or not 0 <= a.loss <= 100:
        raise SystemExit("invalid link parameters")
    records = []
    for index, (ns, rate) in enumerate(((CLIENT, a.up), (SERVER, a.down))):
        # Queue limit includes propagation residence. Queue-ms is additional
        # nominal residence at this rate for 1200-byte packets, not a byte AQM.
        limit = a.limit or max(16, math.ceil(rate * 1e6 * (a.rtt/2 + a.queue_ms) / 1000 / (1200*8)))
        args = ["tc", "qdisc", "replace", "dev", LINKS[ns], "root", "handle", "1:",
                "netem", "limit", str(limit), "delay", f"{a.rtt/2}ms"]
        if a.jitter:
            args += [f"{a.jitter}ms", "distribution", "normal"]
        if a.burst:
            # Gilbert-Elliott: 1% entry, 25% leave (mean 4 packets), 95%
            # loss in bad state, 0.1% in good state. Report this separately.
            args += ["loss", "gemodel", "1%", "25%", "95%", "0.1%"]
        elif a.loss:
            args += ["loss", "random", f"{a.loss}%"]
        args += ["rate", f"{rate}mbit", "24"]
        seeded = a.seed is not None
        if seeded:
            args += ["seed", str(a.seed + index)]
        result = run(args, ns=ns, check=False)
        if result.returncode and seeded and ("seed" in result.stderr or "Unknown" in result.stderr):
            # Old iproute2 kernels lack seeded netem. Do not pretend the seed
            # controlled them; retain this fact in every run's profile.
            args = args[:-2]
            seeded = False
            result = run(args, ns=ns, check=False)
        if result.returncode:
            raise SystemExit(result.stderr)
        records.append({"namespace": ns, "rate_mbps": rate, "limit_packets": limit,
                        "requested_seed": a.seed + index if a.seed is not None else None,
                        "seed_applied": seeded, "command": ["ip", "netns", "exec", ns] + args})
    data = {"utc": now(), "model": "Linux netem actual IP packets", "rtt_ms": a.rtt,
            "jitter_ms_each_direction": a.jitter, "loss_pct_each_direction": a.loss if not a.burst else None,
            "burst_gemodel": [1, 25, 95, 0.1] if a.burst else None,
            "queue_ms_nominal": a.queue_ms, "packet_overhead_bytes": 24, "directions": records}
    PROFILE.write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps(data, indent=2))


def state():
    require_owned()
    data = {"utc": now(), "kernel": command(["uname", "-a"]),
            "tc_version": command(["tc", "-V"]), "profile": json.loads(PROFILE.read_text()) if PROFILE.exists() else None,
            "namespaces": {}}
    for ns in (CLIENT, SERVER):
        data["namespaces"][ns] = {
            "links": json.loads(command(["ip", "-s", "-j", "link"], ns=ns)),
            "qdisc": json.loads(command(["tc", "-s", "-j", "qdisc", "show", "dev", LINKS[ns]], ns=ns)),
            "offload": command(["ethtool", "-k", LINKS[ns]], ns=ns),
            "pids": command(["ip", "netns", "pids", ns]).split(),
            "nstat_text": command(["nstat", "-az"], ns=ns),
        }
    print(json.dumps(data, indent=2))


def block_udp(enabled):
    require_owned()
    for ns in (CLIENT, SERVER):
        run(["nft", "delete", "table", "inet", "protox_fault"], ns=ns, check=False)
        if enabled:
            run(["nft", "add", "table", "inet", "protox_fault"], ns=ns)
            run(["nft", "add", "chain", "inet", "protox_fault", "out",
                 "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"], ns=ns)
            run(["nft", "add", "rule", "inet", "protox_fault", "out", "oifname", LINKS[ns],
                 "meta", "l4proto", "udp", "counter", "drop"], ns=ns)
    print(json.dumps({"utc": now(), "udp_blocked_on_experimental_link": enabled}))


def cleanup():
    require_owned()
    previous = json.loads(MARKER.read_text()).get("previous_ip_forward")
    for ns in (CLIENT, SERVER):
        pids = run(["ip", "netns", "pids", ns], check=False).stdout.split()
        for pid in pids:
            try:
                os.kill(int(pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
        if pids:
            time.sleep(0.2)
        for pid in run(["ip", "netns", "pids", ns], check=False).stdout.split():
            try:
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        run(["ip", "netns", "del", ns], check=False)
        run(["ip", "link", "del", MGMT_ROOT[ns]], check=False)
        dns = Path("/etc/netns") / ns / "resolv.conf"
        dns.unlink(missing_ok=True)
        try:
            dns.parent.rmdir()
        except OSError:
            pass
    run(["nft", "delete", "table", "ip", "protox_lab"], check=False)
    if previous in ("0", "1"):
        run(["sysctl", "-w", "net.ipv4.ip_forward=" + previous])
    PROFILE.unlink(missing_ok=True)
    MARKER.unlink()
    print(json.dumps({"cleaned": True}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    for name in ("init", "state", "cleanup", "block-udp", "unblock-udp"):
        sub.add_parser(name)
    prof = sub.add_parser("profile")
    prof.add_argument("--up", type=float, default=2, help="client egress Mbps")
    prof.add_argument("--down", type=float, default=8, help="server egress Mbps")
    prof.add_argument("--rtt", type=float, default=60, help="added base RTT ms")
    prof.add_argument("--jitter", type=float, default=0, help="normal jitter ms per direction")
    prof.add_argument("--loss", type=float, default=0, help="independent loss percent per direction")
    prof.add_argument("--burst", action="store_true")
    prof.add_argument("--queue-ms", type=float, default=100)
    prof.add_argument("--limit", type=int, help="override queue packet limit (including propagation)")
    prof.add_argument("--seed", type=int, help="attempt seeded netem; unsupported is recorded")
    for side in ("client", "server"):
        e = sub.add_parser(side)
        e.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo inside the dedicated Linux VM")
    if a.action == "init":
        initialize()
    elif a.action == "profile":
        profile(a)
    elif a.action == "state":
        state()
    elif a.action == "cleanup":
        cleanup()
    elif a.action in ("block-udp", "unblock-udp"):
        block_udp(a.action == "block-udp")
    else:
        require_owned()
        cmd = a.command[1:] if a.command and a.command[0] == "--" else a.command
        if not cmd:
            raise SystemExit("missing command")
        os.execvp("ip", ["ip", "netns", "exec", CLIENT if a.action == "client" else SERVER] + cmd)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"command failed ({e.returncode}): {e.cmd}\n{e.stderr}", file=sys.stderr)
        sys.exit(e.returncode)
