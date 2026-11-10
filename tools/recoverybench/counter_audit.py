#!/usr/bin/env python3
"""Calibrate veth qdisc byte layers on the otherwise idle owned Linux netlab.

Run with sudo inside the project-owned Lima VM, never during a matrix trial.
This does not alter firewall, qdisc, routes, or management connectivity.
"""
import json
import os
from pathlib import Path
import subprocess


def command(side, args):
    return subprocess.check_output(["ip", "netns", "exec", "px-"+side]+args, text=True)


def snapshot(side):
    dev="pxlinkc" if side=="client" else "pxlinks"
    return next(row for row in json.loads(command(side,["tc","-s","-j","qdisc","show","dev",dev])) if row["kind"]=="netem")


def main():
    if os.geteuid()!=0 or not Path("/var/lib/protox-lab/owned.json").is_file():
        raise SystemExit("requires the owned Linux netlab; run inside its VM only")
    receiver = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.203.0.2',0)); print(s.getsockname()[1],flush=True); b,a=s.recvfrom(4096); s.sendto(b,a)"
    server=subprocess.Popen(["ip","netns","exec","px-server","python3","-u","-c",receiver], stdout=subprocess.PIPE,text=True)
    try:
        port=int(server.stdout.readline().strip())
        before={side:snapshot(side) for side in ("client","server")}
        sender="import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(bytes(100),('10.203.0.2',%d)); assert len(s.recvfrom(4096)[0])==100" % port
        command("client",["python3","-c",sender])
        server.wait(timeout=3)
        after={side:snapshot(side) for side in ("client","server")}
        delta={side:{key:after[side][key]-before[side][key] for key in ("bytes","packets","drops")} for side in before}
        expected=all(row==dict(bytes=142,packets=1,drops=0) for row in delta.values())
        print(json.dumps(dict(payload_bytes_each_direction=100, ip_udp_expected=128, ethernet_header_expected=14,
                              qdisc_delta=delta, calibrated_expected_ethernet_layer=expected,
                              notes=["If extra ARP/other traffic or loss is counted, this one-packet calibration is inconclusive.",
                                     "142 = payload100 + UDP8 + IPv4 20 + Ethernet14; FCS is not included.",
                                     "Configured netem rate overhead affects shaping, not this byte counter."]),indent=2))
        return 0 if expected else 1
    finally:
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=3)


if __name__=="__main__":
    raise SystemExit(main())
