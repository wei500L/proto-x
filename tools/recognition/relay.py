#!/usr/bin/env python3
"""Observe real TLS stream bytes and UDP datagrams at a controlled relay.

These records are socket observations, NOT fabricated IP packets or a host
pcap. They do not preserve TCP segmentation, retransmissions or NIC timings.
Captures contain visible hostnames and belong in a private .local directory.
"""
import argparse
import asyncio
import base64
import json
import os
from pathlib import Path
import re
import signal
import time


def address(value):
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), int(port)


def private_json(path, value):
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


class Capture:
    def __init__(self, directory, label, limit_bytes, limit_packets):
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.path = directory / "capture.jsonl"
        self.stream = self.path.open("x", buffering=1)
        os.chmod(self.path, 0o600)
        self.start = time.monotonic_ns()
        self.limit_bytes, self.limit_packets = limit_bytes, limit_packets
        self.counts = {}
        self.next_id = {"tcp": 0, "udp": 0}
        self.event(kind="capture_started", label=label, schema=1,
                   observation="actual bytes read by a user-space forwarding relay",
                   is_host_pcap=False, tcp_segmentation_preserved=False,
                   capture_byte_limit_per_direction=limit_bytes,
                   capture_udp_packet_limit_per_direction=limit_packets)

    def event(self, **data):
        data["elapsed_ns"] = time.monotonic_ns() - self.start
        self.stream.write(json.dumps(data, separators=(",", ":")) + "\n")

    def new_flow(self, transport):
        self.next_id[transport] += 1
        name = transport + "-" + str(self.next_id[transport])
        self.event(kind="flow_started", flow=name, transport=transport)
        return name

    def data(self, flow, direction, payload, datagram=False):
        key = (flow, direction)
        state = self.counts.setdefault(key, {"bytes": 0, "chunks": 0, "captured_bytes": 0,
                                            "captured_chunks": 0, "capture_truncated": False})
        state["bytes"] += len(payload)
        state["chunks"] += 1
        remaining = max(0, self.limit_bytes - state["captured_bytes"])
        # A partial UDP datagram is not useful evidence for AEAD parsing.
        if datagram:
            kept = payload if len(payload) <= remaining and state["captured_chunks"] < self.limit_packets else b""
        else:
            kept = payload[:remaining]
        if len(kept) != len(payload):
            state["capture_truncated"] = True
        if kept:
            state["captured_bytes"] += len(kept)
            state["captured_chunks"] += 1
            self.event(kind="udp_datagram" if datagram else "tcp_bytes", flow=flow,
                       direction=direction, observed_bytes=len(payload), captured_bytes=len(kept),
                       complete_observation=len(kept) == len(payload),
                       data_base64=base64.b64encode(kept).decode())

    def close(self):
        for (flow, direction), values in sorted(self.counts.items()):
            self.event(kind="flow_counts", flow=flow, direction=direction, **values)
        self.event(kind="capture_stopped")
        self.stream.close()


class UDPBackend(asyncio.DatagramProtocol):
    def __init__(self, frontend, client, flow):
        self.frontend, self.client, self.flow = frontend, client, flow

    def datagram_received(self, data, _):
        self.frontend.capture.data(self.flow, "server_to_client", data, True)
        self.frontend.transport.sendto(data, self.client)

    def error_received(self, exc):
        self.frontend.capture.event(kind="udp_backend_error", flow=self.flow,
                                    error_class=type(exc).__name__)


class UDPFrontend(asyncio.DatagramProtocol):
    def __init__(self, capture, target, max_flows):
        self.capture, self.target, self.max_flows = capture, target, max_flows
        self.transport = None
        self.flows = {}
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, client):
        state = self.flows.get(client)
        if state is None:
            if len(self.flows) >= self.max_flows:
                self.capture.event(kind="relay_bound_drop", reason="max_udp_flows")
                return
            state = {"id": self.capture.new_flow("udp"), "transport": None, "pending": []}
            self.flows[client] = state
            task = asyncio.create_task(self.connect(client, state))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        self.capture.data(state["id"], "client_to_server", data, True)
        if state["transport"] is not None:
            state["transport"].sendto(data)
        elif len(state["pending"]) < 64:
            state["pending"].append(data)
        else:
            self.capture.event(kind="relay_bound_drop", flow=state["id"], reason="udp_connect_pending")

    async def connect(self, client, state):
        try:
            backend, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: UDPBackend(self, client, state["id"]), remote_addr=self.target,
                # Explicit bind makes backend port isolation observable in
                # loopback fixtures. Private mapping events support diagnosis
                # of the reflection seen in the first local smoke run.
                local_addr=("::" if ":" in self.target[0] else "0.0.0.0", 0))
            state["transport"] = backend
            self.capture.event(kind="private_udp_mapping", flow=state["id"], client=list(client),
                               backend_local=list(backend.get_extra_info("sockname")),
                               target=list(self.target), frontend_local=list(self.transport.get_extra_info("sockname")))
            for data in state["pending"]:
                backend.sendto(data)
            state["pending"].clear()
        except Exception as exc:
            self.capture.event(kind="udp_connect_error", flow=state["id"], error_class=type(exc).__name__)
            state["pending"].clear()

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for state in self.flows.values():
            if state["transport"]:
                state["transport"].close()
        self.transport.close()


async def run(args):
    directory = Path(args.out)
    capture = Capture(directory, args.label, args.capture_bytes, args.capture_packets)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    tcp_tasks, tcp_writers = set(), set()

    async def tcp_connection(reader, writer):
        task = asyncio.current_task()
        tcp_tasks.add(task)
        tcp_writers.add(writer)
        flow = capture.new_flow("tcp")
        upstream = None
        copies = []
        try:
            if len(tcp_tasks) > args.max_flows:
                capture.event(kind="relay_bound_drop", flow=flow, reason="max_tcp_flows")
                return
            upstream_reader, upstream = await asyncio.wait_for(asyncio.open_connection(*address(args.tcp_target)), 5)
            tcp_writers.add(upstream)

            async def copy(source, destination, direction):
                while True:
                    payload = await source.read(65536)
                    if not payload:
                        if destination.can_write_eof():
                            destination.write_eof()
                        return
                    capture.data(flow, direction, payload)
                    destination.write(payload)
                    await destination.drain()

            copies = [asyncio.create_task(copy(reader, upstream, "client_to_server")),
                      asyncio.create_task(copy(upstream_reader, writer, "server_to_client"))]
            await asyncio.gather(*copies)
        except (Exception, asyncio.CancelledError) as exc:
            capture.event(kind="tcp_flow_ended", flow=flow, error_class=type(exc).__name__)
        finally:
            for copy_task in copies:
                copy_task.cancel()
            await asyncio.gather(*copies, return_exceptions=True)
            for w in (writer, upstream):
                if w is not None:
                    w.close()
                    tcp_writers.discard(w)
            tcp_tasks.discard(task)

    tcp_server, udp_front = None, None
    ready = {"pid": os.getpid(), "label": args.label, "capture": str(capture.path)}
    try:
        if args.tcp_target:
            tcp_server = await asyncio.start_server(tcp_connection, *address(args.tcp_listen))
            ready["tcp_listen"] = list(tcp_server.sockets[0].getsockname()[:2])
        if args.udp_target:
            transport, udp_front = await loop.create_datagram_endpoint(
                lambda: UDPFrontend(capture, address(args.udp_target), args.max_flows),
                local_addr=address(args.udp_listen))
            ready["udp_listen"] = list(transport.get_extra_info("sockname")[:2])
        private_json(directory / "ready.json", ready)
        print(json.dumps({"ready_file": str(directory / "ready.json")}), flush=True)
        await stop.wait()
    finally:
        if tcp_server:
            tcp_server.close()
            await tcp_server.wait_closed()
        for writer in tcp_writers:
            writer.close()
        for task in list(tcp_tasks):
            task.cancel()
        await asyncio.gather(*list(tcp_tasks), return_exceptions=True)
        if udp_front:
            await udp_front.close()
        capture.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="new private capture directory, normally below .local")
    parser.add_argument("--label", required=True)
    parser.add_argument("--tcp-listen", default="127.0.0.1:0")
    parser.add_argument("--udp-listen", default="127.0.0.1:0")
    parser.add_argument("--tcp-target")
    parser.add_argument("--udp-target")
    parser.add_argument("--capture-bytes", type=int, default=262144)
    parser.add_argument("--capture-packets", type=int, default=128)
    parser.add_argument("--max-flows", type=int, default=64)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", args.label):
        parser.error("label must be a redacted ASCII category")
    if not args.tcp_target and not args.udp_target:
        parser.error("specify at least one explicitly authorized target")
    if min(args.capture_bytes, args.capture_packets) < 0 or args.max_flows <= 0:
        parser.error("capture bounds must be nonnegative and max-flows must be positive")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
