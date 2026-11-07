#!/usr/bin/env python3
"""Export redacted ClientHello observations from private relay recordings."""
import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from wire import CryptoStream, DecodeError, NeedMore, crypto_frames, decrypt_initial, tls_record_hello


def redact_hello(hello, names, legacy_alpns):
    out = dict(hello)
    values = out.pop("server_names")
    cover = set(x.lower().rstrip(".") for x in names.get("cover_names", []))
    legacy = set(x.lower().rstrip(".") for x in names.get("legacy_names", []))
    inner = set(x.lower().rstrip(".") for x in names.get("inner_names", []))
    outer = set(x.lower().rstrip(".") for x in names.get("outer_names", []))
    classes = []
    for item in values:
        value = item["value"].lower().rstrip(".")
        kind = ("configured_inner_name" if value in inner else
                "configured_outer_name" if value in outer else
                "configured_cover_name" if value in cover else
                "configured_legacy_name" if value in legacy else "other_present_name")
        classes.append({"name_type": item["type"], "class": kind})
    out["sni"] = {"present": bool(values), "names": classes, "values_redacted": True}
    out["legacy_custom_alpn_observed"] = any(x in legacy_alpns for x in out["alpn"])
    return out


def inspect(path, label, names, legacy_alpns):
    tcp = defaultdict(bytearray)
    udp = []
    started_flows = {}
    counts = []
    source, stopped = None, False
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, 1):
            if len(line) > 2 * 1024 * 1024:
                raise ValueError("capture line exceeds inspection bound")
            digest.update(line)
            event = json.loads(line)
            kind = event.get("kind")
            if kind == "capture_started":
                source = event
            if kind == "capture_stopped":
                stopped = True
            if kind == "flow_started":
                started_flows[event["flow"]] = event["transport"]
                if event["transport"] == "tcp":
                    tcp[event["flow"]]
            if kind == "flow_counts":
                counts.append(event)
            if event.get("direction") != "client_to_server":
                continue
            if kind not in ("tcp_bytes", "udp_datagram"):
                continue
            payload = base64.b64decode(event["data_base64"], validate=True)
            if kind == "tcp_bytes":
                if len(tcp[event["flow"]]) + len(payload) > 2 * 1024 * 1024:
                    raise ValueError("captured TCP flow exceeds inspection bound")
                tcp[event["flow"]] += payload
            elif event.get("complete_observation"):
                udp.append((event["flow"], payload, line_number))
    if not source or source.get("is_host_pcap") is not False:
        raise ValueError("input lacks the declared socket-relay observation schema")
    observations, errors = [], []
    for flow, payload in sorted(tcp.items()):
        item = {"flow": flow, "transport": "tls_over_tcp",
                "observation_method": "actual ordered TLS record bytes read at relay"}
        try:
            item["client_hello"] = redact_hello(tls_record_hello(payload), names, legacy_alpns)
            item["status"] = "client_hello_decoded"
        except DecodeError as exc:
            item.update(status="not_decoded", reason=str(exc))
        observations.append(item)
    crypto, expected, initial_stats, failures = {}, {}, defaultdict(Counter), Counter()
    for flow, datagram, line_number in udp:
        at = 0
        while at < len(datagram):
            packet = datagram[at:]
            if len(packet) < 6 or not packet[0] & 0x80:
                failures["non_initial_or_short_header"] += 1
                break
            version = int.from_bytes(packet[1:5], "big")
            initial_kind = 1 if version == 0x6B3343CF else 0
            if version not in (1, 0x6B3343CF) or (packet[0] >> 4) & 3 != initial_kind:
                failures["other_long_header_or_unsupported_version"] += 1
                break
            # Client DCID can change to a server-selected CID while Initial
            # keys remain derived from the original client-chosen DCID.
            # Retry can establish a new key namespace. Try only public keys
            # already seen on this flow plus this Initial's current DCID;
            # successful AEAD, not a heuristic, selects the namespace.
            dcid_length = packet[5]
            key = (flow, version, packet[6:6 + dcid_length])
            try:
                candidates = [key] + [k for k in crypto if k[:2] == (flow, version) and k != key]
                initial = None
                last_error = None
                for possible_key in candidates:
                    try:
                        initial = decrypt_initial(packet, expected.get(possible_key, 0), original_dcid=possible_key[2])
                        key = possible_key
                        break
                    except DecodeError as exc:
                        last_error = exc
                if initial is None:
                    raise last_error
                expected[key] = max(expected.get(key, 0), initial.packet_number + 1)
                if key not in crypto:
                    if len(crypto) >= 256:
                        raise DecodeError("Initial connection inspection bound exceeded")
                    crypto[key] = CryptoStream()
                for offset, value in crypto_frames(initial.plaintext):
                    crypto[key].add(offset, value)
                initial_stats[key]["authenticated_initial_packets"] += 1
                initial_stats[key]["initial_packet_bytes"] += initial.packet_bytes
                at += initial.packet_bytes
            except DecodeError as exc:
                failures["initial_decryption_or_reassembly_error"] += 1
                errors.append({"flow": flow, "capture_line": line_number, "reason": str(exc)})
                break
    for ordinal, (key, stream) in enumerate(crypto.items(), 1):
        flow, version, dcid = key
        item = {"flow": flow, "initial_context": ordinal, "transport": "quic_initial",
                "quic_version": "0x%08x" % version, "destination_cid_length": len(dcid),
                "observation_method": "actual UDP payload; public Initial-key AEAD decryption and CRYPTO reassembly",
                "initial_keys_are_public": True, "statistics": dict(initial_stats[key])}
        try:
            item["client_hello"] = redact_hello(stream.hello(), names, legacy_alpns)
            item["status"] = "client_hello_decoded"
        except DecodeError as exc:
            item.update(status="not_decoded", reason=str(exc))
        observations.append(item)
    decoded_udp_flows = {key[0] for key in crypto}
    for flow, transport in sorted(started_flows.items()):
        if transport == "udp" and flow not in decoded_udp_flows:
            observations.append({"flow": flow, "transport": "quic_initial", "status": "not_decoded",
                                 "reason": "no authenticated Initial context decoded from this observed UDP flow"})
    return {
        "schema": 1, "label": label, "capture_sha256": digest.hexdigest(),
        "source": "controlled user-space relay observations; not host pcap or server callback",
        "capture_shutdown_observed": stopped, "observations": observations,
        "capture_flow_counts": dict(Counter(started_flows.values())),
        "decoded_client_hello_count": sum(x["status"] == "client_hello_decoded" for x in observations),
        "quic_unparsed_packet_categories": dict(failures), "inspection_errors": errors,
        "relay_counts": counts,
        "interpretation": [
            "SNI values are redacted to configured-name classes; only the visible outer ClientHello is inspected.",
            "An ECH extension can be real or GREASE; its presence does not prove ECH acceptance or reveal the inner name.",
            "Offered ALPN is a ClientHello observation. Negotiated ALPN requires the active client's connection state.",
            "TCP relay reads preserve byte order but do not preserve IP packets, retransmissions, segmentation or NIC timestamps.",
            "QUIC Initial decryption requires no TLS secret; later encrypted traffic is not decrypted here.",
            "A missing legacy ALPN match defeats only that declared rule, not classifiers, all DPI or active detection.",
            "Capture truncation and undecoded observations remain visible. Legacy-ALPN probes must not be mislabeled as native client traffic."
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--names-private", type=Path, help="JSON cover_names/legacy_names; actual values are never exported")
    parser.add_argument("--legacy-alpn", action="append", default=["proto-x/1"])
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", args.label):
        parser.error("label must be a redacted ASCII category")
    if args.out.exists():
        parser.error("refusing to replace an existing observation report")
    names = json.loads(args.names_private.read_text()) if args.names_private else {}
    report = inspect(args.capture, args.label, names, args.legacy_alpn)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"report": str(args.out), "decoded_client_hellos": report["decoded_client_hello_count"],
                      "inspection_errors": len(report["inspection_errors"])}))


if __name__ == "__main__":
    main()
