#!/usr/bin/env python3
"""Generate private, parameterized VLESS/REALITY/Vision and Hysteria2 configs."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid


def private_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def make_configs(args):
    out = args.out.resolve()
    # Deliberately prohibit putting authentication material in public example directories.
    if ".local" not in out.parts:
        raise ValueError("--out must be inside an ignored .local directory")
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o700)
    key_path = out / "credentials.json"
    if key_path.exists():
        credentials = json.loads(key_path.read_text())
    else:
        result = subprocess.run([str(args.xray), "x25519"], check=True, capture_output=True, text=True)
        fields = dict(line.split(":", 1) for line in result.stdout.splitlines() if ":" in line)
        public = fields.get("Password (PublicKey)", fields.get("Public key", fields.get("PublicKey", ""))).strip()
        private = fields.get("PrivateKey", fields.get("Private key", "")).strip()
        if not private or not public:
            raise ValueError("unrecognized xray x25519 output; no keys printed")
        credentials = {"vless_id": str(uuid.uuid4()), "reality_private": private,
                       "reality_public": public, "reality_short_id": secrets.token_hex(8),
                       "hysteria_auth": secrets.token_urlsafe(32)}
        private_json(key_path, credentials)

    cert_path, tls_key_path = out / "tls-cert.pem", out / "tls-key.pem"
    if not cert_path.exists() or not tls_key_path.exists():
        if not re.fullmatch(r"[A-Za-z0-9.-]+", args.tls_sni):
            raise ValueError("TLS SNI must be a DNS name")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-nodes", "-days", "365",
                        "-subj", "/CN=" + args.tls_sni,
                        "-addext", "subjectAltName=DNS:" + args.tls_sni,
                        "-keyout", str(tls_key_path), "-out", str(cert_path)],
                       check=True, capture_output=True)
        tls_key_path.chmod(0o600)
        cert_path.chmod(0o600)

    server_dir = args.server_directory or str(out)
    xray_server = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "vless-reality-vision", "listen": args.listen,
            "port": args.xray_port, "protocol": "vless",
            "settings": {"clients": [{"id": credentials["vless_id"], "flow": "xtls-rprx-vision"}],
                         "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality",
                "realitySettings": {"show": False, "target": args.reality_target,
                    "xver": 0, "serverNames": [args.reality_sni],
                    "privateKey": credentials["reality_private"],
                    "shortIds": [credentials["reality_short_id"]]}}}],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }
    if args.allow_test_cidr:
        xray_server["outbounds"][0]["settings"] = {"finalRules": [
            {"action": "allow", "ip": args.allow_test_cidr, "network": "tcp"}]}
    xray_client = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": args.socks_xray,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"tag": "vless-reality-vision", "protocol": "vless",
            "settings": {"address": args.server, "port": args.xray_port,
                         "id": credentials["vless_id"], "flow": "xtls-rprx-vision", "encryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality",
                "realitySettings": {"fingerprint": "chrome", "serverName": args.reality_sni,
                    "password": credentials["reality_public"],
                    "shortId": credentials["reality_short_id"], "spiderX": "/"}},
            "mux": {"enabled": False}}]
    }
    private_json(out / "xray-server.json", xray_server)
    private_json(out / "xray-client.json", xray_client)
    for profile in ("bbr-standard", "bbr-conservative", "brutal"):
        hserver = {"listen": f"{args.listen}:{args.hysteria_port}",
            "tls": {"cert": server_dir + "/tls-cert.pem", "key": server_dir + "/tls-key.pem"},
            "auth": {"type": "password", "password": credentials["hysteria_auth"]},
            "disableUDP": True,
            "masquerade": {"type": "string", "string": {"content": "Not Found\n", "statusCode": 404}}}
        server_addr = f"[{args.server}]:{args.hysteria_port}" if ":" in args.server else f"{args.server}:{args.hysteria_port}"
        hclient = {"server": server_addr, "auth": credentials["hysteria_auth"],
            "tls": {"sni": args.tls_sni, "ca": str(cert_path), "insecure": False},
            "socks5": {"listen": f"127.0.0.1:{args.socks_hysteria}", "disableUDP": True},
            "fastOpen": False}
        if profile == "brutal":
            hserver["bandwidth"] = {"up": args.down, "down": args.up,
                                    "disableLossCompensation": args.disable_loss_compensation}
            hclient["bandwidth"] = {"up": args.up, "down": args.down,
                                    "disableLossCompensation": args.disable_loss_compensation}
        else:
            congestion = {"type": "bbr", "bbrProfile": profile.removeprefix("bbr-")}
            hserver["congestion"] = congestion
            hserver["ignoreClientBandwidth"] = True
            hclient["congestion"] = congestion
        private_json(out / f"hysteria-server-{profile}.json", hserver)
        private_json(out / f"hysteria-client-{profile}.json", hclient)
    private_json(out / "parameters.json", {"server": args.server, "xray_port": args.xray_port,
        "hysteria_port": args.hysteria_port, "socks_xray": args.socks_xray,
        "socks_hysteria": args.socks_hysteria, "reality_sni": args.reality_sni,
        "reality_target": args.reality_target, "tls_sni": args.tls_sni,
        "up": args.up, "down": args.down, "server_directory": server_dir})
    return out


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path(".local/baselines/config"))
    p.add_argument("--xray", type=Path, default=Path(".local/baselines/bin/darwin-arm64/xray"))
    p.add_argument("--server", required=True)
    p.add_argument("--listen", default="0.0.0.0")
    p.add_argument("--xray-port", type=int, default=33400)
    p.add_argument("--hysteria-port", type=int, default=33401)
    p.add_argument("--socks-xray", type=int, default=10801)
    p.add_argument("--socks-hysteria", type=int, default=10802)
    p.add_argument("--reality-sni", default="www.cloudflare.com")
    p.add_argument("--reality-target", default="www.cloudflare.com:443")
    p.add_argument("--tls-sni", default="protox-baseline.test")
    p.add_argument("--server-directory", help="certificate directory on the server; defaults to --out")
    p.add_argument("--up", default="2 mbps", help="client-to-server Brutal application budget")
    p.add_argument("--down", default="8 mbps", help="server-to-client Brutal application budget")
    p.add_argument("--disable-loss-compensation", action="store_true")
    p.add_argument("--allow-test-cidr", action="append", default=[],
                   help="explicitly allow controlled test targets (e.g. 127.0.0.1/32) in Xray finalRules")
    return p


if __name__ == "__main__":
    os.umask(0o077)
    args = parser().parse_args()
    out = make_configs(args)
    print(f"Private baseline configs generated in {out}; credentials not printed.")
