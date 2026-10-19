import base64
from datetime import datetime, timezone
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import yaml

from check_nodes import build_curl_command, check_node, publish, source_url, validate_public_server
from nodes import parse_node


UUID = "12345678-1234-4234-8234-123456789abc"


class CheckerTests(unittest.TestCase):
    def test_source_date_rolls_at_shanghai_midnight(self):
        now = datetime(2026, 10, 18, 16, 1, tzinfo=timezone.utc)
        self.assertTrue(source_url(now).endswith("20261019.txt"))

    def test_curl_forces_socks_remote_dns_and_disables_noproxy(self):
        command = build_curl_command(19876, "https://www.gstatic.com/generate_204", 10)
        self.assertEqual(command[command.index("--proxy") + 1], "socks5h://127.0.0.1:19876")
        self.assertEqual(command[command.index("--noproxy") + 1], "")
        self.assertNotIn("--insecure", command)
        self.assertNotIn("--location", command)

    def test_non_public_addresses_rejected(self):
        for host in ["127.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "192.0.2.1", "198.51.100.5", "203.0.113.5"]:
            with self.subTest(host=host):
                self.assertFalse(validate_public_server(host))
        self.assertTrue(validate_public_server("8.8.8.8"))

    def test_domain_resolving_to_private_address_rejected(self):
        response = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("socket.getaddrinfo", return_value=response):
            self.assertFalse(validate_public_server("node.example"))

    def test_all_failed_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            for file in ["v2ray.txt", "clash.yaml", "status.json"]:
                (out / file).write_bytes(b"last-known-good")
            self.assertFalse(publish(out, [], [], {"status": "failed"}))
            self.assertEqual({p.read_bytes() for p in out.iterdir()}, {b"last-known-good"})

    def test_success_exports_only_passed_nodes(self):
        good = parse_node(f"vless://{UUID}@node.example:443?security=tls#node")
        bad = parse_node(f"vless://{UUID}@other.example:443?security=tls#bad")
        with tempfile.TemporaryDirectory() as td:
            results = [{"id": good.id, "status": "ok", "latency_ms": 123}, {"id": bad.id, "status": "failed"}]
            self.assertTrue(publish(Path(td), [good, bad], results, {"updated_at": "2026-10-19"}))
            decoded = base64.b64decode((Path(td) / "v2ray.txt").read_bytes()).decode()
            self.assertEqual(decoded.strip(), good.uri)
            clash = yaml.safe_load((Path(td) / "clash.yaml").read_text())
            self.assertEqual(len(clash["proxies"]), 1)
            self.assertEqual(clash["proxies"][0]["server"], "node.example")
            self.assertNotIn("DIRECT", json.dumps(clash))

    def test_unconvertible_node_retains_previous_clash(self):
        n = parse_node(f"vless://{UUID}@node.example:443?type=xhttp&security=tls&extra=%7B%22noGRPCHeader%22%3Atrue%7D")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "clash.yaml").write_text("previous-clash")
            report = {}
            self.assertTrue(publish(out, [n], [{"id": n.id, "status": "ok", "latency_ms": 1}], report))
            self.assertEqual((out / "clash.yaml").read_text(), "previous-clash")
            self.assertFalse(report["clash_updated"])
            self.assertEqual(len(report["clash_unsupported"]), 1)


@unittest.skipUnless(os.environ.get("XRAY_BIN"), "set XRAY_BIN for real proxy integration")
class RealProxyIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.cert = cls.root / "cert.pem"
        cls.key = cls.root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, cls.key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.proxy_port = sock.getsockname()[1]
        config = {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": cls.proxy_port, "protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": "none"}}], "outbounds": [{"protocol": "freedom"}]}
        config_path = cls.root / "server.json"
        config_path.write_text(json.dumps(config))
        cls.core = subprocess.Popen([os.environ["XRAY_BIN"], "run", "-c", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", cls.proxy_port), timeout=.1):
                    break
            except OSError:
                if cls.core.poll() is not None:
                    raise RuntimeError("integration VLESS server failed to start")
                time.sleep(.05)
        cls.settings = {"test_urls": [f"https://127.0.0.1:{cls.server.server_port}/generate_204"], "timeout_seconds": 2, "rounds": 1}

    @classmethod
    def tearDownClass(cls):
        cls.core.terminate()
        cls.core.wait(timeout=5)
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp.cleanup()

    def test_valid_proxy_and_invalid_credentials_against_reachable_https(self):
        good = parse_node(f"vless://{UUID}@127.0.0.1:{self.proxy_port}?type=tcp&security=none")
        bad = parse_node(f"vless://22345678-1234-4234-8234-123456789abc@127.0.0.1:{self.proxy_port}?type=tcp&security=none")
        with patch.dict(os.environ, {"CURL_CA_BUNDLE": str(self.cert), "NO_PROXY": "*"}):
            self.assertEqual(check_node(good, os.environ["XRAY_BIN"], self.settings)["status"], "ok")
            self.assertEqual(check_node(bad, os.environ["XRAY_BIN"], self.settings)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
