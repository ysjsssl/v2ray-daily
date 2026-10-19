import base64
import json
import unittest

from nodes import decode_subscription, parse_node, unique_nodes


UUID = "12345678-1234-4234-8234-123456789abc"


class SubscriptionTests(unittest.TestCase):
    def test_base64_and_plain_have_same_lines(self):
        text = f"vless://{UUID}@node.example:443?security=tls#one\n"
        encoded = base64.b64encode(text.encode()).decode().rstrip("=")
        self.assertEqual(decode_subscription(encoded), decode_subscription(text))

    def test_html_is_rejected(self):
        with self.assertRaises(ValueError):
            decode_subscription("<!doctype html><h1>error</h1>")

    def test_encoded_shadowsocks_credentials(self):
        n = parse_node("ss://aes-128-gcm%3Apass%3Aword@node.example:443#ss")
        server = n.xray_outbound()["settings"]["servers"][0]
        self.assertEqual(server["password"], "pass:word")
        self.assertEqual(n.clash_proxy()["cipher"], "aes-128-gcm")

    def test_sip002_base64_credentials(self):
        auth = base64.urlsafe_b64encode(b"aes-256-gcm:password").decode().rstrip("=")
        n = parse_node(f"ss://{auth}@[2001:4860:4860::8888]:443#ss")
        self.assertEqual(n.server, "2001:4860:4860::8888")
        self.assertEqual(n.clash_proxy()["password"], "password")

    def test_ipv6_tls_and_vision_preserved(self):
        n = parse_node(f"vless://{UUID}@[2001:4860:4860::8888]:443?type=tcp&security=tls&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision#v6")
        ob = n.xray_outbound()
        self.assertEqual(ob["streamSettings"]["tlsSettings"]["serverName"], "www.example.com")
        self.assertEqual(ob["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(n.clash_proxy()["server"], "2001:4860:4860::8888")

    def test_reality_fields_preserved(self):
        n = parse_node(f"vless://{UUID}@node.example:443?security=reality&pbk=public-key&sid=abcd&sni=www.example.com&fp=chrome#reality")
        reality = n.xray_outbound()["streamSettings"]["realitySettings"]
        self.assertEqual(reality["publicKey"], "public-key")
        self.assertEqual(n.clash_proxy()["reality-opts"]["short-id"], "abcd")

    def test_xhttp_path_host_and_mode_preserved(self):
        n = parse_node(f"vless://{UUID}@node.example:443?type=xhttp&security=tls&path=%2Fmy%3Fx%3D1&host=front.example&mode=packet-up#xhttp")
        self.assertEqual(n.xray_outbound()["streamSettings"]["xhttpSettings"]["path"], "/my?x=1")
        self.assertEqual(n.clash_proxy()["xhttp-opts"]["host"], "front.example")
        self.assertEqual(n.clash_proxy()["xhttp-opts"]["mode"], "packet-up")

    def test_xhttp_extra_is_kept_but_lossy_clash_conversion_rejected(self):
        n = parse_node(f"vless://{UUID}@node.example:443?type=xhttp&security=tls&extra=%7B%22noGRPCHeader%22%3Atrue%7D#x")
        self.assertTrue(n.xray_outbound()["streamSettings"]["xhttpSettings"]["extra"]["noGRPCHeader"])
        with self.assertRaises(ValueError):
            n.clash_proxy()

    def test_unknown_transport_parameter_is_reported(self):
        _, errors = unique_nodes([f"vless://{UUID}@node.example:443?security=tls&newTransportSecret=value"])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["status"], "unsupported")
        self.assertNotIn(UUID, json.dumps(errors))

    def test_same_configuration_different_names_deduplicated(self):
        a = f"vless://{UUID}@node.example:443?type=tcp&security=tls#one"
        b = f"vless://{UUID}@node.example:443?security=tls&type=tcp#two"
        nodes, errors = unique_nodes([a, b])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(errors[0]["status"], "duplicate")

    def test_different_credentials_not_deduplicated(self):
        a = f"vless://{UUID}@node.example:443?security=tls#one"
        b = "vless://22345678-1234-4234-8234-123456789abc@node.example:443?security=tls#one"
        self.assertEqual(len(unique_nodes([a, b])[0]), 2)

    def test_vmess_websocket_mapping(self):
        vmess = {"v": "2", "ps": "vmess", "add": "node.example", "port": "443", "id": UUID, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "front.example", "path": "/ws", "tls": "tls", "sni": "tls.example"}
        uri = "vmess://" + base64.b64encode(json.dumps(vmess).encode()).decode()
        n = parse_node(uri)
        self.assertEqual(n.clash_proxy()["ws-opts"]["path"], "/ws")
        self.assertEqual(n.xray_outbound()["protocol"], "vmess")

    def test_trojan_password_kept(self):
        n = parse_node("trojan://p%40ssword@node.example:443?sni=front.example#trojan")
        self.assertEqual(n.clash_proxy()["password"], "p@ssword")
        self.assertTrue(n.clash_proxy()["tls"])

    def test_insecure_option_remains_in_original_uri(self):
        n = parse_node(f"vless://{UUID}@node.example:443?security=tls&allowInsecure=1")
        self.assertIn("allowInsecure=1", n.uri)
        self.assertTrue(n.xray_outbound()["streamSettings"]["tlsSettings"]["allowInsecure"])

    def test_ss_transport_options_are_not_silently_discarded(self):
        with self.assertRaises(ValueError):
            parse_node("ss://aes-128-gcm:password@node.example:443?type=ws&security=tls&path=%2Fproxy")

    def test_malformed_vmess_container_does_not_abort_other_nodes(self):
        good = f"vless://{UUID}@node.example:443?security=tls"
        nodes, errors = unique_nodes(["vmess://W10=", good])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(errors[0]["status"], "unsupported")

    def test_unknown_vmess_connection_field_is_reported(self):
        v = {"add": "node.example", "port": 443, "id": UUID, "net": "ws", "tls": "tls", "customTransportOption": "required"}
        uri = "vmess://" + base64.b64encode(json.dumps(v).encode()).decode()
        with self.assertRaises(ValueError):
            parse_node(uri)

    def test_vmess_allow_insecure_is_preserved(self):
        v = {"add": "node.example", "port": 443, "id": UUID, "net": "tcp", "tls": "tls", "allowInsecure": True}
        uri = "vmess://" + base64.b64encode(json.dumps(v).encode()).decode()
        n = parse_node(uri)
        self.assertTrue(n.xray_outbound()["streamSettings"]["tlsSettings"]["allowInsecure"])
        self.assertTrue(n.clash_proxy()["skip-cert-verify"])

    def test_packet_encoding_not_supported_by_tester_is_reported(self):
        with self.assertRaises(ValueError):
            parse_node(f"vless://{UUID}@node.example:443?security=tls&packetEncoding=packetaddr")

    def test_early_data_settings_not_implemented_by_pinned_core_are_reported(self):
        for query in ["ed=2048", "eh=Sec-WebSocket-Protocol", "path=%2Fws%3Fed%3D2048"]:
            with self.subTest(query=query), self.assertRaises(ValueError):
                parse_node(f"vless://{UUID}@node.example:443?security=tls&type=ws&{query}")

    def test_plain_trojan_not_exported_as_forced_tls_in_mihomo(self):
        n = parse_node("trojan://password@node.example:443?security=none")
        self.assertEqual(n.xray_outbound()["streamSettings"]["security"], "none")
        with self.assertRaises(ValueError):
            n.clash_proxy()

    def test_xhttp_for_non_vless_not_silently_exported_as_tcp(self):
        n = parse_node("trojan://password@node.example:443?security=tls&type=xhttp")
        with self.assertRaises(ValueError):
            n.clash_proxy()
        v = {"add": "node.example", "port": 443, "id": UUID, "net": "xhttp", "tls": "tls"}
        n = parse_node("vmess://" + base64.b64encode(json.dumps(v).encode()).decode())
        with self.assertRaises(ValueError):
            n.clash_proxy()

    def test_overflowing_vmess_port_does_not_abort_other_nodes(self):
        v = {"add": "node.example", "port": float("inf"), "id": UUID}
        bad = "vmess://" + base64.b64encode(json.dumps(v).encode()).decode()
        nodes, errors = unique_nodes([bad, f"vless://{UUID}@node.example:443?security=tls"])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(errors[0]["status"], "unsupported")

    def test_non_string_vmess_label_does_not_abort_valid_connection(self):
        v = {"add": "node.example", "port": 443, "id": UUID, "ps": 123}
        uri = "vmess://" + base64.b64encode(json.dumps(v).encode()).decode()
        self.assertEqual(parse_node(uri).name, "123")


if __name__ == "__main__":
    unittest.main()
