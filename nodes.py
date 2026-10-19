"""Parse subscription URIs locally and preserve connection semantics."""

import base64
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit


MAX_BYTES = 5 * 1024 * 1024
MAX_NODES = 2000
QUERY_FIELDS = {
    "type", "encryption", "security", "sni", "serverName", "fp", "flow",
    "alpn", "allowInsecure", "insecure", "host", "path", "serviceName",
    "mode", "authority", "pbk", "sid", "spx", "headerType", "extra",
    "plugin", "group", "remarks",
}
VMESS_FIELDS = {
    "v", "ps", "add", "port", "id", "aid", "scy", "net", "type",
    "host", "path", "tls", "sni", "alpn", "fp", "allowInsecure",
}


def unbase64(value):
    value = re.sub(r"\s+", "", value)
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode("utf-8-sig")


def decode_subscription(text):
    if len(text.encode()) > MAX_BYTES:
        raise ValueError("subscription exceeds 5 MiB")
    text = text.strip().lstrip("\ufeff")
    if not re.search(r"(?m)^[a-z][a-z0-9+.-]*://", text):
        try:
            text = unbase64(text)
        except (ValueError, UnicodeError):
            raise ValueError("not a URI list or Base64 subscription") from None
    lines = [x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")]
    if not lines or len(lines) > MAX_NODES or any(len(x) > 16384 for x in lines):
        raise ValueError("empty or oversized subscription")
    return lines


def display_name(value, fallback):
    return re.sub(r"[\x00-\x1f\x7f]", " ", unquote(str(value or fallback)))[:120]


@dataclass
class Node:
    uri: str
    kind: str
    name: str
    server: str
    port: int
    auth: dict
    params: dict

    @property
    def id(self):
        normalized = json.dumps(self.xray_outbound(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def xray_outbound(self):
        if self.kind == "ss":
            return {"protocol": "shadowsocks", "settings": {"servers": [{
                "address": self.server, "port": self.port, **self.auth,
            }]}}
        p = self.params
        network = p.get("type") or "tcp"
        security = p.get("security") or ("tls" if self.kind == "trojan" else "none")
        stream = {"network": network, "security": security}
        server_name = p.get("sni") or p.get("serverName") or self.server
        insecure = (p.get("allowInsecure") or p.get("insecure")) in {"1", "true"}
        if security == "tls":
            tls = {"serverName": server_name, "allowInsecure": insecure}
            if p.get("fp"):
                tls["fingerprint"] = p["fp"]
            if p.get("alpn"):
                tls["alpn"] = p["alpn"].split(",")
            stream["tlsSettings"] = tls
        elif security == "reality":
            stream["realitySettings"] = {
                "serverName": server_name, "fingerprint": p.get("fp") or "chrome",
                "publicKey": p.get("pbk", ""), "shortId": p.get("sid", ""),
                "spiderX": p.get("spx") or "/",
            }
        if network in {"ws", "httpupgrade"}:
            opt = {"path": p.get("path") or "/"}
            if p.get("host"):
                opt["host" if network == "httpupgrade" else "headers"] = p["host"] if network == "httpupgrade" else {"Host": p["host"]}
            stream["wsSettings" if network == "ws" else "httpupgradeSettings"] = opt
        elif network == "grpc":
            stream["grpcSettings"] = {"serviceName": p.get("serviceName", ""), "multiMode": p.get("mode") == "multi"}
            if p.get("authority"):
                stream["grpcSettings"]["authority"] = p["authority"]
        elif network == "xhttp":
            opt = {"path": p.get("path") or "/", "host": p.get("host", ""), "mode": p.get("mode") or "auto"}
            if p.get("extra"):
                opt["extra"] = json.loads(p["extra"])
                if not isinstance(opt["extra"], dict):
                    raise ValueError("XHTTP extra must be an object")
            stream["xhttpSettings"] = opt
        if self.kind == "trojan":
            settings = {"servers": [{"address": self.server, "port": self.port, "password": self.auth["password"]}]}
        else:
            user = {"id": self.auth["id"]}
            if self.kind == "vless":
                user.update(encryption=p.get("encryption") or "none")
                if p.get("flow"):
                    user["flow"] = p["flow"]
            else:
                user.update(security=self.auth.get("cipher", "auto"), alterId=self.auth.get("alterId", 0))
            settings = {"vnext": [{"address": self.server, "port": self.port, "users": [user]}]}
        return {"protocol": self.kind, "settings": settings, "streamSettings": stream}

    def clash_proxy(self):
        p = self.params
        proxy = {"name": f"{self.name} [{self.id[:6]}]", "type": self.kind, "server": self.server, "port": self.port, "udp": True}
        if self.kind == "ss":
            proxy.update(cipher=self.auth["method"], password=self.auth["password"])
            return proxy
        network = p.get("type") or "tcp"
        security = p.get("security") or ("tls" if self.kind == "trojan" else "none")
        if p.get("extra") or p.get("authority") or (network == "grpc" and p.get("mode") == "multi"):
            raise ValueError("transport options cannot be converted without loss")
        if (self.kind == "trojan" and security == "none") or (network == "xhttp" and self.kind != "vless"):
            raise ValueError("protocol and transport combination is unsupported by Mihomo")
        proxy.update(network="ws" if network == "httpupgrade" else network, tls=security in {"tls", "reality"})
        if self.kind == "trojan":
            proxy["password"] = self.auth["password"]
        else:
            proxy["uuid"] = self.auth["id"]
        if self.kind == "vmess":
            proxy.update(alterId=self.auth.get("alterId", 0), cipher=self.auth.get("cipher", "auto"))
        if p.get("flow"):
            proxy["flow"] = p["flow"].removesuffix("-udp443")
        if p.get("encryption") and p["encryption"] != "none":
            proxy["encryption"] = p["encryption"]
        if proxy["tls"]:
            proxy["servername"] = p.get("sni") or p.get("serverName") or self.server
            if self.kind == "trojan":
                proxy["sni"] = proxy["servername"]
            proxy["skip-cert-verify"] = (p.get("allowInsecure") or p.get("insecure")) in {"1", "true"}
            if p.get("fp") or security == "reality":
                proxy["client-fingerprint"] = p.get("fp") or "chrome"
            if p.get("alpn"):
                proxy["alpn"] = p["alpn"].split(",")
        if security == "reality":
            proxy["reality-opts"] = {"public-key": p.get("pbk", ""), "short-id": p.get("sid", "")}
        if network in {"ws", "httpupgrade"}:
            opt = {"path": p.get("path") or "/"}
            if p.get("host"):
                opt["headers"] = {"Host": p["host"]}
            if network == "httpupgrade":
                opt["v2ray-http-upgrade"] = True
            proxy["ws-opts"] = opt
        elif network == "grpc":
            proxy["grpc-opts"] = {"grpc-service-name": p.get("serviceName", "")}
        elif network == "xhttp":
            proxy["xhttp-opts"] = {"path": p.get("path") or "/", "host": p.get("host", "")}
            if p.get("mode") and p["mode"] != "auto":
                proxy["xhttp-opts"]["mode"] = p["mode"]
            if not p.get("alpn"):
                proxy["alpn"] = ["h2"]
        return proxy


def parse_node(uri):
    if len(uri) > 16384:
        raise ValueError("oversized node")
    u = urlsplit(uri)
    kind = u.scheme.lower()
    if kind not in {"vless", "vmess", "ss", "trojan"}:
        raise ValueError("unsupported protocol")
    if kind == "vmess":
        v = json.loads(unbase64(uri.partition("://")[2].split("#")[0]))
        if not isinstance(v, dict):
            raise ValueError("VMess payload must be an object")
        if any(k not in VMESS_FIELDS and value is not None and value != "" for k, value in v.items()):
            raise ValueError("unsupported VMess parameter")
        if v.get("type") not in {None, "", "none"}:
            raise ValueError("unsupported VMess header")
        p = {"type": v.get("net") or "tcp", "security": v.get("tls") or "none"}
        p.update({k: str(v[k]) for k in ["host", "path", "sni", "alpn", "fp"] if v.get(k)})
        if "allowInsecure" in v:
            p["allowInsecure"] = str(v["allowInsecure"]).lower()
        if p["type"] == "grpc":
            p["serviceName"] = v.get("path", "")
        n = Node(uri, kind, display_name(v.get("ps"), kind), str(v["add"]), int(v["port"]), {"id": str(v["id"]), "cipher": v.get("scy") or "auto", "alterId": int(v.get("aid") or 0)}, p)
    else:
        q = parse_qs(u.query, keep_blank_values=True)
        if any(len(v) != 1 for v in q.values()):
            raise ValueError("duplicate query parameters")
        p = {k: v[0] for k, v in q.items()}
        if any(k not in QUERY_FIELDS and v for k, v in p.items()):
            raise ValueError("unsupported query parameter")
        if p.get("plugin") or p.get("headerType") not in {None, "", "none"}:
            raise ValueError("unsupported plugin or transport header")
        if kind == "ss":
            if p.get("type") not in {None, "", "tcp", "raw"} or p.get("security") not in {None, "", "none"} or any(value for k, value in p.items() if k not in {"type", "security", "group", "remarks"}):
                raise ValueError("unsupported Shadowsocks transport parameters")
            authority = uri.partition("://")[2].split("#", 1)[0].split("?", 1)[0].rstrip("/")
            if "@" not in authority:
                authority = unbase64(authority)
            auth_part, _, endpoint = authority.rpartition("@")
            auth_part = unquote(auth_part)
            if ":" not in auth_part:
                auth_part = unbase64(auth_part)
            method, sep, password = auth_part.partition(":")
            target = urlsplit("ss://" + endpoint)
            if not sep or not password:
                raise ValueError("invalid SS credentials")
            n = Node(uri, kind, display_name(u.fragment, kind), target.hostname or "", target.port or 0, {"method": method, "password": password}, p)
        else:
            auth = unquote(u.username or "")
            if not auth:
                raise ValueError("missing credentials")
            n = Node(uri, kind, display_name(u.fragment, kind), u.hostname or "", u.port or 0, {"password" if kind == "trojan" else "id": auth}, p)
    if not n.server or not 1 <= n.port <= 65535:
        raise ValueError("invalid endpoint")
    if n.params.get("type", "tcp") not in {"", "tcp", "raw", "ws", "grpc", "xhttp", "httpupgrade"}:
        raise ValueError("unsupported transport")
    if n.params.get("type") == "raw":
        n.params["type"] = "tcp"
    if n.params.get("type") in {"ws", "httpupgrade"}:
        path_query = parse_qs(urlsplit(n.params.get("path") or "").query, keep_blank_values=True)
        if path_query.get("ed"):
            raise ValueError("embedded early-data options are unsupported")
    if n.params.get("security", "none") not in {"", "none", "tls", "reality"}:
        raise ValueError("unsupported transport security")
    n.xray_outbound()
    return n


def unique_nodes(uris):
    nodes, reports, seen = [], [], set()
    for index, uri in enumerate(uris, 1):
        try:
            node = parse_node(uri)
            if node.id in seen:
                reports.append({"index": index, "id": node.id, "status": "duplicate"})
            else:
                seen.add(node.id)
                nodes.append(node)
        except (ValueError, KeyError, TypeError, UnicodeError, OverflowError, RecursionError):
            reports.append({"index": index, "status": "unsupported", "reason": "invalid or unsupported node parameters"})
    return nodes, reports
