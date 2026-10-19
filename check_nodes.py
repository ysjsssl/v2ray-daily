"""Fetch today's subscription, test real proxy tunnels, and stage stable files."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

import yaml

from nodes import MAX_BYTES, decode_subscription, unique_nodes


SOURCE_TEMPLATE = "https://clashgithub.com/wp-content/uploads/rss/{date}.txt"
TZ = ZoneInfo("Asia/Shanghai")


def source_url(now=None):
    now = now or datetime.now(TZ)
    return SOURCE_TEMPLATE.format(date=now.astimezone(TZ).strftime("%Y%m%d"))


def validate_public_server(server):
    try:
        addresses = [ipaddress.ip_address(server)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(server, None, type=socket.SOCK_STREAM)]
        except (OSError, ValueError):
            return False
    return bool(addresses) and all(x.is_global and not x.is_multicast for x in addresses)


def build_curl_command(port, url, timeout):
    return [
        "curl", "--silent", "--show-error", "--fail", "--proxy",
        f"socks5h://127.0.0.1:{port}", "--noproxy", "",
        "--connect-timeout", str(min(5, timeout)), "--max-time", str(timeout),
        "--output", os.devnull, "--write-out", "%{http_code} %{time_total}",
        "--header", "Cache-Control: no-cache", "--url", url,
    ]


def check_node(node, xray, settings):
    result = {"id": node.id, "type": node.kind, "status": "failed"}
    timeout = float(settings.get("timeout_seconds", 10))
    with tempfile.TemporaryDirectory(prefix="node-check-") as temp:
        root = Path(temp)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        outbound = node.xray_outbound()
        outbound["tag"] = "candidate"
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"tag": "probe", "listen": "127.0.0.1", "port": port,
                          "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [outbound],
            "routing": {"rules": [{"type": "field", "inboundTag": ["probe"], "outboundTag": "candidate"}]},
        }
        config_path = root / "config.json"
        config_path.write_text(json.dumps(config))
        process = None
        try:
            process = subprocess.Popen([str(xray), "run", "-c", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ready = False
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    result.update(status="engine_error", reason="core rejected configuration")
                    return result
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        ready = True
                        break
                except OSError:
                    time.sleep(.05)
            if not ready:
                result.update(status="engine_error", reason="core did not start in time")
                return result
            delays = []
            for _ in range(int(settings.get("rounds", 1))):
                for target in settings["test_urls"]:
                    probe = subprocess.run(build_curl_command(port, target, timeout), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout + 3)
                    fields = probe.stdout.split()
                    if probe.returncode or len(fields) != 2 or fields[0] != "204":
                        result["reason"] = "HTTPS 204 probe failed"
                        return result
                    delays.append(round(float(fields[1]) * 1000))
            result.update(status="ok", latency_ms=round(statistics.median(delays)), probes=len(delays))
            return result
        except (OSError, ValueError, subprocess.SubprocessError):
            result.update(status="engine_error", reason="core or probe execution failed")
            return result
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                else:
                    process.wait()


def publish(output, nodes, results, report):
    passed = {r["id"]: r for r in results if r["status"] == "ok"}
    good = sorted((n for n in nodes if n.id in passed), key=lambda n: passed[n.id].get("latency_ms", 0))
    if not good:
        return False
    proxies, excluded = [], []
    for node in good:
        try:
            proxies.append(node.clash_proxy())
        except ValueError:
            excluded.append(node.id)
    report.update(published_nodes=len(good), clash_nodes=len(proxies), clash_updated=bool(proxies), clash_unsupported=excluded)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    contents = {
        "v2ray.txt": base64.b64encode(("\n".join(n.uri for n in good) + "\n").encode()).decode() + "\n",
    }
    if proxies:
        names = [p["name"] for p in proxies]
        config = {
            "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info",
            "proxies": proxies,
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": ["AUTO", *names]},
                {"name": "AUTO", "type": "url-test", "proxies": names,
                 "url": "https://www.gstatic.com/generate_204", "interval": 300},
            ],
            "rules": ["MATCH,PROXY"],
        }
        contents["clash.yaml"] = yaml.safe_dump(config, allow_unicode=True, sort_keys=False)
    contents["status.json"] = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    # GitHub publishes this whole set in one git commit, after the script succeeds.
    with tempfile.TemporaryDirectory(prefix=".stage-", dir=output) as temp:
        stage = Path(temp)
        for name, content in contents.items():
            (stage / name).write_text(content, encoding="utf-8")
        for name in contents:
            os.replace(stage / name, output / name)
    return True


def fetch_subscription(url):
    for attempt in range(3):
        try:
            request = Request(url, headers={"User-Agent": "v2ray-daily/1.0", "Cache-Control": "no-cache"})
            with urlopen(request, timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("subscription exceeds 5 MiB")
            return decode_subscription(data.decode("utf-8-sig"))
        except (URLError, OSError, ValueError, UnicodeError):
            if attempt == 2:
                raise ValueError("subscription unavailable or invalid after three attempts") from None
            time.sleep(3 * (attempt + 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", default="settings.json")
    parser.add_argument("--xray", default="bin/xray")
    parser.add_argument("--source-file", help="test an already downloaded subscription")
    parser.add_argument("--output", default="subscribe")
    parser.add_argument("--report", default=".run/report.json")
    args = parser.parse_args()
    now = datetime.now(TZ)
    report = {"source_url": source_url(now), "source_date": now.strftime("%Y%m%d"),
              "checked_at": now.isoformat(), "status": "failed", "results": []}
    success = False
    try:
        settings = json.loads(Path(args.settings).read_text())
        if not settings.get("test_urls") or not all(x.startswith("https://") for x in settings["test_urls"]):
            raise ValueError("HTTPS test URLs are required")
        if not 1 <= int(settings.get("rounds", 1)) <= 5 or not 1 <= float(settings.get("timeout_seconds", 10)) <= 60:
            raise ValueError("invalid probe limits")
        xray = Path(args.xray).resolve()
        version = subprocess.run([str(xray), "version"], capture_output=True, text=True, timeout=5, check=True)
        report["core_version"] = version.stdout.splitlines()[0][:120]
        uris = decode_subscription(Path(args.source_file).read_text()) if args.source_file else fetch_subscription(report["source_url"])
        nodes, skipped = unique_nodes(uris)
        report.update(input_entries=len(uris), unique_candidates=len(nodes))
        results = list(skipped)
        workers = max(1, min(int(settings.get("workers", 8)), 16))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for node in nodes:
                if validate_public_server(node.server):
                    futures[pool.submit(check_node, node, xray, settings)] = node.id
                else:
                    results.append({"id": node.id, "type": node.kind, "status": "rejected", "reason": "non-public endpoint or DNS lookup failed"})
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                print(f"{result['id']} {result['status']}", flush=True)
        report["results"] = results
        report["tested_nodes"] = sum(r["status"] in {"ok", "failed", "engine_error"} for r in results)
        if any(r["status"] == "ok" for r in results):
            report.update(status="published", updated_at=datetime.now(TZ).isoformat())
            success = publish(Path(args.output), nodes, results, report)
        else:
            report["reason"] = "No usable nodes; prior subscription files retained"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        report.update(status="failed", reason="Fetch, settings, or engine failure; prior subscriptions retained")
    finally:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        summary = f"Status: {report['status']}; input: {report.get('input_entries', 0)}; tested: {report.get('tested_nodes', 0)}; published: {report.get('published_nodes', 0)}"
        print(summary, flush=True)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
                stream.write(summary + "\n\nSee the node-check-report artifact for this run's detailed results.\n")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
