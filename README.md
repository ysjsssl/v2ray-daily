# 每日筛选 V2Ray 订阅 · GitHub Actions

每天按北京时间拼接订阅日期，用 Xray 实际连接节点，输出地址固定的 V2Ray 与 Mihomo 订阅。原始来源：

```text
https://clashgithub.com/wp-content/uploads/rss/YYYYMMDD.txt
```

## 部署

1. 在自己的 GitHub 账户下新建一个 **Public** 仓库，例如 `v2ray-daily`，默认分支使用 `main`。公开仓库的 raw 地址可供普通订阅客户端直接下载；私有仓库需要另配鉴权或托管。
2. 把本工程的所有文件放在仓库根目录，务必包含 `.github/workflows/update.yml`。不要把整个 `v2ray-daily` 目录再套在仓库里面。也可以把空仓库链接发给协助部署的助手，并让 GitHub 连接获得该仓库访问权限。
3. 确认仓库的 Actions 已启用；若策略禁止工作流写入，在 **Settings → Actions → General → Workflow permissions** 允许读写。工作流已声明 `contents: write`，通常无需个人访问令牌。若账户或组织策略禁用写入，需由拥有者调整。
4. 打开 **Actions → Update verified subscription → Run workflow**。首次上传代码也会触发；等待检测和发布步骤全部成功后再导入订阅链接。

拥有 GitHub CLI 时，也可从本工程目录执行：

```bash
gh auth login
git init -b main
git add .
git commit -m "Set up daily subscription filtering"
gh repo create v2ray-daily --public --source=. --remote=origin --push
```

如果本地已经是 git 仓库，沿用现有仓库提交与推送即可，不必再次初始化。

## 固定订阅地址

本仓库为 `ysjsssl/v2ray-daily`，默认分支为 `main`。以下地址在首轮检测得到可用节点并成功发布后生效：

| 用途 | 固定 URL |
| --- | --- |
| V2Ray / v2rayN / 支持 URI 订阅的客户端 | `https://raw.githubusercontent.com/ysjsssl/v2ray-daily/main/subscribe/v2ray.txt` |
| Mihomo / 使用 Mihomo 内核的 Clash 或 OpenClash | `https://raw.githubusercontent.com/ysjsssl/v2ray-daily/main/subscribe/clash.yaml` |
| 最近成功发布状态 | `https://raw.githubusercontent.com/ysjsssl/v2ray-daily/main/subscribe/status.json` |

默认分支不是 `main` 时需替换地址中的分支。成功发布后的 Actions 摘要会显示本仓库实际地址。第一次没有测出任何可用节点时不会创建空订阅，地址会暂时返回 404；稍后可重新运行工作流。

原版旧 Clash 内核不支持 VLESS。VLESS 的 XHTTP 需要较新的 Mihomo；已按当前官方配置文档导出基础 `path`、`host`、`mode`。包含复杂 `extra`、不能无损转换的 gRPC 选项、明文 Trojan、Trojan/VMess 的 XHTTP 等节点仍可进入 V2Ray 订阅，但会从 Mihomo 输出中排除，并在报告中列出节点 ID。若本轮没有可转换节点，保留旧的 Mihomo 文件，`clash_updated` 会标为 `false`。实际联网检测使用 Xray；Mihomo 文件来自参数映射，客户端内核版本与网络仍会影响使用结果。

客户端自动更新间隔建议设为 6–12 小时。GitHub raw 有缓存，推送后可能不会立即读到新内容；在无法访问 GitHub raw 的网络中，需要自行解决该订阅地址的可达性。

## 默认运行规则

- 定时：北京时间每天 **09:20**，对应工作流 `20 1 * * *`（UTC）。GitHub 可能排队延迟，不能保证精确到分钟。
- 手动重试：Actions 中点击 **Run workflow**。
- 原始源下载：最多重试三次，只使用当天文件；当日源尚未发布或返回 HTML 时本轮失败，保留上次订阅。
- 相同连接配置但名称不同的节点去重；不同凭据、TLS 或传输参数分别测试。
- 每个候选节点独立运行 Xray，curl 强制使用 SOCKS5 代理与远端 DNS。
- 以下两个 HTTPS 地址都返回 **204** 才通过；测试目标的 HTTPS 证书仍由 curl 校验，不跟随跳转。
  - `https://www.gstatic.com/generate_204`
  - `https://cp.cloudflare.com/generate_204`
- 超时 10 秒，并发 8，可在 `settings.json` 中调整；`rounds: 2` 表示每个地址再重复一次，必须全部成功。
- 私网、回环、文档示例地址和 DNS 解析失败的节点不会连接。未知协议或无法保留的传输参数会记为 `unsupported`，不会伪装成已测失败。
- 当前版本不处理 WS/HTTPUpgrade 的早期数据 `ed`/`eh`、`packetEncoding` 或 SS 的额外传输封装；有这些非空参数的条目会明确排除。VMess 的未知连接字段也会明确排除，不会静默改成默认参数。
- 下载异常、核心异常、零节点通过时，工作流失败并保留之前的订阅。逐节点状态保存在本次 **node-check-report** artifact；公开的 `status.json` 始终对应最近一次成功发布。

检测反映 **GitHub runner 所在网络在检测时的 TCP/HTTPS 可用性**。没有测试 UDP、带宽、长期稳定性和特定网站解锁，不能保证从你的本地网络也能连接。公开免费节点可能很快失效，因此这里每天重新测量。

## 修改时间与参数

例如希望北京时间每天 18:20，修改 `.github/workflows/update.yml`：

```yaml
schedule:
  - cron: '20 10 * * *'  # UTC 10:20 = 北京时间 18:20
```

`settings.json` 的测试地址必须是预期返回 204 的 HTTPS 地址；`timeout_seconds` 范围 1–60，`rounds` 范围 1–5，`workers` 最大 16。若两个测试地址中的一个整体故障，即使代理本身能用也会被剔除，可更换测试地址再运行。

## 本地验证

仅适用 Linux amd64，需 Python 3.12、curl、openssl：

```bash
python -m pip install -r requirements.txt
python download_xray.py
XRAY_BIN="$PWD/bin/xray" python -m unittest discover -s tests -v
python check_nodes.py
```

核心来自官方 Xray **v26.3.27**，下载脚本校验固定 SHA256；更新核心版本时同时更新版本和官方校验值。测试包含真实的本地 VLESS → HTTPS 链路：正确凭据通过，错误凭据失败，即使环境变量 `NO_PROXY=*` 也不能绕过候选代理。

## 参考

- [GitHub schedule 事件与运行限制](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [GitHub 工作流 token 权限](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [Xray 官方版本](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)
- [Xray VLESS 配置](https://xtls.github.io/config/outbounds/vless.html)
- [Mihomo VLESS 与传输层](https://wiki.metacubex.one/config/proxies/vless/)
- [Mihomo XHTTP 配置](https://wiki.metacubex.one/config/proxies/transport/#xhttp-opts)

GitHub 官方说明：公开仓库连续 60 天没有仓库活动时，定时工作流可能被自动禁用。正常成功更新会持续产生订阅提交；若上游长期失效，应定期检查 Actions 状态并在需要时重新启用。
