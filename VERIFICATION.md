# 验证记录 · 2026-10-19

此文件记录代码交付前的本地验证。GitHub Actions 的在线结果应查看[本仓库工作流记录](https://github.com/ysjsssl/v2ray-daily/actions/workflows/update.yml)，本地测试不证明上游公网节点在 GitHub runner 可用。

- 完整测试命令：`XRAY_BIN=/absolute/path/to/xray python -m unittest discover -s tests -v`。
- 32 项测试全部通过，包括真实的本地 VLESS → HTTPS 204 链路；凭据错误的代理无法通过，设置 `NO_PROXY=*` 也无法绕过代理。
- 失败保护：没有任何成功节点时，已有 V2Ray、Mihomo、状态文件保持原有字节不变。
- 工作流 YAML、UTC/北京时间换算、读写权限与固定 action commit 引用已检查。
- 官方 Xray v26.3.27 二进制经固定 SHA256 校验；TCP、WS、gRPC、XHTTP 的配置通过实际核心加载。
- 导出当天去重后的 65 个配置，官方 Mihomo v1.19.32 通过配置语法检查。语法检查不等于 Mihomo 联网测试。
- 独立审查发现的参数丢失、畸形 VMess 阻断整批、早期数据参数不受核心支持、部分 Mihomo 协议组合不兼容等问题，均用先失败后通过的回归测试覆盖并修复。

## 当天源文件实测

对 `https://clashgithub.com/wp-content/uploads/rss/20261019.txt` 在本次运行环境中的一次检测：

| 项目 | 数量 |
| --- | ---: |
| 原始条目 | 85 |
| 重复连接配置 | 20 |
| 独立配置 | 65 |
| 未通过公网地址或 DNS 预检 | 36 |
| 实际运行 Xray/HTTPS 检测 | 29 |
| 检测通过 | 0 |

因此这次本地检测没有生成订阅文件。上述结果只反映本次运行环境；DNS、IPv6 或网络出口的限制都可能影响结果。应以 GitHub runner 的真实检测结果为准；第一轮检测得到可用节点并成功提交后，固定 raw 地址才会存在。

## 部署配置

工程包含 `.github/workflows/update.yml`，目标为公开仓库 `ysjsssl/v2ray-daily` 的 `main` 分支。默认北京时间每天 09:20 更新，支持手动触发；首次提交代码会触发检测。失败时保留上次结果，首轮无可用节点则暂不创建订阅文件。

检查是否部署成功，应同时确认工作流已存在、定时触发配置存在，以及最近运行的检测/发布结果。固定订阅地址已写入 README；文件不存在或检测失败时不得宣称已有可用订阅。
