# 红果桌面版 · macOS 分支

红果短剧桌面播放器的 macOS 移植（[上游 Windows 发行页](https://github.com/waligoraamodio288-rgb/hongguo-desktop-releases) · [dddmiku 本地维护分支](https://github.com/dddmiku/hongguo-desktop-releases)，后端源码来自 [zhangbaio/hongguo](https://github.com/zhangbaio/hongguo) 生态）。

**不是移植 Windows exe**——Tauri 壳不跨平台，本分支直接跑原生组件：

| 组件 | Windows 版 | macOS 版 |
|---|---|---|
| 外壳 | Tauri 2 (Rust exe) | 浏览器（Safari/Chrome 访问 `http://127.0.0.1:8787/ui`） |
| 后端 | FastAPI (Python embeddable) | FastAPI (uv venv, Python 3.11+) |
| 签名服务 | unidbg jar (JRE 随包) | **同一 jar 原样跑在 macOS JDK17 上**（unidbg 是纯 Java 安卓模拟层，无 Windows 依赖） |
| 前端 | exe 内嵌 React | 上游 server 版 web UI（`backend/web/`，同源直连 API） |
| 设备身份 | device-bundled.json | 同一文件复用 |

已在本机（Apple M4, macOS 27, arm64）端到端实测：搜索 → 选集 → 解密串流全通。1080p H.264+AAC，首次约 34s（下载+解密），缓存后 0.7s，支持 Range 拖动。

## 快速开始

前置：Python 3.11+（`uv` 或 pip）、JDK 17+（`brew install --cask temurin`，或把 JDK 放 `../runtime/jdk*.jdk`）。

```bash
./start.sh            # 首次自动建 venv + 装依赖, 起 signer + API, 自动开浏览器
./start.sh 9000       # 指定端口
```

打开 `http://127.0.0.1:8787/ui` 即可用——本机回环客户端免 api_key（服务只绑 127.0.0.1，同机进程本可读 `data/session-key.txt`，鉴权对它不构成边界；限流保留，非回环来源仍要求 key）。若 UI 的 api_key 框留有旧值请清空。

## 与 Windows 版的差异/裁剪

- **无老板键/托盘**：那是 Tauri 壳的功能；浏览器版用 Cmd+H/Cmd+Q。
- **无 `/desktop/hls` 会话播放器**：用 `/stream` 直链（`<video src>` 可播、可拖动）。HLS 管线代码在（`desktop_hls*.py`），如需接入 React 前端可后补。
- **无自动更新**：`/desktop/update/*` 指向 dddmiku 的 Windows exe，macOS 版忽略。
- **账号同步未接**：`desktop_account*.py` 是 dddmiku 为 Windows 加的（扫码登录/进度同步），依赖其 Rust 壳 IPC；后端路由在，未验证。
- `os.startfile`（Windows 打开文件）等 3 处 Windows 调用在 `/stream` 链路上不被触及，无需改动。

## 目录

```
start.sh              # 入口
start_mac.py          # macOS 启动器: 起 unidbg signer + uvicorn, 浏览器打开 /ui
backend/              # dddmiku 1.3.2 后端源码 + sign/unidbg-sign.jar + capture/ so + device-bundled.json
backend/web/          # 上游 server 版 web UI (index.html/admin.html)
data/                 # 运行时生成: content-config.json, session-key.txt, stream-cache/
```

## 已知坑

- signer 的 cwd 必须是 `backend/sign/`（unidbg 以相对路径加载 `../capture` 的 so），`start_mac.py` 已处理。
- macOS `/usr/bin/java` 是 stub（本机无 JVM 时 exec 报错），`find_java()` 会跳过它。
- GitHub 下载 release 附件常限速（本机实测 ~300KB/s），`unidbg-sign.jar` 32MB 已随仓库，无需另下。

## 法律

仅供个人学习研究。红果品牌与剧集内容归字节跳动/权利方所有；签名 jar 与设备身份文件来自公开发行的 Windows 安装包，版权归原作者。请勿用于商业用途或大规模分发。
