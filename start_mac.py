# -*- coding: utf-8 -*-
"""macOS 启动器: 起 unidbg 签名服务 + FastAPI 后端, 浏览器访问 http://127.0.0.1:8787/ui

与 Windows 版 desktop_bootstrap.py 的区别:
  - 不再走 Tauri 壳的 stdin/stdout 握手, 直接前台可用
  - java 可执行文件用 JAVA_HOME 或系统 java
  - /desktop/update/* 已无关(没有 exe), 忽略其失败
用法: python3 start_mac.py [--port 8787] [--java /path/to/java]
"""
import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE / "backend"
DATA = HERE / "data"


def find_java():
    """优先级: HONGGUO_JAVA env > repo 内置 JDK > ~/tools/jdk* > 系统 java(须真能跑)。"""
    import shutil
    cands = []
    env = os.environ.get("HONGGUO_JAVA")
    if env:
        cands.append(env)
    here = Path(__file__).resolve().parent
    for pat in ("runtime/jdk*/Contents/Home/bin/java",
                "../runtime/jdk*/Contents/Home/bin/java",
                "jdk*/Contents/Home/bin/java",
                "jre/Contents/Home/bin/java"):
        cands.extend(str(p) for p in sorted(here.glob(pat)))
    cands.extend(sorted(Path.home().glob("tools/jdk*/Contents/Home/bin/java")))
    sys_java = shutil.which("java")
    if sys_java:
        cands.append(sys_java)
    for cand in cands:
        if not cand:
            continue
        if "/" in cand and not Path(cand).exists():
            continue
        # 必须真能执行(排除 macOS /usr/bin/java stub)
        try:
            r = subprocess.run([cand, "-version"], capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and "Unable to locate" not in (r.stderr or "") + (r.stdout or ""):
                return cand
        except Exception:
            continue
    return None


def signer_port_ready_probe(port, timeout=2.0):
    return None


def wait_port_by_pid(pid, timeout=60):
    """等 pid 进程出现监听端口(lsof)。返回端口或 None。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-a", "-p", str(pid)],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    addr = parts[8]
                    if addr.endswith(":*"):
                        continue
                    if ":" in addr:
                        try:
                            return int(addr.rsplit(":", 1)[1])
                        except ValueError:
                            pass
        except Exception:
            pass
        process_alive = subprocess.run(["kill", "-0", str(pid)], capture_output=True).returncode == 0
        if not process_alive:
            return None
        time.sleep(0.3)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--java", default=None)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    DATA.mkdir(exist_ok=True)

    # 1) 内容配置(设备身份) — 用随包 guest-config + bundled 设备身份合并
    cfg_path = DATA / "content-config.json"
    cfg = json.loads((BACKEND / "guest-config.json").read_text(encoding="utf-8"))
    # 合并 device-bundled 身份字段进 base_query
    try:
        dev = json.loads((BACKEND / "device-bundled.json").read_text(encoding="utf-8"))
        for k in ("device_id", "iid", "cdid", "channel", "openudid", "udid"):
            if dev.get(k):
                cfg["base_query"][k] = dev[k]
        # 设备池文件 devicepool 用的字段
        (DATA / "device-bundled.json").write_text(json.dumps(dev, ensure_ascii=False, indent=1),
                                                  encoding="utf-8")
    except FileNotFoundError:
        print("[start] 警告: 缺 device-bundled.json, 使用 guest-config 原样")
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=1), encoding="utf-8")

    # 2) 环境变量(对齐 Windows bootstrap 的关键项)
    session_key = secrets.token_hex(32)
    # 固定 key 落盘: web UI 需要输入 api_key; 本机文件, 权限 600
    key_file = DATA / "session-key.txt"
    if key_file.is_file():
        session_key = key_file.read_text(encoding="utf-8").strip()
        if len(session_key) != 64 or any(c not in "0123456789abcdef" for c in session_key):
            session_key = secrets.token_hex(32)
            key_file.write_text(session_key, encoding="utf-8")
    else:
        key_file.write_text(session_key, encoding="utf-8")
    key_file.chmod(0o600)
    os.environ["HONGGUO_SESSION_API_KEY"] = session_key
    os.environ["HONGGUO_CONTENT_CONFIG"] = str(cfg_path)
    os.environ["HONGGUO_BACKEND_DATA_DIR"] = str(DATA)
    os.environ["BIND_HOST"] = "127.0.0.1"
    os.environ["HONGGUO_STREAM_CACHE"] = str(DATA / "stream-cache")
    os.environ["IMPERSONATE"] = ""
    os.environ["DEVICE_POOL_SIZE"] = "0"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(name, None)
    os.environ.pop("SIGN_SERVER", None)

    os.makedirs(str(DATA / "stream-cache"), exist_ok=True)

    # 3) 起 JVM 签名服务
    java = args.java or find_java()
    if not java:
        print("[start] 找不到 java, 请装 JDK17+(brew install --cask temurin) 或 --java 指定")
        sys.exit(1)
    # 签名服务的 cwd 必须是 backend/sign: unidbg 以相对路径加载 ../capture 或 ./capture 的 so
    sign_dir = BACKEND / "sign"
    jar = sign_dir / "unidbg-sign.jar"
    if not jar.is_file():
        jar = BACKEND / "unidbg-sign.jar"
        sign_dir = BACKEND
    print(f"[start] java={java}")
    signer = subprocess.Popen(
        [java, "-Djava.net.preferIPv4Stack=true", "--add-opens", "java.base/java.lang=ALL-UNNAMED",
         "-Xmx512m", "-cp", str(jar), "com.hongguo.sign.FqTrace", "serve", "0"],
        cwd=str(sign_dir), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(f"[start] signer pid={signer.pid}, 等端口…")
    signer_port = wait_port_by_pid(signer.pid, timeout=90)
    if not signer_port:
        signer.kill()
        print("[start] 签名服务起不来; 见上")
        sys.exit(1)
    os.environ["SIGN_SERVER"] = f"http://127.0.0.1:{signer_port}"
    print(f"[start] signer ok @ http://127.0.0.1:{signer_port}")

    # 4) 起后端(uvicorn)
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)
    import uvicorn
    import server  # noqa: E402
    print(f"[start] API  @  http://127.0.0.1:{args.port}/ui")

    # 5) 浏览器(上游 web UI 会自己处理 api_key 输入)
    if not args.no_browser:
        subprocess.Popen(["open", f"http://127.0.0.1:{args.port}/ui"])

    config = uvicorn.Config(server.app, host="127.0.0.1", port=args.port, log_config=None)
    uvi = uvicorn.Server(config)
    try:
        uvi.run()
    finally:
        if signer.poll() is None:
            signer.terminate()
            try:
                signer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                signer.kill()


if __name__ == "__main__":
    main()
