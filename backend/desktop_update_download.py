# -*- coding: utf-8 -*-
"""本地维护: 应用内下载新版安装包（国内走 Gitee，快）。

为什么不让后端直接返回一个「下载地址」了事：
    GitHub 在国内很慢；Gitee 快，但它的下载链接是**带时效 token 的跳转**
    （302 到 foruda.gitee.com/...?token=...&ts=...），直接交给浏览器打开
    会跳到 Gitee 页面而不是「立即开始下载」。用户要的是点一下就开始下。

做法：
    * 后端流式代理下载（跟随跳转），前端用 fetch 读进度条；
    * 下完把文件交给系统默认程序打开 —— 那就是安装包自己弹安装向导，
      不经过浏览器，也就不会被浏览器拦。
    * 下载源按优先级排：Gitee 在前（国内快），GitHub 兜底。

校验：下载完成后比对 SHA256。Gitee 和 GitHub 都提供不了可靠的摘要接口，
所以摘要由发布方写进 latest.json（`sha256` 字段），下载后核对；
对不上就报错，不把坏文件交给用户。
"""
import hashlib
import os
import subprocess
import threading
import time
import uuid

import hongguo as H

GH_RELEASE = ("https://github.com/dddmiku/hongguo-desktop-releases"
              "/releases/download/v%s/hongguo-%s-setup.exe")

# 下载源优先级（2026-10-08 实测，同一 20MB 取样、不走本机代理）：
#   gh-proxy 镜像   12.2 MB/s   <- 最快
#   GitHub 直连      7.3 MB/s
#   Gitee            2.1 MB/s
# 所以 gh-proxy 在前，后面两个只作兜底（镜像挂了也不至于下不了）。
SOURCES = (
    ("gh-proxy", "https://gh-proxy.com/" + GH_RELEASE),
    ("gitee", "https://gitee.com/q24111/hongguo-desktop-releases"
              "/releases/download/v%s/hongguo-%s-setup.exe"),
    ("github", GH_RELEASE),
)
GITEE_API = ("https://gitee.com/api/v5/repos/q24111/hongguo-desktop-releases"
             "/releases/tags/v%s")

_tasks = {}
_lock = threading.RLock()
_MAX_TASKS = 4


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download_dir():
    """安装包下载到用户数据目录下的 downloads/（便于清理与排查）。"""
    base = os.environ.get("HONGGUO_DATA_DIR") or os.environ.get(
        "HONGGUO_BACKEND_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(base, "downloads")
    os.makedirs(d, exist_ok=True)
    return d


def _prune():
    with _lock:
        if len(_tasks) <= _MAX_TASKS:
            return
        done = sorted((t for t in _tasks.values()
                       if t["phase"] in ("done", "error")),
                      key=lambda t: t["at"])
        for t in done[:len(_tasks) - _MAX_TASKS]:
            _tasks.pop(t["id"], None)


def _run(task, version, sha_expected):
    urls = [(name, tpl % (version, version)) for name, tpl in SOURCES]
    dest = os.path.join(download_dir(),
                        "hongguo-%s-setup.exe" % version)
    part = dest + ".part"
    last_err = ""
    for name, url in urls:
        task["source"] = name
        task["phase"] = "downloading"
        try:
            r = H.http_request("GET", url, stream=True, timeout=60,
                               allow_redirects=True)
            if r.status_code != 200:
                last_err = "%s: HTTP %s" % (name, r.status_code)
                continue
            total = int(r.headers.get("content-length") or 0)
            task["total"] = total
            got = 0
            with open(part, "wb") as f:
                for chunk in r.iter_content(1 << 18):
                    if task.get("cancelled"):
                        raise RuntimeError("cancelled")
                    if not chunk:
                        continue
                    f.write(chunk)
                    got += len(chunk)
                    task["downloaded"] = got
            if total and got != total:
                last_err = "%s: 下载不完整（%d/%d）" % (name, got, total)
                continue
            task["phase"] = "verifying"
            actual = _sha256(part)
            if sha_expected and actual != sha_expected:
                last_err = ("%s: 校验不一致（期望 %s…，实际 %s…）"
                            % (name, sha_expected[:12], actual[:12]))
                try:
                    os.remove(part)
                except OSError:
                    pass
                continue
            os.replace(part, dest)
            task.update(phase="done", path=dest, sha256=actual,
                        size=os.path.getsize(dest), at=time.time())
            return
        except Exception as e:
            last_err = "%s: %s" % (name, type(e).__name__)
            try:
                if os.path.isfile(part):
                    os.remove(part)
            except OSError:
                pass
    task.update(phase="error", error=last_err or "下载失败", at=time.time())


def start(version, sha256=""):
    version = "".join(c for c in str(version or "") if c.isdigit() or c == ".")
    if not version:
        return {"ok": False, "error": "版本号无效"}
    with _lock:
        for t in _tasks.values():
            if t["version"] == version and t["phase"] in ("downloading", "verifying"):
                return {"ok": True, "task": public(t)}
        task = {"id": uuid.uuid4().hex, "version": version, "phase": "starting",
                "downloaded": 0, "total": 0, "source": "", "at": time.time(),
                "path": "", "sha256": "", "size": 0, "error": ""}
        _tasks[task["id"]] = task
    threading.Thread(target=_run, args=(task, version, sha256),
                     name="hq-download", daemon=True).start()
    return {"ok": True, "task": public(task)}


def public(task):
    return {"id": task["id"], "version": task["version"],
            "phase": task["phase"], "downloaded": task["downloaded"],
            "total": task["total"], "source": task["source"],
            "size": task["size"], "error": task["error"]}


def status(task_id):
    with _lock:
        t = _tasks.get(str(task_id))
    if not t:
        return {"ok": False, "error": "下载任务不存在"}
    return {"ok": True, "task": public(t)}


def _installer_pids(exe_name):
    """当前正在运行的安装包进程 PID 集合（按 exe 文件名匹配）。

    不依赖 tasklist 的本地化表头：改用 CIM 查询，按 Name 精确比对。
    """
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Process -Filter \"Name='%s'\" "
             "| Select-Object -ExpandProperty ProcessId) -join ','" % exe_name],
            capture_output=True, text=True, timeout=15).stdout.strip()
        return {int(x) for x in out.split(",") if x.strip().isdigit()}
    except Exception:
        return set()


def _wait_installer(before, exe_name, timeout=25.0):
    """等安装程序进程真正出现（返回 True/False）。

    比固定 sleep 可靠：慢盘上解压/启动要多久都能等，
    而且能识别「根本没起来」这种情况，让前端不要急着退出。
    """
    import time as _t
    deadline = _t.time() + timeout
    while _t.time() < deadline:
        now = _installer_pids(exe_name)
        if now - before:
            return True
        _t.sleep(0.4)
    return False


def launch(task_id):
    """启动下好的安装包（会弹安装向导）。

    为什么不能直接用 os.startfile：
        2026-10-08 实测（用户点了「下载并更新」后程序退出、安装向导没出现）：
          1) 本进程树在一个 **job object** 里（`IsProcessInJob(hongguo-desktop-companion.exe)`
             返回 True —— 进程树是 exe -> python.exe，python 是 exe 的子进程）；
          2) `os.startfile` 起的安装程序也落在这个 job 里；
          3) 前端随后调 Tauri 的 quit_app 退出 —— job 关闭，**安装程序被连带杀掉**。
        现场证据：TEMP 下的 ns*.tmp 里，MicrosoftEdgeWebview2Setup.exe 是 0 字节
        —— NSIS 刚开始自解压就被终止了（时间戳与下载完成同一秒）。

    做法：用 explorer.exe 中转启动。explorer 常驻、不在我们的 job 里，
    它拉起的安装程序自然也不在；父进程退出影响不到它。
    再退回 Popen + DETACHED_PROCESS|CREATE_BREAKAWAY_FROM_JOB 兜底。

    返回里带 `ready`：确认「安装程序真的起来了」再让前端退出。
    固定 sleep 不可靠 —— 慢盘上 6 秒也可能不够，而前端一退，
    兜底路径（仍在 job 内）的安装程序照样会被连坐杀掉。
    """
    with _lock:
        t = _tasks.get(str(task_id))
    if not t:
        return {"ok": False, "error": "下载任务不存在"}
    if t["phase"] != "done":
        return {"ok": False, "error": "还没下载完"}
    path = t["path"]
    if not os.path.isfile(path):
        return {"ok": False, "error": "安装包不见了，请重新下载"}

    before = _installer_pids(os.path.basename(path))

    # 首选 explorer 中转：它不受我们的 job 约束，父进程退出也不影响它。
    try:
        subprocess.Popen(["explorer.exe", os.path.abspath(path)], close_fds=True)
        return {"ok": True, "path": path, "via": "explorer",
                "ready": _wait_installer(before, os.path.basename(path))}
    except Exception as e:
        first = "%s" % type(e).__name__

    # 兜底：自己起，但尽量脱离 job（需要 job 允许 breakaway；不允许时会抛错，
    # 那就退回不带 breakaway 的 detached，至少不继承控制台）。
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000
    for flags, how in (
            (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,
             "breakaway"),
            (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, "detached")):
        try:
            subprocess.Popen([os.path.abspath(path)], creationflags=flags, close_fds=True)
            return {"ok": True, "path": path, "via": how,
                    "ready": _wait_installer(before, os.path.basename(path))}
        except Exception:
            continue
    return {"ok": False, "error": "无法打开安装包：%s" % first}


def cancel(task_id):
    with _lock:
        t = _tasks.get(str(task_id))
    if t:
        t["cancelled"] = True
    return {"ok": True}
