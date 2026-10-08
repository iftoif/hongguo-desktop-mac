# -*- coding: utf-8 -*-
"""本地维护: 更新检测（指向本分支自己的仓库）。

为什么不用 Tauri 自带的那套：
    上游的在线更新在 Rust 侧用 **minisign 公钥验签**，私钥只有原作者有。
    我们把内嵌公钥/端点换掉之后，官方 updater 仍然会走「下载 -> 验签 -> 安装」，
    而我们签不出那个名 —— 硬走只会失败。所以：
      * 检测：后端查我们仓库的 GitHub Release，和本地版本比对；
      * 安装：不代下载安装，而是打开 Release 页面让用户下载安装包
        （安装包本身是我们构建的，装完就是新版）。

这样「检查更新」是真能用的，也不会骗用户说「正在安装」然后失败。

版本比较：按段数值比较（1.10.0 > 1.9.0），不接受字符串比较。
"""
import json
import os
import re
import time

import hongguo as H

REPO = "dddmiku/hongguo-desktop-releases"
# 优先用 Release 里的**静态资源** latest.json，而不是 GitHub API：
#   * API 匿名只有 60 次/小时，且本机走代理时出口 IP 常被限流（实测 403）；
#   * 静态下载链接不限流、不需要 token，上游 updater 用的也是这个。
# API 只作为 latest.json 缺失时的兜底。
LATEST_JSON = ("https://github.com/%s/releases/latest/download/latest.json" % REPO)
RELEASES_URL = "https://api.github.com/repos/%s/releases/latest" % REPO
PAGE_URL = "https://github.com/%s/releases/latest" % REPO

# 本地版本：优先环境变量（打包/测试用），否则读 exe 的 PE 版本信息。
LOCAL_VERSION = os.environ.get("HONGGUO_VERSION", "1.1.0")

_cache = {"at": 0.0, "data": None}
_CACHE_TTL = 600          # 10 分钟内不重复打 GitHub API（匿名有 60 次/小时限额）


def _parse_version(text):
    """把 'v1.2.3' / '1.2.3' 解析成可比较的元组；无法解析返回 None。"""
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", str(text or "").strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp(a, b):
    """按段数值比较，缺位补 0。返回 -1/0/1。"""
    a, b = list(a), list(b)
    while len(a) < len(b):
        a.append(0)
    while len(b) < len(a):
        b.append(0)
    return (a > b) - (a < b)


def check(local=None):
    """查询最新版本。返回 dict；任何失败都给出可读原因，不抛异常。"""
    local = local or LOCAL_VERSION
    now = time.time()
    if _cache["data"] is not None and now - _cache["at"] < _CACHE_TTL:
        cached = dict(_cache["data"])
        cached["cached"] = True
        return _merge(cached, local)

    data = _from_latest_json(local)
    if not data.get("ok"):
        fallback = _from_api(local)
        if fallback.get("ok"):
            data = fallback
    if data.get("ok"):
        _cache["at"], _cache["data"] = now, data
    return _merge(dict(data), local)


def _from_latest_json(local):
    """读 Release 里的 latest.json（静态，不限流）。"""
    try:
        r = H.http_request("GET", LATEST_JSON, headers={
            "accept": "application/json",
            "user-agent": "hongguo-desktop-update-check",
        }, timeout=15)
        if r.status_code != 200:
            return {"ok": False, "error": "查询失败（HTTP %s）" % r.status_code,
                    "currentVersion": local, "page": PAGE_URL}
        j = r.json()
    except Exception as e:
        return {"ok": False, "error": "网络不可用：%s" % type(e).__name__,
                "currentVersion": local, "page": PAGE_URL}
    version = str(j.get("version") or "").lstrip("v")
    if not version:
        return {"ok": False, "error": "latest.json 里没有版本号",
                "currentVersion": local, "page": PAGE_URL}
    plat = (j.get("platforms") or {}).get("windows-x86_64") or {}
    return {
        "ok": True, "currentVersion": local, "latestVersion": version,
        "tag": "v" + version, "notes": str(j.get("notes") or "")[:4000],
        "publishedAt": str(j.get("pub_date") or ""), "page": PAGE_URL,
        "assetName": "hongguo-%s-setup.exe" % version,
        "assetUrl": str(plat.get("url") or PAGE_URL),
        "assetSize": int(plat.get("size") or 0),
        "sha256": str(j.get("sha256") or ""),
    }


def _from_api(local):
    """兜底：走 GitHub API（有速率限制，仅当 latest.json 不可用时）。"""
    try:
        r = H.http_request("GET", RELEASES_URL, headers={
            "accept": "application/vnd.github+json",
            "user-agent": "hongguo-desktop-update-check",
        }, timeout=15)
        if r.status_code == 404:
            return {"ok": False, "error": "仓库暂无 Release（或仓库不是公开的）",
                    "currentVersion": local, "page": PAGE_URL}
        if r.status_code == 403:
            return {"ok": False, "error": "查询被限流（HTTP 403），稍后再试",
                    "currentVersion": local, "page": PAGE_URL}
        if r.status_code != 200:
            return {"ok": False, "error": "查询失败（HTTP %s）" % r.status_code,
                    "currentVersion": local, "page": PAGE_URL}
        j = r.json()
    except Exception as e:
        return {"ok": False, "error": "网络不可用：%s" % type(e).__name__,
                "currentVersion": local, "page": PAGE_URL}
    tag = str(j.get("tag_name") or "")
    assets = j.get("assets") or []
    setup = next((a for a in assets
                  if str(a.get("name", "")).endswith(".exe")), None)
    return {
        "ok": True, "currentVersion": local,
        "latestVersion": tag.lstrip("v"), "tag": tag,
        "notes": str(j.get("body") or "")[:4000],
        "publishedAt": j.get("published_at") or "",
        "page": j.get("html_url") or PAGE_URL,
        "assetName": (setup or {}).get("name") or "",
        "assetUrl": (setup or {}).get("browser_download_url") or PAGE_URL,
        "assetSize": int((setup or {}).get("size") or 0),
    }


def _merge(data, local):
    cur = _parse_version(local)
    latest = _parse_version(data.get("latestVersion"))
    if data.get("ok") and cur and latest:
        data["updateAvailable"] = _cmp(latest, cur) > 0
    else:
        data["updateAvailable"] = False
    if data.get("ok") and not latest:
        data["error"] = "仓库里的版本号无法识别：%s" % data.get("latestVersion")
        data["ok"] = False
    return data


def public():
    """给前端用的精简结果（去掉 notes 里的超长内容）。"""
    r = check()
    return {
        "currentVersion": r.get("currentVersion"),
        "latestVersion": r.get("latestVersion") or "",
        "updateAvailable": bool(r.get("updateAvailable")),
        "notes": r.get("notes") or "",
        "page": r.get("page") or PAGE_URL,
        "assetUrl": r.get("assetUrl") or "",
        "assetName": r.get("assetName") or "",
        "assetSize": r.get("assetSize") or 0,
        # 下载后要核对摘要。latest.json 里带 sha256（由发布脚本写入），
        # Gitee / GitHub 都没有可靠的摘要接口，所以只能自己带。
        "sha256": r.get("sha256") or "",
        # 下载走哪个源由后端决定（Gitee 优先），前端不需要知道。
        "publishedAt": r.get("publishedAt") or "",
        "error": r.get("error") or "",
        "cached": bool(r.get("cached")),
    }
