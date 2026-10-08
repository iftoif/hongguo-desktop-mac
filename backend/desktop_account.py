# -*- coding: utf-8 -*-
"""本地维护: 红果账号（验证码登录）+ 观看进度 / 收藏 双向同步。

纯协议实现，不需要模拟器常驻；登录态保存在本机应用数据目录。
签名走 backend 自带的脱机签名服务（SIGN_SERVER）。

协议要点（均以真机抓包核对）：
  * 验证码登录
      POST /passport/mobile/send_code/v1/   mobile/type/unbind_exist = XOR(0x05) 后 hex
      POST /passport/mobile/sms_login/      mobile/code          = XOR(0x05) 后 hex
      mix_mode=1；表单编码；返回 Set-Cookie 即登录态
  * 观看进度（手机“历史”页读的就是这个）
      POST /reading/bookapi/read_history/update/v   body gzip + x-ss-stub
      GET  /reading/bookapi/read_history/list/v?book_type=2
  * 收藏（短剧书架）
      POST /reading/bookapi/bookshelf/video/update/v   video_shelf_operate_type 0=加 1=删
      GET  /reading/bookapi/bookshelf/video/list/v

请求体统一 gzip 压缩，X-SS-STUB = 压缩后字节的 MD5(大写)，Content-Encoding: gzip。
"""
import gzip
import hashlib
import io
import json
import os
import re
import threading
import time

import requests

import hongguo as H

# ---- 登录态存放位置 -------------------------------------------------------
_DATA_DIR = os.environ.get("HONGGUO_DATA_DIR") or os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"), "cn.guoban.desktop-companion")
SESSION_PATH = os.environ.get("HONGGUO_ACCOUNT_FILE") or os.path.join(
    _DATA_DIR, "desktop-account.json")

# 验证码登录接口所在的 host（与主 API host 不同）
PASSPORT_HOST = os.environ.get("HONGGUO_PASSPORT_HOST", "security.snssdk.com")

# 护照接口的 UA 必须与真机一致（模拟器抓包原文）。
# 用内容接口那套 UA 或自定义 UA 会被风控判为异常客户端，登录直接返回 error_code=7。
PASSPORT_UA = os.environ.get(
    "HONGGUO_PASSPORT_UA",
    "com.phoenix.read/73932 (Linux; U; Android 12; zh_CN_#Hans; PGT-AN10; "
    "Build/V417IR;tt-ok/3.12.13.20)")

# ---- 护照请求的设备身份 ---------------------------------------------------
# 护照接口会校验设备指纹：device_id / iid / cdid 缺失会被判为异常客户端。
# 内容接口不校验这些（所以搜索播放一直正常），只有登录会踩到。
DEVICE_PATH = os.environ.get("HONGGUO_DEVICE_FILE") or os.path.join(
    _DATA_DIR, "desktop-device.json")

# 机型档案：与真实红果客户端一致（护照侧对参数完整性敏感，故写全）
PASSPORT_DEVICE_DEFAULTS = {
    "device_brand": "HONOR", "device_type": "PGT-AN10",
    "resolution": "1080*1920", "dpi": "480",
    "os": "android", "os_version": "12", "os_api": "32",
    "rom_version": "V417IR release-keys", "host_abi": "arm64-v8a",
    "channel": "vivo_8662_64", "ac": "wifi", "ssmix": "a",
    "language": "zh", "dragon_device_type": "phone",
    "manifest_version_code": "73932", "update_version_code": "73932",
    "version_code": "73932", "version_name": "7.3.9.32",
    "pv_player": "73932", "compliance_status": "0",
    "need_personal_recommend": "1", "player_so_load": "1",
    "is_android_pad_screen": "0", "okhttp_version": "4.2.243.31-douyin",
    "use_store_region_cookie": "1", "use_new_token_expire_rule": "true",
    "passport-sdk-version": "5051452",
    # 运行态/会话字段：真机每次请求都带，缺失可能被判为异常客户端
    "aid": "8662", "app_name": "novelread", "device_platform": "android",
    "gender": "2", "har_status": "0", "charging": "0",
    "network_type": "4", "down_speed": "60000", "font_scale": "100",
    "battery_pct": "93", "screen_brightness": "102", "current_volume": "0",
    "app_dark_mode": "0", "sys_dark_mode": "0", "sys_mini_window": "0",
    "app_mini_window": "0", "is_power_save_mode": "0",
    "normal_session_cnt_in_day": "1", "normal_session_cnt_in_life": "1",
    "cold_start_session_cnt_in_day": "1", "cold_start_session_cnt_in_life": "1",
}

# 允许放进请求体的字段（registered / source 等本地标记必须排除）
PASSPORT_BODY_FIELDS = set(PASSPORT_DEVICE_DEFAULTS) | {
    "device_id", "iid", "cdid", "normal_session_id", "cold_start_session_id",
}


def _digits(n):
    import random
    return "".join(random.choice("0123456789") for _ in range(n))


# 已注册设备身份的来源优先级：
#   1) 显式环境变量（HONGGUO_DEVICE_ID / _IID / _CDID）
#   2) 本机设备文件（首次从模拟器同步后固定下来）
#   3) 模拟器（adb 读取，已注册的那台）
# 随机生成的 device_id 会被护照边缘直接 403，所以不能凭空造。
DEVICE_ENV = ("HONGGUO_DEVICE_ID", "HONGGUO_DEVICE_IID", "HONGGUO_DEVICE_CDID")


def _from_env():
    values = [os.environ.get(name) for name in DEVICE_ENV]
    if all(values):
        return {"device_id": values[0], "iid": values[1], "cdid": values[2]}
    return None


def _from_emulator():
    """从模拟器里已注册的红果客户端读设备身份。

    只读 shared_prefs 里的公开字段，不注入进程、不改动 App。
    实测位置：
      device_id / iid -> applog_stats.xml
      cdid            -> com.ss.android.deviceregister.utils.Cdid.xml
    """
    import subprocess
    adb = os.environ.get("ADB", r"D:\Tools\adb\adb.exe")
    dev = os.environ.get("ADB_DEVICE", "127.0.0.1:16448")
    prefs = "/data/data/com.phoenix.read/shared_prefs"

    def read(name):
        try:
            out = subprocess.run([adb, "-s", dev, "shell", "cat", "%s/%s" % (prefs, name)],
                                 capture_output=True, timeout=20)
        except Exception:
            return ""
        return out.stdout.decode("utf-8", "replace")

    def grab(text, field):
        for pat in (r'name="%s"[^>]*>([^<]+)<' % re.escape(field),
                    r'name="%s"[^>]*value="([^"]+)"' % re.escape(field)):
            m = re.search(pat, text)
            if m and m.group(1).strip():
                return m.group(1).strip()
        return ""

    found = {}
    stats = read("applog_stats.xml")
    if stats:
        found["device_id"] = grab(stats, "device_id")
        found["iid"] = grab(stats, "install_id")
    cdid = read("com.ss.android.deviceregister.utils.Cdid.xml")
    if cdid:
        found["cdid"] = grab(cdid, "cdid")
    if all(found.get(k) for k in ("device_id", "iid", "cdid")):
        return found
    return None


def _session_ids():
    """真机会带会话 id（形如 <uuid>#<序号>）。缺失时补上并固定。"""
    data = load_device()
    changed = False
    for key, suffix in (("normal_session_id", "#1"), ("cold_start_session_id", "")):
        if not data.get(key):
            import uuid
            data[key] = str(uuid.uuid4()) + suffix
            changed = True
    if changed and data.get("registered"):
        try:
            io.open(DEVICE_PATH, "w", encoding="utf-8").write(
                json.dumps(data, ensure_ascii=False, indent=1))
        except OSError:
            pass
    return data


def _from_bundled():
    """随安装包携带的设备身份。

    为什么必须这么做（2026-10-08 实测 + 上游调查结论）：
      红果的护照接口对 device_id / iid **两个字段一起**校验，未注册的随机值
      直接 403 + 空 body（前端只看到「非 JSON 响应」）。而**离线注册一台新设备
      是研究级难题**：
        * 设备注册接口的签名校验 aid（红果 8662 vs 内置签名器 1967）对不上，
          实测跨 app 签名被接受（HTTP 200）但返回 device_id=0；
        * 红果新版 metasec 用 .msp_<sha1> 设备态存储，内容按设备上下文加密，
          搬过来也解不开；fresh 注册要复现 metasec 的引导握手（网络+VM 保护 crypto）。
      上游自己的做法也是「让真 app 注册一台，再 grab 它的设备参数入池」。
      所以分发包直接带一台已注册的设备身份，装完即可用，用户什么都不用做。
    设备身份不是账号凭据（不带 token/cookie），同一台设备多人登录互不影响；
    文件缺失或校验失败时自动退回下面的流程。
    """
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "device-bundled.json")
        data = json.loads(io.open(path, encoding="utf-8").read())
    except Exception:
        return None
    if not (isinstance(data, dict) and data.get("device_id") and data.get("iid")):
        return None
    data.setdefault("registered", True)
    data.setdefault("source", "bundled")
    return data


def load_device():
    """本机设备身份：一旦确定就固定下来，避免每次登录换设备。

    优先级：环境变量 > 已存的本机文件 > 随包携带的 > 模拟器同步 > 随机兜底。
    「随包携带」放在模拟器同步之前：普通用户没有模拟器，这是他们唯一
    能自动拿到的合法设备身份。
    """
    env = _from_env()
    if env:
        return env
    try:
        data = json.loads(io.open(DEVICE_PATH, encoding="utf-8").read())
        if isinstance(data, dict) and data.get("device_id") and data.get("registered"):
            return data
    except Exception:
        pass
    bundled = _from_bundled()
    if bundled:
        try:
            os.makedirs(os.path.dirname(DEVICE_PATH), exist_ok=True)
            io.open(DEVICE_PATH, "w", encoding="utf-8").write(
                json.dumps(bundled, ensure_ascii=False, indent=1))
        except OSError:
            pass
        log_event("device_bundled", note="使用随安装包携带的设备身份")
        return bundled
    synced = _from_emulator()
    if synced:
        synced["registered"] = True
        synced["source"] = "emulator"
        try:
            os.makedirs(os.path.dirname(DEVICE_PATH), exist_ok=True)
            io.open(DEVICE_PATH, "w", encoding="utf-8").write(
                json.dumps(synced, ensure_ascii=False, indent=1))
        except OSError:
            pass
        return synced
    # 兜底：沿用已存文件（即便未标记 registered）
    try:
        data = json.loads(io.open(DEVICE_PATH, encoding="utf-8").read())
        if isinstance(data, dict) and data.get("device_id"):
            return data
    except Exception:
        pass
    # 最后才随机 —— 但要标清楚「未注册」。
    # 2026-10-07 实测：随机生成的 device_id 在字节的注册服务里没有记录，
    # 登录会被判为异常客户端，稳定返回 error_code=7（系统繁忙）。
    # 模拟器里那台真实注册过的设备同样条件下返回 1202/1203（正常进入校验）。
    # 所以调用方应优先用 registered=True 的设备；这里只作最后兜底。
    import uuid
    log_event("device_unregistered",
              note="随机设备未经注册，登录可能被判异常客户端")
    return {"device_id": _digits(16), "iid": _digits(16),
            "cdid": str(uuid.uuid4()), "registered": False, "source": "random"}


def passport_query():
    """护照请求要带的完整设备参数（内容接口那套精简 query 不够用）。"""
    query = dict(PASSPORT_DEVICE_DEFAULTS)
    query.update(_session_ids())
    return query
SMS_TYPE = os.environ.get("HONGGUO_SMS_TYPE", "24")   # 抓包: type=24 → 登录场景

# ---- 安全验证（身份验证 / MFA）--------------------------------------------
# 2026-10-08 实测（真实 2046 响应已 dump，11 个字段全部核对存在）：
#   有些号发码成功、登录却返回 2046「为保证账号安全，暂不支持此操作」。
#   响应里带一整套验证上下文：
#     data.sms_code_key / encrypt_uid / biz_params / schema / url
#     data.event_params.verify_scene(="sms_login") + verify_reason(="ato")
#     data.verify_ways[].verify_way + channel_mobile + sms_content
#       （例：发 "YZ" 到 10691859839103；通道号每次不同）
#   这不是「被限流」，而是**要求先完成身份验证**。
#
# 完成机制（反编译 com.bytedance.sdk.account 逐行确认，已实测登录成功）：
#   H5 验证页 → bridge account.setVerifyStatus{status:0}
#     → bi1/b.java 取 data.biz_params
#     → ai1/c.java 把 sms_code_key 用 XOR(0x05) 再编码一次
#     → impl/w.java 把该 map **合并进原始 sms_login 参数**（biz 覆盖同名键）
#     → x.k() **原样重发 sms_login**
#   关键：verify_ticket 虽进了 ai1/c.a() 的参数表，但**方法体从未引用**，
#   所以它不是完成验证的凭据；真正起作用的是 biz_params。
#   /passport/upsms/verify/ 只负责「服务端收到上行短信了吗」的轮询
#   （端点定义在 H5 的 passport-second-verification 页面 JS 里）。
#
# 会要求验证的错误码（反编译 ai1/d.java 的分支常量）：
MFA_CODES = (2046, 2139, 2148, 4023)
MFA_PATH = os.environ.get("HONGGUO_MFA_FILE") or os.path.join(
    _DATA_DIR, "desktop-mfa.json")
_mfa_lock = threading.RLock()


def save_mfa(ctx):
    try:
        os.makedirs(os.path.dirname(MFA_PATH), exist_ok=True)
        io.open(MFA_PATH, "w", encoding="utf-8").write(
            json.dumps(ctx, ensure_ascii=False, indent=1))
    except OSError:
        pass


def load_mfa():
    try:
        d = json.loads(io.open(MFA_PATH, encoding="utf-8").read())
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def clear_mfa():
    try:
        os.remove(MFA_PATH)
    except OSError:
        pass


def _mfa_cookie(response):
    """从 2046 响应里取出安全验证用的 cookie（passport_mfa_token 等）。

    这些 cookie 是「这次挑战」的凭据，validate_code 必须原样带回。
    """
    raw = ""
    try:
        jar = getattr(response, "cookies", None)
        if jar is not None and len(jar):
            raw = "; ".join("%s=%s" % (c.name, c.value) for c in jar)
    except Exception:
        raw = ""
    if not raw:
        raw = response.headers.get("set-cookie") or ""
    keep = []
    for part in raw.split(","):
        kv = part.split(";")[0].strip()
        if "=" in kv and any(kv.startswith(n) for n in
                             ("passport_mfa_token", "d_ticket", "sid_guard",
                              "passport_csrf_token")):
            keep.append(kv)
    return "; ".join(keep)


def _mfa_context(data, cookie=""):
    """从 2046 响应里抽出验证所需上下文（前端要展示验证方式）。"""
    ways = []
    for w in (data.get("verify_ways") or []):
        if not isinstance(w, dict):
            continue
        ways.append({
            "way": str(w.get("verify_way") or ""),
            "mobile": str(w.get("mobile") or ""),
            "channelMobile": str(w.get("channel_mobile") or ""),
            "smsContent": str(w.get("sms_content") or ""),
            "name": str(w.get("platform_screen_name") or ""),
        })
    ev = data.get("event_params") if isinstance(data.get("event_params"), dict) else {}
    cp = (data.get("common_params")
          if isinstance(data.get("common_params"), dict) else {})
    # biz_params 是**完成验证后重发登录**时要原样带回的一整套参数
    # （含 sms_code_key）。2026-10-08 反编译 com.bytedance.sdk.account 确认：
    #   bi1/b.java(account.setVerifyStatus) 取 ai1/f.f4379c = data.biz_params，
    #   交给 ai1/c.java 合并进**原始 sms_login 请求参数**，再重发同一个请求。
    # 少了它，重发登录必然失败（服务端认不出这次验证属于哪一步）。
    biz = data.get("biz_params")
    biz = biz if isinstance(biz, dict) else {}
    # sms_code_key 优先取顶层；顶层没有就从 biz_params 里取
    # （反编译里 ai1/c.java 读的就是合并后的 map，两处都可能有）。
    sms_key = str(data.get("sms_code_key") or biz.get("sms_code_key") or "")
    return {
        "mobile": str(data.get("mobile") or ""),
        "smsCodeKey": sms_key,
        "encryptUid": str(data.get("encrypt_uid") or ""),
        "verifyScene": str(ev.get("verify_scene") or data.get("passport_scene") or ""),
        "verifyReason": str(ev.get("verify_reason") or ""),
        "verifyWays": ways,
        "bizParams": biz,
        "schema": str(data.get("schema") or ""),
        "url": str(data.get("url") or ""),
        "desc": str(cp.get("copywriting") or "")[:600],
        "cookie": cookie,
        "at": int(time.time()),
    }

_lock = threading.RLock()
_cache = None
_cache_mtime = 0.0   # 缓存对应的会话文件 mtime（外部改写后要能失效重读）

# ---- 诊断日志 -------------------------------------------------------------
# 登录失败时用户没有可查的证据，所以每次护照调用都留一条记录。
# 绝不记录 token / cookie / 完整手机号 / 完整验证码。
LOG_PATH = os.environ.get("HONGGUO_ACCOUNT_LOG") or os.path.join(_DATA_DIR, "account-log.jsonl")
LOG_MAX_BYTES = 512 * 1024


def mask_mobile(value):
    text = re.sub(r"\D", "", str(value or ""))
    if len(text) < 7:
        return "***"
    return text[:3] + "****" + text[-4:]


def log_event(event, **fields):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        try:
            if os.path.getsize(LOG_PATH) > LOG_MAX_BYTES:
                os.replace(LOG_PATH, LOG_PATH + ".1")
        except OSError:
            pass
        record = {"t": int(time.time() * 1000), "event": event}
        record.update(fields)
        with io.open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_log(limit=50):
    items = []
    try:
        for line in io.open(LOG_PATH, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        return []
    return items[-int(limit):]


# ---- 编解码 ---------------------------------------------------------------
def xor_hex(text):
    """红果 passport 的字段编码：UTF-8 字节逐字节异或 0x05，再转小写 hex。"""
    return bytes(b ^ 5 for b in str(text).encode("utf-8")).hex()


def normalize_mobile(mobile):
    """护照接口要求手机号带国家码并按 3-4-4 分组。

    实测：真机发的是 '+86157 3063 9941'（含 '+86' 与空格），
    XOR(0x05) 后与抓包逐字节一致；发裸 11 位会被判为非法号码，
    服务端直接返回 error_code=7（提示却是「系统繁忙」）。
    """
    digits = re.sub(r"\D", "", str(mobile or ""))
    if len(digits) == 13 and digits.startswith("86"):
        digits = digits[2:]
    if len(digits) == 11 and digits.startswith("1"):
        # 真机形态：+86 前缀 + 3-4-4 分组（组间是空格）
        return "+86" + digits[:3] + " " + digits[3:7] + " " + digits[7:11]
    return ("+86" + digits) if digits else ""


def xor_unhex(value):
    try:
        return bytes(b ^ 5 for b in bytes.fromhex(value)).decode("utf-8")
    except Exception:
        return ""


def _gzip_body(payload):
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6, mtime=0) as gz:
        gz.write(raw)
    return buf.getvalue()


# ---- 登录态读写 -----------------------------------------------------------
def _session_mtime():
    try:
        return os.path.getmtime(SESSION_PATH)
    except OSError:
        return 0.0


def load_session():
    """读登录态。

    带 mtime 失效检查：会话文件同时也被开发脚本/其它工具改写
    （安装目录里就有直接 copy 覆盖它的脚本），
    而 _cache 是模块级全局且原先只看一次文件 ——
    外部改写后运行中的后端仍返回旧值，两边会互相覆盖。
    这里只要文件比缓存新就重读。
    """
    global _cache, _cache_mtime
    with _lock:
        stamp = _session_mtime()
        if _cache is not None and stamp == _cache_mtime:
            return _cache
        data = {}
        try:
            if os.path.isfile(SESSION_PATH):
                data = json.loads(io.open(SESSION_PATH, encoding="utf-8").read())
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        _cache = data
        _cache_mtime = stamp
        return _cache


def save_session(data):
    global _cache, _cache_mtime
    with _lock:
        _cache = data or {}
        try:
            os.makedirs(os.path.dirname(SESSION_PATH), exist_ok=True)
            tmp = SESSION_PATH + ".tmp"
            io.open(tmp, "w", encoding="utf-8").write(
                json.dumps(_cache, ensure_ascii=False, indent=2))
            os.replace(tmp, SESSION_PATH)
        except OSError:
            pass
        _cache_mtime = _session_mtime()
    return _cache


def _backup_path(uid=""):
    """按账号分文件存「退出前的登录态」。

    原先只有单槽位 .last，换号后一退出就把上一个号的备份覆盖掉了；
    而恢复时不校验有效性，于是「恢复上次登录」可能恢复成另一个号，
    或者恢复一个早就失效的会话。
    """
    text = re.sub(r"[^0-9A-Za-z_-]", "", str(uid or ""))[:40]
    return SESSION_PATH + ".last" + ("." + text if text else "")


def clear_session():
    """退出登录：先留一份可恢复的备份，再清空。

    验证码登录尚未稳定，万一退出后登不回来，用户不该被卡死；
    所以这里把当前登录态另存一份，restore_session() 可以原样恢复。
    备份按 uid 分文件，换号不会互相覆盖。
    """
    current = load_session() or {}
    if current.get("token") or current.get("cookie"):
        for path in (_backup_path(current.get("uid")), SESSION_PATH + ".last"):
            try:
                io.open(path, "w", encoding="utf-8").write(
                    json.dumps(current, ensure_ascii=False, indent=2))
            except OSError:
                pass
    return save_session({})


def _restore_candidates():
    """可恢复的备份，当前账号优先，其次旧的单槽位 .last。"""
    uid = (load_session() or {}).get("uid")
    out = []
    for path in (_backup_path(uid), SESSION_PATH + ".last"):
        if path not in out:
            out.append(path)
    try:
        import glob as _g
        for path in sorted(_g.glob(SESSION_PATH + ".last.*"), reverse=True):
            if path not in out:
                out.append(path)
    except Exception:
        pass
    return out


def restore_session():
    """把上一次「退出登录」前的登录态恢复回来。

    恢复后必须验一次有效性：备份可能是失效会话，
    直接写回会让界面显示「已登录」但所有请求都失败。
    验证不通过就原样回滚，不污染当前登录态。
    """
    data = None
    for path in _restore_candidates():
        try:
            cand = json.loads(io.open(path, encoding="utf-8").read())
        except Exception:
            continue
        if isinstance(cand, dict) and (cand.get("token") or cand.get("cookie")):
            data = cand
            break
    if data is None:
        return {"ok": False, "error": "没有可恢复的登录态"}
    previous = load_session() or {}
    # 校验要发网络请求，签名服务/网络不可用时会抛异常。
    # 必须兜住：恢复登录态失败不该变成 500，更不能因此写回坏会话。
    try:
        info = _json(_call("GET", "/reading/user/info/v", session=data))
    except Exception as exc:
        log_event("restore_session", ok=False, reason="verify_error",
                  error="%s" % type(exc).__name__)
        return {"ok": False,
                "error": "无法校验备份的登录态（%s），请稍后重试或用验证码登录"
                         % type(exc).__name__}
    body = info.get("data") if isinstance(info.get("data"), dict) else {}
    if info.get("code") not in (0, "0") or not body:
        log_event("restore_session", ok=False, code=info.get("code"),
                  reason="backup_invalid")
        return {"ok": False, "error": "备份的登录态已失效，请重新用验证码登录"}
    data["user_name"] = body.get("user_name") or data.get("user_name") or ""
    data["uid"] = str(body.get("user_id") or data.get("uid") or "")
    save_session(data)
    log_event("restore_session", ok=True, user=bool(data["user_name"]))
    return {"ok": True, "session": public_session(data)}


def has_restorable():
    """是否存在可恢复的登录态（用于前端显示恢复入口）。"""
    for path in _restore_candidates():
        try:
            data = json.loads(io.open(path, encoding="utf-8").read())
        except Exception:
            continue
        if isinstance(data, dict) and (data.get("token") or data.get("cookie")):
            return True
    return False


def is_logged_in():
    s = load_session()
    return bool(s.get("cookie") or s.get("token"))


# ---- 请求 -----------------------------------------------------------------
def _headers(session=None, extra=None):
    headers = dict(H.CFG.get("session_headers") or {})
    session = session if session is not None else load_session()
    token = (session or {}).get("token")
    cookie = (session or {}).get("cookie")
    if token:
        headers["x-tt-token"] = token
    if cookie:
        headers["cookie"] = cookie
    headers["content-type"] = "application/json; charset=utf-8"
    if extra:
        headers.update(extra)
    return headers


def _call(method, path, body=None, extra=None, session=None, host=None, form=None,
          passport=False, cookie_extra=""):
    """发一个带签名的红果请求。body/form 二选一。

    passport=True 时用完整设备参数（登录接口校验设备指纹，精简 query 会被风控）。

    cookie_extra：额外并入 Cookie 头的键值（形如 "a=1; b=2"）。
    安全验证必须用它 —— 2046 下发的 passport_mfa_token 要靠它带回给
    validate_code；而 _headers() 在「本机已有登录账号」时会用账号 cookie
    覆盖整个 Cookie 头，把挑战 cookie 冲掉，导致 validate_code 报
    1203/1204（看着像验证码错了，其实是凭据断了）。
    """
    if passport:
        merged = dict(passport_query())
        if extra:
            merged.update(extra)
        url = H.build_url(path, merged)
    else:
        url = H.build_url(path, extra)
    if host:
        url = re.sub(r"^https://[^/]+", "https://" + host, url)
    headers = _headers(session)
    data = None
    if form is not None:
        data = form.encode("utf-8")
        headers["content-type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = _gzip_body(body)
        headers["content-encoding"] = "gzip"
        headers["x-ss-stub"] = hashlib.md5(data).hexdigest().upper()
    if passport:
        # 真机护照请求的三个硬性条件（2026-10-07 抓包 + 剥离实验确认）：
        #   1) UA 必须是 App 原文（内容接口那套 UA 会被判异常客户端 → error_code=7）
        #   2) 必须带 x-ss-req-ticket（毫秒时间戳），否则同样退化成 error_code=7
        #   3) 请求体必须带 x-ss-stub（登录/发码都是表单，所以是真机那种 32 位大写十六进制）
        # 只补 1+2 仍然失败；补上 3 后服务端才放行（错误码从 7 变成「验证码错误/过期」）。
        #
        # 头部要与真机逐项对齐（2026-10-07 对照实验，真机头部全量通过风控）：
        #   · 去掉内容接口那套 x-tt-store-region*，以及 X-Neptune / X-Soter（护照请求不带）
        #   · 补 lc / x-vc-bdturing-sdk-version
        #   · cookie 与 x-tt-passport-csrf-token 必须带上（真机请求里有；
        #     之前 sms_login 传了空 session，等于完全不发 cookie，这是被拦的关键）
        for stale in ("x-tt-store-region", "x-tt-store-region-src"):
            headers.pop(stale, None)
        headers["user-agent"] = PASSPORT_UA
        headers["lc"] = "101"
        headers["x-vc-bdturing-sdk-version"] = "4.0.3.cn"
        headers["x-ss-req-ticket"] = str(int(time.time() * 1000))
        # x-ss-stub 不能是 md5(请求体)！
        # 2026-10-07 交替对照（各测 2 次，结果稳定）：
        #   x-ss-stub = md5(请求体)     -> error_code=7（被拦）
        #   x-ss-stub = 随机 32 位 hex  -> 1203（通过，进入验证码校验）
        # 上游文档写的「x-ss-stub = body 的 MD5」对护照接口不成立；
        # 服务端会拒绝 stub 恰好等于请求体 md5 的请求。这里用随机值。
        import secrets as _secrets
        headers["x-ss-stub"] = _secrets.token_hex(16).upper()
        # csrf：优先用会话里的；没有就从 cookie 里抠出来。
        csrf = ""
        cookie_text = headers.get("cookie") or ""
        m = re.search(r"passport_csrf_token=([^;]+)", cookie_text)
        if m:
            csrf = m.group(1)
        if csrf:
            headers["x-tt-passport-csrf-token"] = csrf
    if cookie_extra:
        base = headers.get("cookie") or ""
        headers["cookie"] = (base + "; " + cookie_extra).strip("; ") if base else cookie_extra
    headers.update(H.sign(url, headers))
    headers.pop("accept-encoding", None)
    if passport:
        # 签名会补上 X-Neptune / X-Soter，但真机的护照请求没有这两个头，
        # 必须在签名之后删，否则等于没删。
        for stale in ("x-neptune", "x-soter", "X-Neptune", "X-Soter"):
            headers.pop(stale, None)
    r = H.http_request(method, url, data=data, headers=headers, timeout=30)
    return r


def _json(response):
    try:
        return response.json()
    except ValueError:
        return {"code": -1, "message": "非 JSON 响应", "raw": response.text[:300]}


# 设备身份问题的可操作提示。
# 2026-10-08 实测定位：护照边缘对 device_id / iid **两个字段一起**校验
#   · 已注册设备（从真机/模拟器抓到的）-> HTTP 200
#   · 随机设备 -> HTTP 403 + **空 body**（连 JSON 都不给，所以前端显示
#     「非 JSON 响应」这种看不出原因的报错）
# 逐字段替换实验：device_id+iid 都换成已注册的 -> 200；只换其中一个 -> 403。
# 所以必须两个字段同时是服务端注册过的。
DEVICE_HINT = (
    "本机缺少随包携带的设备身份文件（device-bundled.json），"
    "服务端因此拒绝了这次请求。请重新安装一次安装包（安装程序会把它放回 "
    "%s 目录）；若仍不行，请把这个问题反馈给提供安装包的人。"
)


def device_issue():
    """返回 (是否有问题, 提示)。设备身份没拿到时给出可操作的说明。"""
    try:
        dev = load_device()
    except Exception:
        return True, DEVICE_HINT % _DATA_DIR
    if not dev.get("device_id") or not dev.get("iid"):
        return True, DEVICE_HINT % _DATA_DIR
    if not dev.get("registered"):
        return True, DEVICE_HINT % _DATA_DIR
    return False, ""


# ---- 验证码登录 -----------------------------------------------------------
def _passport_form_params(mobile=None, code=None, with_device=False):
    """构造护照表单，返回**有序 dict**（键值未编码）。

    与 _passport_form 的唯一区别：不在这里做 URL 编码、也不拼成字符串。
    重放 sms_login 时需要「把 biz_params 合并进来、biz 覆盖同名键」，
    直接拼两段编码串会产生重复键（wire 上同一个 key 出现两次），
    所以先出 dict，合并后再统一编码一次。
    """
    params = {}
    if mobile:
        params["mobile"] = xor_hex(mobile)
    if code:
        params["code"] = xor_hex(code)
    params["account_sdk_source"] = "app"
    params["passport_support_flow"] = "captcha,verify"
    params["mix_mode"] = "1"
    if with_device:
        for key, value in passport_query().items():
            if key in PASSPORT_BODY_FIELDS:
                params[key] = str(value)
    return params


def _passport_form(mobile=None, code=None, with_device=False):
    """构造护照表单（URL 编码后的字符串）。

    with_device=True 时把设备参数也编进请求体 —— 真机就是这么发的
    （sms_login 请求体 55 个字段，设备字段和业务字段在同一个表单里）。
    只放 URL query 不生效：服务端校验的是请求体。
    """
    from urllib.parse import quote
    params = _passport_form_params(mobile=mobile, code=code, with_device=with_device)
    return "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in params.items())


def _passport_result(body):
    """passport 的响应形状与内容接口不同：
    成功是 {"message":"success","data":{...}}；
    失败是 {"message":"error","data":{"error_code":N,"description":"..."}}。
    """
    if not isinstance(body, dict):
        return False, "响应格式异常", None
    data = body.get("data")
    if isinstance(data, dict) and data.get("error_code"):
        return False, str(data.get("description") or "请求被拒绝"), data.get("error_code")
    message = str(body.get("message") or "").lower()
    if message == "success" or body.get("code") in (0, "0"):
        return True, "", None
    return False, str(body.get("message") or "请求失败"), None


def send_code(mobile):
    mobile = re.sub(r"\D", "", str(mobile or ""))
    if not re.fullmatch(r"1\d{10}", mobile):
        return {"ok": False, "error": "手机号格式不正确"}
    # 先自查设备身份：服务端对未注册设备直接 403 + 空 body，
    # 前端只会看到「非 JSON 响应」，用户完全不知道要做什么。
    bad, hint = device_issue()
    if bad:
        log_event("send_code", ok=False, reason="device_unregistered",
                  mobile=mask_mobile(mobile))
        return {"ok": False, "error": hint, "error_code": "device"}
    form = (_passport_form(mobile=normalize_mobile(mobile), with_device=True)
            + "&type=" + xor_hex(SMS_TYPE)
            + "&unbind_exist=" + xor_hex("1") + "&auto_read=0")
    r = _call("POST", "/passport/mobile/send_code/v1/", form=form,
              host=PASSPORT_HOST, passport=True)
    j = _json(r)
    ok, why, err_code = _passport_result(j)
    data = j.get("data") if isinstance(j.get("data"), dict) else {}
    # 403 + 空 body：不是网络问题，是设备身份被拒（服务端连错误码都不给）。
    # 把它翻成人能看懂的话，否则用户只能看到「非 JSON 响应」。
    if not ok and r.status_code in (401, 403) and not r.text.strip():
        why, err_code = hint, "device"
    log_event("send_code", host=PASSPORT_HOST, http=r.status_code, ok=ok,
              mobile=mask_mobile(mobile), type=SMS_TYPE,
              error_code=err_code, message=str(j.get("message"))[:80],
              description=str(data.get("description") or why)[:120],
              has_ticket=bool(data.get("mobile_ticket")),
              retry_time=data.get("retry_time"))
    return {"ok": ok, "code": j.get("code"), "message": j.get("message"),
            "error": "" if ok else why, "error_code": err_code,
            "hasTicket": bool(data.get("mobile_ticket")),
            "retryTime": data.get("retry_time"),
            "data": j.get("data"), "http": r.status_code}


def _extract_session(response, session):
    """从登录响应里取出 token / cookie。"""
    cookie = ""
    try:
        jar = getattr(response, "cookies", None)
        if jar is not None and len(jar):
            cookie = "; ".join("%s=%s" % (c.name, c.value) for c in jar)
    except Exception:
        cookie = ""
    if not cookie:
        raw = response.headers.get("set-cookie") or ""
        if raw:
            cookie = re.sub(r";\s*(Path|Domain|Expires|Max-Age|Secure|HttpOnly|SameSite)[^;]*", "", raw, flags=re.I)
    if not cookie:
        cookie = (session or {}).get("cookie") or ""
    try:
        body = response.json()
    except ValueError:
        body = {}
    data = body.get("data") if isinstance(body, dict) else None
    token = ""
    if isinstance(data, dict):
        for key in ("token", "session_key", "x_tt_token", "x-tt-token"):
            if data.get(key):
                token = str(data[key])
                break
    if not token:
        token = (session or {}).get("token") or ""
    user = ""
    uid = ""
    if isinstance(data, dict):
        user = str(data.get("user_name") or data.get("name") or "")
        uid = str(data.get("user_id") or data.get("uid") or data.get("user_id_str") or "")
    return {"token": token, "cookie": cookie, "user_name": user, "uid": uid}


def _finish_login(r, mobile):
    """登录响应有效时的收尾：存会话 + 拉账号信息。"""
    session = _extract_session(r, {})
    session["saved_at"] = int(time.time())
    session["mobile"] = mobile
    save_session(session)
    log_event("sms_login_ok", host=PASSPORT_HOST, http=r.status_code,
              mobile=mask_mobile(mobile), has_cookie=bool(session.get("cookie")))
    info = _json(_call("GET", "/reading/user/info/v", session=session))
    if isinstance(info.get("data"), dict):
        session["user_name"] = info["data"].get("user_name") or session.get("user_name") or ""
        session["uid"] = str(info["data"].get("user_id") or session.get("uid") or "")
        save_session(session)
    clear_mfa()
    return {"ok": True, "code": 0, "session": public_session(session)}


def verify_mfa(mobile, code=""):
    """完成安全验证（2046 之后那一步）。

    2026-10-08 反编译 com.bytedance.sdk.account 得到**完整**机制（不再是猜的）：

      H5 验证页 → bridge `account.setVerifyStatus{status:0, verifyWay, verifyTicket}`
        → bi1/b.java：hashMap = 2046 响应的 data.biz_params
        → ai1/c.java：原请求 mix_mode==1 时，把 sms_code_key 用
                      StringUtils.encryptWithXor 再编码一次（XOR 0x05 → 小写 hex）
        → com/bytedance/sdk/account/impl/w.java：
              把 hashMap **合并进原始 sms_login 的请求参数**，然后 x.k()
              —— 即**原样重发那个 sms_login 请求**
        → 这次服务端放行，登录成功

    关键结论：**完成验证靠的是「重发 sms_login + biz_params」，不是把
    verify_ticket 传给登录接口**。verifyTicket 虽然进了 ai1/c.a() 的参数表，
    但方法体里**根本没用到**；真正起作用的是 biz_params 里的 sms_code_key。

    而 /passport/upsms/verify/ 只负责「服务端收到你的上行短信了吗」这一件事
    （轮询），它的 ticket 我们不依赖。

    参数 code：重发 sms_login 必须带**同一条**短信验证码，所以要传。
    """
    mobile = re.sub(r"\D", "", str(mobile or ""))
    if not re.fullmatch(r"1\d{10}", mobile):
        return {"ok": False, "error": "手机号格式不正确"}
    code = re.sub(r"\D", "", str(code or ""))
    if not re.fullmatch(r"\d{4,8}", code):
        return {"ok": False, "error": "验证码格式不正确"}
    ctx = load_mfa()
    if not ctx:
        return {"ok": False, "error": "没有待完成的验证，请先点「发送验证码」"}
    ways = [w.get("way") for w in (ctx.get("verifyWays") or [])]
    # 目前只打通了上行短信这条（mobile_up_sms_verify）。
    # 列表为空时不要直接拒：可能只是没带 verify_ways，继续试重放更稳。
    if ways and "mobile_up_sms_verify" not in ways:
        return {"ok": False,
                "error": "该账号要求的是「%s」验证，暂不支持" % "、".join(ways)}

    from urllib.parse import quote

    # ---- 第 1 步：轮询 upsms/verify，确认服务端已收到上行短信 ----
    # 它不接收验证码（页面上只有「编辑短信/发送至/提交」）。
    # 这一步没过不代表失败：用户可能还没发，前端会重试。
    parts = [("mobile", normalize_mobile(mobile))]
    for key, src in (("sms_code_key", "smsCodeKey"),
                     ("encrypt_uid", "encryptUid"),
                     ("verify_scene", "verifyScene"),
                     ("verify_reason", "verifyReason")):
        val = ctx.get(src)
        if val:
            parts.append((key, val))
    body = "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in parts)
    form = (_passport_form(mobile=normalize_mobile(mobile), with_device=True)
            + "&" + body)
    r = _call("POST", "/passport/upsms/verify/", form=form,
              host=PASSPORT_HOST, passport=True,
              cookie_extra=str(ctx.get("cookie") or ""))
    j = _json(r)
    data = j.get("data") if isinstance(j.get("data"), dict) else {}
    up_ok = bool(data.get("ticket") or data.get("verify_ticket"))
    if not up_ok:
        _ok, why, err_code = _passport_result(j)
        log_event("verify_mfa_pending", host=PASSPORT_HOST, http=r.status_code,
                  mobile=mask_mobile(mobile), error_code=err_code,
                  description=str(data.get("description") or why)[:120])
        return {"ok": False,
                "error": str(data.get("description") or why or "还没收到你的上行短信"),
                "error_code": err_code, "http": r.status_code,
                "pending": True}
    log_event("verify_mfa_upsms_ok", host=PASSPORT_HOST, http=r.status_code,
              mobile=mask_mobile(mobile))

    # ---- 第 2 步：重发 sms_login，带上 biz_params（这就是完成验证的动作）----
    biz = ctx.get("bizParams") if isinstance(ctx.get("bizParams"), dict) else {}
    if not biz:
        # 没有 biz_params 就没法重放（老版本存的上下文）。
        # 不要返回「ok=True + ticket」——ticket 在验证机制里根本没用，
        # 前端会以为可以继续登录却永远登不上。直接说清楚要重新发码。
        log_event("verify_mfa_no_biz", mobile=mask_mobile(mobile))
        return {"ok": False, "pending": True, "error_code": "no_biz",
                "error": "验证上下文已过期，请返回重新发送验证码"}
    # 重放请求体 = 原始 sms_login 参数 **被 biz_params 覆盖**。
    # 反编译 impl/w.java:30-31 做的是 `map2.putAll(map)`（biz 赢），
    # 所以不能把两段编码串直接拼起来 —— 那样同一个 key 会在 wire 上出现两次
    # （_passport_form 已经发过 mix_mode，biz 里也有 mix_mode 时就重复了）。
    # 这里改成先做有序 dict 合并，再统一编码一次。
    merged = _passport_form_params(mobile=normalize_mobile(mobile), code=code,
                                   with_device=True)
    for k, v in biz.items():
        # sms_code_key 必须**再编码一次**（ai1/c.java:36-37 明确这么做，
        # 且只在原请求 mix_mode==1 时）。其余 biz 字段原样回传。
        # 我们的 sms_login 恒发 mix_mode=1，所以条件成立。
        merged[str(k)] = xor_hex(v) if k == "sms_code_key" else str(v)
    form2 = "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in merged.items())
    r2 = _call("POST", "/passport/mobile/sms_login/", form=form2,
               host=PASSPORT_HOST, passport=True,
               cookie_extra=str(ctx.get("cookie") or ""))
    j2 = _json(r2)
    ok2, why2, err2 = _passport_result(j2)
    d2 = j2.get("data") if isinstance(j2.get("data"), dict) else {}
    if not ok2:
        log_event("verify_mfa_replay_failed", host=PASSPORT_HOST,
                  http=r2.status_code, mobile=mask_mobile(mobile),
                  error_code=err2,
                  description=str(d2.get("description") or why2)[:120])
        # 又被要求验证（2046/2139/2148/4023）：这是**一次新的挑战**，
        # 必须把新上下文存下来，否则用户没法再试（旧 ctx 已失效）。
        if err2 in MFA_CODES:
            ctx2 = _mfa_context(d2, _mfa_cookie(r2))
            if ctx2.get("schema") or ctx2.get("verifyWays") or ctx2.get("bizParams"):
                save_mfa(ctx2)
                log_event("verify_mfa_rechallenge", mobile=mask_mobile(mobile),
                          error_code=err2)
        return {"ok": False,
                "error": str(d2.get("description") or why2 or "验证后登录未通过"),
                "error_code": err2, "http": r2.status_code,
                "pending": err2 in MFA_CODES}
    log_event("verify_mfa_ok", host=PASSPORT_HOST, http=r2.status_code,
              mobile=mask_mobile(mobile), replayed=True)
    # _finish_login 已经返回完整的 {"ok":True,"code":0,"session":...}，
    # 直接透传（它会顺带 clear_mfa，把这次验证上下文清掉）。
    out = _finish_login(r2, mobile)
    out["replayed"] = True
    return out


def sms_login(mobile, code, ticket=""):
    """验证码登录。

    ticket 参数保留只为兼容旧调用方，**实际不再使用**：
    2026-10-08 反编译确认，完成 MFA 靠的是「重发 sms_login + biz_params」，
    verify_ticket 进了 ai1/c.a() 的参数表但方法体从未引用它 ——
    把它塞进登录请求是无效的（实测一直是 1203）。
    """
    mobile = re.sub(r"\D", "", str(mobile or ""))
    code = re.sub(r"\D", "", str(code or ""))
    if not re.fullmatch(r"1\d{10}", mobile):
        return {"ok": False, "error": "手机号格式不正确"}
    if not re.fullmatch(r"\d{4,8}", code):
        return {"ok": False, "error": "验证码格式不正确"}
    bad, hint = device_issue()
    if bad:
        log_event("sms_login_failed", ok=False, reason="device_unregistered",
                  mobile=mask_mobile(mobile))
        return {"ok": False, "error": hint, "error_code": "device"}
    form = _passport_form(mobile=normalize_mobile(mobile), code=code, with_device=True)
    if ticket:
        # 旧调用方还在传；记一笔以便发现没清理干净的路径，但不发出去。
        log_event("sms_login_ticket_ignored", mobile=mask_mobile(mobile))
    r = _call("POST", "/passport/mobile/sms_login/", form=form,
              host=PASSPORT_HOST, passport=True)
    j = _json(r)
    ok, why, err_code = _passport_result(j)
    data = j.get("data") if isinstance(j.get("data"), dict) else {}
    if not ok and r.status_code in (401, 403) and not r.text.strip():
        why, err_code = hint, "device"
    # 2046 = 需要身份验证，不是「被限流」。把验证上下文存下来并交给前端，
    # 让用户按提示完成验证后继续登录（原来这里当失败处理，流程走不通）。
    if not ok and err_code in MFA_CODES:
        ctx = _mfa_context(data, _mfa_cookie(r))
        # 判据不能只看 verifyWays/smsCodeKey：2046 也可能只带 schema+url+
        # biz_params（验证方式列表为空），那种情况同样是「要你去做验证」。
        # 反编译 ai1/d.java 的入闸条件就是 schema 与 url 都非空。
        if ctx.get("verifyWays") or ctx.get("smsCodeKey") or \
                (ctx.get("schema") and ctx.get("url")) or ctx.get("bizParams"):
            save_mfa(ctx)
            log_event("sms_login_mfa", host=PASSPORT_HOST, http=r.status_code,
                      mobile=mask_mobile(mobile), ways=len(ctx["verifyWays"]),
                      has_key=bool(ctx["smsCodeKey"]))
            return {"ok": False, "mfaRequired": True, "mfa": ctx,
                    "error": "该账号需要先完成身份验证", "error_code": err_code}
    if not ok:
        log_event("sms_login_failed", host=PASSPORT_HOST, http=r.status_code,
                  mobile=mask_mobile(mobile), code_len=len(code),
                  error_code=err_code, message=str(j.get("message"))[:80],
                  description=str(data.get("description") or why)[:120])
        return {"ok": False, "code": err_code if err_code is not None else j.get("code"),
                "error": why or "登录失败", "error_code": err_code,
                "http": r.status_code}
    return _finish_login(r, mobile)


def _mask_uid(value):
    """把 uid 变成「同一账号稳定、但看不出原文」的短标识。

    红果的 uid 形如 `#c1967_<base64>`，base64 解开就是明文 user_id
    （实测 `MTk2NzE5...` -> `19671967196719676...`）。
    mobile 已经脱敏，uid 却原样返回给前端并写进 localStorage，口径不一致。
    这里用 sha256 前 16 位代替：仍然唯一、仍然稳定（前端靠它做换号隔离），
    但不再携带明文 user_id。
    """
    text = str(value or "")
    if not text:
        return ""
    return "u" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def public_session(session=None):
    s = session if session is not None else load_session()
    bad, hint = device_issue()
    return {
        "loggedIn": bool(s.get("cookie") or s.get("token")),
        "userName": s.get("user_name") or "",
        "uid": _mask_uid(s.get("uid")),
        "mobile": (s.get("mobile") or "")[:3] + "****" + (s.get("mobile") or "")[-4:]
        if s.get("mobile") else "",
        "savedAt": s.get("saved_at") or 0,
        # 设备身份状态：没有它验证码接口会被服务端 403（空 body），
        # 前端要据此提示用户走「从模拟器同步」而不是反复点发送。
        "deviceReady": not bad,
        "deviceHint": hint,
    }


# ---- 观看进度 / 历史 ------------------------------------------------------
def sync_progress(series_id, episode, total=0, position=0, duration=0, series=None):
    """把桌面端的观看进度上报到账号（手机“历史”页立即可见）。

    合并规则：同一剧集「取更靠前的进度」，不允许把云端进度改小。
    否则会出现：手机看到 520 集，PC 本地停在 500 集，PC 一上报就把 520 覆盖成 500。
    所以上报前先读云端，只有本地确实更靠前时才写。
    """
    if not is_logged_in():
        return {"ok": False, "error": "未登录红果账号"}
    series_id = str(series_id)
    if not re.fullmatch(r"[0-9]{8,24}", series_id):
        return {"ok": False, "error": "剧集标识不合法"}
    episode = int(episode)
    if not 1 <= episode <= 100000:
        return {"ok": False, "error": "集号不合法"}
    # 先比云端：本地不更靠前就跳过，避免把多端的进度改小。
    try:
        cloud = remote_progress(series_id)
    except Exception:
        cloud = {"ok": False}
    if cloud.get("ok"):
        cloud_ep = int(cloud.get("episode") or 0)
        cloud_pos = int(cloud.get("position") or 0)
        if cloud_ep > episode:
            log_event("progress_skipped", reason="cloud_ahead",
                      cloud_episode=cloud_ep, local_episode=episode)
            return {"ok": True, "skipped": True, "episode": cloud_ep,
                    "reason": "云端进度更靠前，保持不变"}
        if cloud_ep == episode and cloud_pos > int(max(0, position)):
            log_event("progress_skipped", reason="cloud_position_ahead",
                      cloud_episode=cloud_ep, local_position=int(max(0, position)))
            return {"ok": True, "skipped": True, "episode": cloud_ep,
                    "reason": "云端播放位置更靠前，保持不变"}
    vid = ""
    try:
        _, episodes = H.get_episodes(series_id)
        target = next((it for it in episodes if int(it.get("index") or 0) == episode), None)
        if target:
            vid = str(target.get("vid") or "")
    except Exception:
        vid = ""
    now = int(time.time() * 1000)
    # 字段对齐手机端实测格式（2026-10-08 抓包，mitmproxy 解明文）。
    # 手机端 POST /reading/bookapi/read_history/update/v 的 update_datas[0] 有 26 个字段；
    # 我们原来只传 14 个。差异与取舍：
    #   * use_soft_delete: 手机传 false，我们原来传 True。
    #     这个字段服务端**不存**（返回里没有），但语义上是「软删除」开关，
    #     传 True 有被理解成「标记删除」的风险，改成 false 对齐手机。
    #   * update_timestamp_ms: 手机传 0，我们原来传 now。
    #     服务端同样不存。传 0 对齐手机（避免影响服务端的更新时间推断）。
    #   * chapter_index: 手机不传（服务端返回里也没有），但我们传了且**服务端保留了**，
    #     说明这个值对我们有用（列表显示「上次看到第 N 集」），保留。
    #   * book_id_str / genre_type: 手机不传，服务端会自己补。
    #     我们传了也无害（服务端保留），保留以便服务端少做一次补全。
    #   * 其余手机端有而我们没有的 14 个字段（digged_count / is_listen_mode /
    #     is_multi_season / season_index / series_play_cnt / tone_id / recent_reads /
    #     origin_novel_book_id / user_digg / is_interactive_game /
    #     meet_guide_comment_tag / retain_video_play_time / user_playlet_comment_flag）
    #     全是 0/false 的默认值，服务端会自行补默认，不传等价。
    #   * vid: 手机必传（服务端返回里也有），我们本来就在传，保留。
    item = {
        "book_id": int(series_id),
        "book_id_str": series_id,
        "book_type": 2,
        "vid_index": episode,
        "chapter_index": episode,
        "read_timestamp_ms": now,
        "update_timestamp_ms": 0,
        "current_play_position": int(max(0, position)),
        "player_accumulate_total_time": int(max(0, position)),
        "duration": int(max(0, duration)),
        "episode_cnt": int(max(0, total)),
        "is_delete": False,
        "use_soft_delete": False,
        "genre_type": 2150,
    }
    if vid and re.fullmatch(r"\d{8,24}", vid):
        item["vid"] = int(vid)
    if series and isinstance(series, dict):
        if series.get("title"):
            item["book_name"] = str(series["title"])[:120]
        if series.get("cover"):
            item["thumb_url"] = str(series["cover"])[:400]
    r = _call("POST", "/reading/bookapi/read_history/update/v",
              body={"update_datas": [item]})
    j = _json(r)
    if j.get("code") not in (0, "0"):
        log_event("progress_failed", series_id=series_id, episode=episode,
                  code=j.get("code"), message=str(j.get("message"))[:80])
        return {"ok": False, "code": j.get("code"),
                "error": j.get("message") or "上报失败"}
    fails = ((j.get("data") or {}).get("update_fail_datas") or []) if isinstance(j.get("data"), dict) else []
    # 成功也要记一笔：原先只有「跳过」才写日志，导致事后排查时
    # 「一次 progress 都没有」既可能是没上报、也可能是上报成功没记，
    # 无法区分（2026-10-07 排查时就踩了这个坑）。
    log_event("progress_ok", series_id=series_id, episode=episode,
              position=int(max(0, position)), total=int(max(0, total)),
              has_vid=bool(vid), failed=len(fails))
    return {"ok": not fails, "code": 0, "episode": episode, "failed": len(fails)}


def _history_raw(limit=30):
    """读一次云端历史原始列表（内部用）。"""
    r = _call("GET", "/reading/bookapi/read_history/list/v", extra={
        "book_type": "2", "offset": "0", "limit": str(int(limit)),
        "query_soft_deleted": "false", "is_first_load": "false",
        "last_min_read_timestamp_ms": "0", "full_field": "false"})
    return _json(r)


# 服务端单次返回有硬上限。2026-10-07 实测：账号有 574 条历史，
# 无论 limit 传 50/200/497/574/1000/2000，都只返回 497 条，
# 必须靠 offset 翻页才能拿全（翻页累计 571 条）。
_HISTORY_PAGE = 200
_HISTORY_PAGE_MAX = 20        # 最多 4000 条，防跑飞


def _history_all(max_items=2000):
    """翻页取云端历史，返回 (items, total, ok, error)。

    只在**需要看全量**的场合用（例如查某部剧的云端进度 —— 只读第一页的话，
    排在后面的剧会被当成「云端没有」，progress 判成 0，
    合并逻辑随后可能用本地较低的进度把它覆盖掉。实测 574 条里有 77 条
    落在第一页之外）。

    注意：翻页 = 多一次往返（实测单次 3.4 秒），
    给界面用的列表**不要**走这里，用 _history_page()。
    """
    items = []
    seen = set()
    total = 0
    last = {"ok": False, "error": ""}
    for page in range(_HISTORY_PAGE_MAX):
        offset = page * _HISTORY_PAGE
        try:
            r = _call("GET", "/reading/bookapi/read_history/list/v", extra={
                "book_type": "2", "offset": str(offset), "limit": str(_HISTORY_PAGE),
                "query_soft_deleted": "false", "is_first_load": "false",
                "last_min_read_timestamp_ms": "0", "full_field": "false"})
            j = _json(r)
        except Exception as exc:
            last = {"ok": False, "error": "%s" % type(exc).__name__}
            break
        if j.get("code") not in (0, "0"):
            last = {"ok": False, "code": j.get("code"),
                    "error": j.get("message") or "读取失败"}
            break
        data = j.get("data") or {}
        total = int(data.get("total") or 0) or total
        chunk = data.get("data_list") or []
        if not chunk:
            last = {"ok": True, "error": ""}
            break
        fresh = 0
        for it in chunk:
            key = str(it.get("book_id_str") or it.get("book_id") or "")
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            items.append(it)
            fresh += 1
            if len(items) >= max_items:
                break
        last = {"ok": True, "error": ""}
        # 本页没有新条目 = 服务端开始重复返回，停。
        if fresh == 0 or len(items) >= max_items:
            break
    return items, total, last["ok"], last.get("error", "")


def _history_page(limit=200):
    """只取第一页（服务端已按「最近观看」降序返回）。

    给界面列表用：一次往返即可，且最新的条目一定在第一页。
    翻页留给 remote_progress 那种「必须确认某条在不在」的场合。
    """
    try:
        r = _call("GET", "/reading/bookapi/read_history/list/v", extra={
            "book_type": "2", "offset": "0", "limit": str(int(limit)),
            "query_soft_deleted": "false", "is_first_load": "false",
            "last_min_read_timestamp_ms": "0", "full_field": "false"})
        j = _json(r)
    except Exception as exc:
        return [], 0, False, "%s" % type(exc).__name__
    if j.get("code") not in (0, "0"):
        return [], 0, False, j.get("message") or "读取失败"
    data = j.get("data") or {}
    return (data.get("data_list") or [], int(data.get("total") or 0), True, "")


def remote_progress(series_id):
    """查单部剧在云端的进度（用于「取最新」合并，避免把进度改小）。

    必须翻页找：只读第一页的话，排在后面的剧会被误判成「云端 0 集」，
    合并逻辑随后就可能用本地较低的进度把它覆盖掉。
    """
    if not is_logged_in():
        return {"ok": False, "error": "未登录红果账号"}
    series_id = str(series_id)
    if not re.fullmatch(r"[0-9]{8,24}", series_id):
        return {"ok": False, "error": "剧集标识不合法"}
    items, _total, ok, error = _history_all()
    if not ok:
        return {"ok": False, "error": error or "读取失败"}
    for it in items:
        if str(it.get("book_id_str") or it.get("book_id") or "") == series_id:
            return {"ok": True,
                    "episode": int(it.get("vid_index") or it.get("chapter_index") or 0),
                    "position": int(it.get("current_play_position") or 0),
                    "updatedAt": int(it.get("read_timestamp_ms") or 0)}
    return {"ok": True, "episode": 0, "position": 0, "updatedAt": 0}


def remote_history(limit=30):
    if not is_logged_in():
        return {"ok": False, "error": "未登录红果账号"}
    # 界面列表只需第一页：服务端已按「最近观看」降序返回，
    # 最新的条目一定在第一页。翻页留给 remote_progress（要确认某条在不在）。
    raw, total, ok, error = _history_page(limit=max(1, int(limit)))
    if not ok:
        return {"ok": False, "error": error or "读取失败"}
    items = []
    for it in raw:
        items.append({
            "seriesId": str(it.get("book_id_str") or it.get("book_id") or ""),
            "title": it.get("book_name") or "",
            "cover": it.get("thumb_url") or "",
            "episode": int(it.get("vid_index") or it.get("chapter_index") or 1),
            "position": int(it.get("current_play_position") or 0),
            "total": int(it.get("episode_cnt") or 0),
            "updatedAt": int(it.get("read_timestamp_ms") or 0),
        })
    return {"ok": True, "total": total or len(items), "items": items}


# ---- 收藏（短剧书架） -----------------------------------------------------
def set_favorite(series_id, favorite):
    if not is_logged_in():
        return {"ok": False, "error": "未登录红果账号"}
    series_id = str(series_id)
    if not re.fullmatch(r"[0-9]{8,24}", series_id):
        return {"ok": False, "error": "剧集标识不合法"}
    body = {"update_bookshelf_video_list": [{
        "book_id": series_id,
        "book_type": 2,
        "video_shelf_operate_type": 0 if favorite else 1,
        "modify_time": int(time.time() * 1000),
        "group_name": "",
    }]}
    r = _call("POST", "/reading/bookapi/bookshelf/video/update/v", body=body)
    j = _json(r)
    if j.get("code") not in (0, "0"):
        return {"ok": False, "code": j.get("code"), "error": j.get("message")}
    return {"ok": True, "favorite": bool(favorite)}


def remote_favorites():
    if not is_logged_in():
        return {"ok": False, "error": "未登录红果账号"}
    r = _call("GET", "/reading/bookapi/bookshelf/video/list/v")
    j = _json(r)
    if j.get("code") not in (0, "0"):
        return {"ok": False, "code": j.get("code"), "error": j.get("message")}
    info = ((j.get("data") or {}).get("video_shelf_info") or [])
    items = []
    for it in info:
        items.append({
            "seriesId": str(it.get("series_id") or it.get("book_id") or ""),
            "contentType": int(it.get("content_type") or 0),
            "addedAt": int(it.get("collect_time") or it.get("modify_time") or 0),
        })
    # 书架接口只给 id，没有封面/标题。
    # 前端卡片必须要有 cover（还要能解析出封面地址），否则收藏页只有文字没有图。
    # 所以这里用剧集接口把封面和标题补齐。
    ids = [x["seriesId"] for x in items if x["seriesId"]]
    if ids:
        meta = _series_meta(ids)
        for x in items:
            m = meta.get(x["seriesId"]) or {}
            x["title"] = m.get("title") or ""
            x["cover"] = m.get("cover") or ""
            x["episodeCount"] = int(m.get("episodeCount") or 0)
    return {"ok": True, "items": items}


def _series_meta(series_ids):
    """批量取剧集的标题/封面/集数（收藏补封面用）。取不到就返回空，不影响主流程。"""
    out = {}
    ids = [str(s) for s in series_ids if re.fullmatch(r"[0-9]{8,24}", str(s or ""))]
    if not ids:
        return out
    try:
        # get_episodes_batch 返回 (剧集表, ...)，剧集表是 {series_id: 剧集信息}。
        batch = H.get_episodes_batch(ids)
        series_map = batch[0] if isinstance(batch, (list, tuple)) and batch else batch
        for sid, meta in (series_map or {}).items():
            if not isinstance(meta, dict):
                continue
            out[str(sid)] = {
                "title": meta.get("title") or "",
                "cover": meta.get("cover") or "",
                "episodeCount": int(meta.get("episode_cnt") or meta.get("episodeCount") or 0),
            }
    except Exception:
        pass
    return out

# ---- 从模拟器同步登录态 ---------------------------------------------------
def _adb():
    import subprocess
    adb = os.environ.get("ADB", r"D:\Tools\adb\adb.exe")
    dev = os.environ.get("ADB_DEVICE", "127.0.0.1:16448")
    return adb, dev


def _adb_shell(cmd, timeout=25):
    import subprocess
    adb, dev = _adb()
    try:
        out = subprocess.run([adb, "-s", dev, "shell", cmd],
                             capture_output=True, timeout=timeout)
    except Exception:
        return ""
    return out.stdout.decode("utf-8", "replace")


def sync_from_emulator():
    """在模拟器里已登录的前提下，把该会话同步到桌面端。

    只读 App 自己的会话数据（不改动 App、不注入进程）。
    """
    pkg = "com.phoenix.read"
    prefs = "/data/data/%s/shared_prefs" % pkg

    token = ""
    cookie = ""

    # 1) 会话数据可能落在若干 prefs 文件里，逐个找
    names = _adb_shell("ls %s 2>/dev/null" % prefs).split()
    for name in names:
        if not name.endswith(".xml"):
            continue
        low = name.lower()
        if not any(k in low for k in ("account", "passport", "session", "token",
                                      "login", "cookie", "sid", "user")):
            continue
        body = _adb_shell("cat %s/%s" % (prefs, name))
        if not body:
            continue
        if not token:
            for pat in (r'name="x-tt-token"[^>]*>([^<]+)<',
                        r'name="x_tt_token"[^>]*>([^<]+)<',
                        r'name="token"[^>]*>([^<]+)<'):
                m = re.search(pat, body)
                if m and len(m.group(1)) > 40:
                    token = m.group(1).strip()
                    break
        if not cookie:
            m = re.search(r'name="[^"]*cookie[^"]*"[^>]*>([^<]{40,})<', body, re.I)
            if m:
                cookie = m.group(1).strip()

    # 2) WebView 的 Cookie 持久化库（SQLite）：直接读字节再本地匹配，
    #    避免在 shell 里拼正则。
    if not cookie:
        import re as _re
        for cand in ("%s/../app_webview/Default/Cookies" % prefs,
                     "%s/../app_webview/Cookies" % prefs):
            blob = _adb_shell("cat %s 2>/dev/null" % cand, timeout=30)
            if not blob:
                continue
            m = _re.search(r"sessionid=([0-9a-f]{32})", blob)
            if m:
                sid = m.group(1)
                cookie = "sessionid=%s; sessionid_ss=%s; sid_tt=%s" % (sid, sid, sid)
                break

    if not (token or cookie):
        return {"ok": False, "error":
                "模拟器里没有可用的登录态。请确认：1) MuMu 模拟器已启动；"
                "2) 模拟器里装了红果（com.phoenix.read）并已登录；"
                "3) 已执行过 adb connect / adb root（读应用私有目录需要 root）。"}

    # 先在内存里构造并验证，通过之后才落盘。
    # 之前是「先 save_session 再验」，验证失败也不回滚 ——
    # 于是模拟器里抓到的坏凭据会覆盖掉原本可用的登录态。
    # 也不再用 load_session() 做基底：失败时不能污染既有会话。
    session = {}
    if token:
        session["token"] = token
    if cookie:
        session["cookie"] = cookie
    session["saved_at"] = int(time.time())
    session["source"] = "emulator"

    # 立刻验一次，确认真的能用
    info = _json(_call("GET", "/reading/user/info/v", session=session))
    data = info.get("data") if isinstance(info.get("data"), dict) else {}
    if info.get("code") in (0, "0") and data:
        session["user_name"] = data.get("user_name") or ""
        session["uid"] = str(data.get("user_id") or "")
        save_session(session)
        log_event("sync_from_emulator", ok=True, has_token=bool(token),
                  has_cookie=bool(cookie), user=bool(session["user_name"]))
        return {"ok": True, "session": public_session(session)}
    log_event("sync_from_emulator", ok=False, has_token=bool(token),
              has_cookie=bool(cookie), code=info.get("code"))
    return {"ok": False, "error": "同步到的登录态无效，请在模拟器里重新登录"}
