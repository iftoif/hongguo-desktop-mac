# -*- coding: utf-8 -*-
"""红果短剧 API 服务
部署在服务器,客户端连接后可搜索/看榜单/取剧集/拿视频直链。
签名由后端(Frida预言机/未来redroid/unidbg)提供,客户端无需签名。

启动: python server.py   (或 uvicorn server:app --host 0.0.0.0 --port 8000)

接口:
  GET /search?q=剧名
  GET /rank?board=recommend|hot|new&limit=30
  GET /filters?genre=comic_series         取某体裁全部筛选条件(实时)
  GET /browse?genre=ai_series&theme=玄幻&sort=hot_score&days=7   按筛选浏览(多选逗号分隔)
  GET /episodes?series_id=xxx
  GET /play?series_id=xxx&ep=1            取剧集信息(encrypted_url密文直链 + stream_url可播)
  GET /stream?series_id=xxx&ep=1          ★服务端【纯离线解密】后串流, 客户端拿到可播mp4
  GET /stream?vid=xxx&quality=1080p       也可直接按 vid + 清晰度; 支持 Range 拖动; <video>用?api_key=
"""
import re, os, io, time, threading, sys
from fastapi import FastAPI, HTTPException, Query, Depends, Request, Body
from fastapi.responses import StreamingResponse, JSONResponse, Response, FileResponse
import requests, urllib3
import hongguo as H

# 离线解密(纯算法, 无app): spade_a → content key → AES-128-CTR 解密
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida"))
import offline_decrypt as OD
import offline_dl as ODL

STREAM_CACHE = os.environ.get("HONGGUO_STREAM_CACHE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads", ".stream_cache")
# 本地维护: 有界 LRU。原先每集每档位建一个锁且永不回收，
# 长跑后无界增长。这里最多保留 256 个，超出即淘汰最久未用的。
_dec_locks = {}; _dec_guard = threading.Lock()
_HQ_DEC_LOCKS_MAX = 256
def _dec_lock(key):
    with _dec_guard:
        lock = _dec_locks.pop(key, None)
        if lock is None:
            lock = threading.Lock()
        _dec_locks[key] = lock          # 重新插入到末尾 = 最近使用
        while len(_dec_locks) > _HQ_DEC_LOCKS_MAX:
            _dec_locks.pop(next(iter(_dec_locks)))
        return lock

def _hq_cache_path(vid, safe_q):
    """把 vid + 档位解析成缓存文件路径，并强制它落在 STREAM_CACHE 之内。

    为什么必须有这一层：/stream 的 vid 完全来自调用方，而 os.path.join
    在 Windows 上遇到绝对路径会丢弃前缀，
    vid="C:/.../x" 就能让 out 指到缓存目录之外。
    实测（2026-10-07）可读到本机任意 mp4 文件。
    这里要求 vid 是纯数字集号，再对最终路径做 realpath 包含校验，双保险。
    """
    text = str(vid or "")
    if not re.fullmatch(r"[0-9]{1,32}", text):
        raise HTTPException(400, "Invalid media id")
    root = os.path.realpath(STREAM_CACHE)
    out = os.path.realpath(os.path.join(root, f"{text}_{safe_q}.mp4"))
    if out != root and not out.startswith(root + os.sep):
        raise HTTPException(400, "Cache path escapes stream cache")
    return out

def _vm_track(vid, quality="best"):
    """取该集指定清晰度的 (main_url, spade_a, encrypt, definition, size)。"""
    vm = ODL._video_model(vid)
    if not vm:
        return None
    tracks = H.video_model_tracks(vm)
    tr, defn, _ = ODL._pick_track(tracks, quality)
    if not tr:
        return None
    enc = tr.get("encrypt_info") or {}
    meta = tr.get("video_meta") or {}
    return {"url": tr.get("main_url"), "spade_a": enc.get("spade_a"),
            "encrypt": bool(enc.get("encrypt")),
            "definition": meta.get("definition") or defn, "size": meta.get("size", 0)}

def _ensure_decrypted(vid, quality="best"):
    """下载 CDN 密文 + 纯离线解密, 返回缓存的明文 mp4 路径(已缓存则直接返回)。"""
    os.makedirs(STREAM_CACHE, exist_ok=True)
    safe_q = re.sub(r"[^\w]", "", str(quality)) or "best"
    out = _hq_cache_path(vid, safe_q)
    if os.path.exists(out) and os.path.getsize(out) > 0:
        return out
    # offline_decrypt() falls back to a `.raw.mp4` path when ffmpeg is not
    # installed.  Treat that returned path as the cache artifact instead of
    # constructing a non-existent FileResponse target.
    raw = os.path.splitext(out)[0] + ".raw.mp4"
    if os.path.exists(raw) and os.path.getsize(raw) > 0:
        from desktop_remux import remux
        with _dec_lock(f"{vid}_{safe_q}"):
            return out if os.path.exists(out) else remux(raw, out)
    with _dec_lock(f"{vid}_{safe_q}"):                  # 同集并发请求只解一次
        if os.path.exists(out) and os.path.getsize(out) > 0:
            return out
        if os.path.exists(raw) and os.path.getsize(raw) > 0:
            from desktop_remux import remux
            return remux(raw, out)
        t = _vm_track(vid, quality)
        if not t or not t["url"]:
            raise HTTPException(404, "无直链/video_model")
        if not t["encrypt"]:
            H.download_file(t["url"], out)
            return out
        ct = out + ".enc"
        H.download_file(t["url"], ct)
        r = OD.offline_decrypt(t["spade_a"], ct, out)
        try:
            os.remove(ct)
        except OSError:
            pass
        if not (r and os.path.exists(r) and os.path.getsize(r) > 0):
            raise HTTPException(500, "解密失败(spade 异常或 ver2 视频?)")
        if os.path.abspath(r) != os.path.abspath(out):
            from desktop_remux import remux
            r = remux(r, out)
            if os.path.isfile(raw):
                os.remove(raw)
        return r

urllib3.disable_warnings()
app = FastAPI(title="红果短剧 API", version="1.0")

# 图片转换(HEIC->JPEG, 浏览器不支持HEIC)
try:
    from PIL import Image
    import pillow_heif
    pillow_heif.register_heif_opener()
    _IMG_OK = True
except Exception:
    _IMG_OK = False
# 本地维护: 有界封面缓存。原先是无上限 dict，长跑只增不减。
_img_cache = {}; _HQ_IMG_CACHE_MAX = 512


def _hq_img_cache_put(url, data):
    """写入封面缓存；超出上限就丢弃最旧的条目。"""
    _img_cache[url] = data
    while len(_img_cache) > _HQ_IMG_CACHE_MAX:
        _img_cache.pop(next(iter(_img_cache)), None)
_IMG_HOSTS = ("fqnovelpic.com", "byteimg.com", "qznovelvod.com", "douyinpic.com", "pstatp.com")

# ---- 鉴权(强制) + 限流 + 密钥管理 ----
# 数据接口强制要求有效密钥(来自 apikeys.json, 经 /admin 管理); 客户端不带有效密钥=401。
# ADMIN_TOKEN: 进入 /admin 管理页/接口的口令(与普通密钥分离)。
from apikeys import KeyStore
_keys = KeyStore()
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
if not ADMIN_TOKEN:
    import secrets as _sec
    ADMIN_TOKEN = _sec.token_hex(32)
    print("[server] 使用进程内临时管理口令；口令不输出、不持久化。")
RATE_PER_MIN = int(os.environ.get("RATE_PER_MIN", "120"))
_rl = {}
_rl_lock = threading.Lock()

# 免鉴权路径: 首页/网页/封面图/文档/管理页(管理页自己用 ADMIN_TOKEN 校验)
# 本地维护: 去掉 /docs、/openapi.json、/redoc ——
# 它们免鉴权却泄漏完整路由与参数清单，而前端一处都没用到。
_EXEMPT = ("/", "/ui", "/img", "/favicon.ico")
_ADMIN_PREFIX = "/admin"


def _check_admin(request: Request) -> bool:
    tok = request.headers.get("x-admin-token") or request.query_params.get("admin_token") or ""
    return bool(tok) and tok == ADMIN_TOKEN


@app.middleware("http")
async def auth_mw(request: Request, call_next):
    path = request.url.path
    if path == "/stats" or path.startswith(_ADMIN_PREFIX):
        # 管理/统计: 由各自处理器用 ADMIN_TOKEN 校验
        pass
    elif path in _EXEMPT:
        # 本地维护: 免鉴权路径也要限流。
        # /img 必须免鉴权（<img> 标签带不了请求头），但之前连限流
        # 也绕过了，本机任意进程能拿它当无限图片代理。
        _now = time.time()
        with _rl_lock:
            _bucket = _rl.setdefault(("hq_exempt", path), [])
            while _bucket and _bucket[0] < _now - 60:
                _bucket.pop(0)
            if len(_bucket) >= 120:
                return JSONResponse({"detail": "超过限流 120/分钟"}, status_code=429)
            _bucket.append(_now)
    else:
        key = request.headers.get("x-api-key") or request.query_params.get("api_key") or ""
        if not _keys.is_valid(key):            # 强制: 必须有效密钥
            _stats["auth_fail"] += 1
            return JSONResponse({"detail": "缺少或无效的 api_key(请在客户端配置本地链路密钥)"}, status_code=401)
        now = time.time()
        with _rl_lock:
            desktop_segments = path.startswith("/desktop/hls/")
            limit = 600 if desktop_segments else RATE_PER_MIN
            bucket = _rl.setdefault((key, desktop_segments), [])
            while bucket and bucket[0] < now - 60:
                bucket.pop(0)
            if len(bucket) >= limit:
                return JSONResponse({"detail": f"超过限流 {limit}/分钟"}, status_code=429)
            bucket.append(now)
        _stats["requests"] += 1
    resp = await call_next(request)
    if resp.status_code >= 500:
        _stats["errors"] += 1
    return resp


# 本地维护: 单次展开的集数上限。上游 /episodes 返回的集数可被构造得很大，
# 无上界时 parse_range 会一次性建出百万级列表并把上游拖死。
_HQ_RANGE_MAX = 2000


def parse_range(ep, total):
    """'1' / '1-10' / 'all' -> 集号列表"""
    total = min(int(total or 0), _HQ_RANGE_MAX)
    if not ep or ep == "all":
        return list(range(1, total + 1))
    m = re.match(r"(\d+)-(\d+)$", ep)
    if m:
        return list(range(int(m.group(1)), int(m.group(2)) + 1))
    if ep.isdigit():
        return [int(ep)]
    return []


_stats = {"start": time.time(), "requests": 0, "errors": 0, "risk": 0, "auth_fail": 0}


@app.get("/")
def index():
    return {"service": "红果短剧API", "ui": "/ui", "endpoints": [
        "/search?q=", "/rank?board=recommend|hot|new&limit=",
        "/latest?genre=short_play|comic_series|ai_series&only_today=true",
        "/filters?genre=comic_series", "/browse?genre=ai_series&theme=玄幻&sort=hot_score&days=7",
        "/episodes?series_id=", "/play?series_id=&ep=1-10",
        "/download?series_id=&ep=1-10", "/download/status?task_id=",
        "/stream?series_id=&ep=1 (解密可播)", "/stream?vid=&quality=1080p", "/stats"]}


@app.get("/stats")
def stats(request: Request):
    if not _check_admin(request):
        raise HTTPException(401, "需要 admin_token")
    import safeguards as SG
    up = int(time.time() - _stats["start"])
    # 签名后端健康
    backends = []
    for b in H.SIGN_SERVERS:
        try:
            rr = requests.get(b.rstrip("/") + "/", timeout=5).json()
            backends.append({"url": b, "ready": rr.get("ready"), "pid": rr.get("pid")})
        except Exception as e:
            backends.append({"url": b, "ready": False, "error": str(e)})
    return {"uptime_s": up, **{k: _stats[k] for k in ("requests", "errors", "risk", "auth_fail")},
            "cache_backend": "redis" if SG._redis else "memory",
            "sign_backends": backends,
            "download_tasks": len(H.manager().status())}


def _hq_static_page(name):
    """读 backend/web/<name>；打包版没有这个目录，缺就 404 而不是 500。"""
    from fastapi.responses import FileResponse
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", name)
    if not os.path.isfile(path):
        raise HTTPException(404, "该页面未包含在当前安装包中")
    return FileResponse(path)


@app.get("/ui")
def ui():
    return _hq_static_page("index.html")


def _hq_host_allowed(host, hosts):
    """域名白名单判定。必须带前导点，否则 evilfqnovelpic.com 会被放行。"""
    host = (host or "").lower()
    return any(host == h or host.endswith("." + h) for h in hosts)


def _hq_img_fetch(url, hosts, max_hops=3):
    """取封面图，手动跟随重定向，且每一跳都重新校验域名。

    requests 默认自动跟随 302，若允许域名上存在开放重定向，
    就能把请求打到任意 host —— 等于绕过 _IMG_HOSTS 白名单（SSRF）。
    这里显式禁止自动跟随，逐跳校验 Location。
    """
    from urllib.parse import urlparse, urljoin
    current = url
    for _ in range(max_hops + 1):
        u = urlparse(current)
        if u.scheme not in ("http", "https") or not _hq_host_allowed(u.hostname, hosts):
            raise HTTPException(400, "图片域名不允许")
        r = requests.get(current, timeout=30, verify=True, allow_redirects=False,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code not in (301, 302, 303, 307, 308):
            return r
        loc = r.headers.get("location") or ""
        if not loc:
            return r
        current = urljoin(current, loc)
    raise HTTPException(400, "图片重定向过多")


@app.get("/img")
def api_img(url: str):
    """图片代理。红果封面常返回 HEIC，浏览器不支持时转成 JPEG。"""
    from urllib.parse import urlparse
    try:
        raw = (url or "").strip()
        u = urlparse(raw)
        host = (u.hostname or "").lower()
        allowed = u.scheme in ("http", "https") and any(host == h or host.endswith("." + h) for h in _IMG_HOSTS)
        if not allowed:
            raise HTTPException(400, "图片域名不允许")
        cached = _img_cache.get(raw)
        if cached is not None:
            return Response(cached, media_type="image/jpeg", headers={"Cache-Control": "max-age=86400"})
        r = _hq_img_fetch(raw, _IMG_HOSTS)
        r.raise_for_status()
        content_type = (r.headers.get("content-type") or "").lower()
        data = r.content
        if _IMG_OK and ("heic" in content_type or u.path.lower().endswith(".heic")):
            img = Image.open(io.BytesIO(data))
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            out = io.BytesIO()
            img.save(out, format="JPEG", quality=88, optimize=True)
            data = out.getvalue()
            _hq_img_cache_put(raw, data)
            return Response(data, media_type="image/jpeg", headers={"Cache-Control": "max-age=86400"})
        return Response(data, media_type=content_type or "image/jpeg", headers={"Cache-Control": "max-age=86400"})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(404, f"图片读取失败: {e}")


# ---------------- 密钥管理(需 ADMIN_TOKEN) ----------------
def _mask(k: str) -> str:
    return (k[:6] + "****" + k[-4:]) if len(k) > 12 else "****"


@app.get("/admin")
def admin_page():
    return _hq_static_page("admin.html")


@app.get("/admin/keys")
def admin_list_keys(request: Request):
    if not _check_admin(request):
        raise HTTPException(401, "admin_token 无效")
    return {"keys": _keys.list(), "enabled_count": _keys.count_enabled()}


@app.post("/admin/keys")
def admin_gen_key(request: Request, note: str = ""):
    if not _check_admin(request):
        raise HTTPException(401, "admin_token 无效")
    key = _keys.generate(note)
    return {"ok": True, "key": key, "note": note}


@app.post("/admin/keys/revoke")
def admin_revoke_key(request: Request, key: str, enable: bool = False):
    if not _check_admin(request):
        raise HTTPException(401, "admin_token 无效")
    return {"ok": _keys.revoke(key, enabled=enable)}


@app.delete("/admin/keys")
def admin_delete_key(request: Request, key: str):
    if not _check_admin(request):
        raise HTTPException(401, "admin_token 无效")
    return {"ok": _keys.delete(key)}


from search_pages import SearchPager
_search_pager = SearchPager(lambda params: H.api("GET", "/reading/bookapi/search/tab/v", extra_query=params, max_retries=1), H._parse_search_cell)


@app.get("/search/page")
def api_search_page(q: str = Query(..., min_length=1, max_length=80), cursor: str = Query(None, max_length=128)):
    try:
        return _search_pager.page(q, cursor)
    except Exception as error:
        raise HTTPException(502, {"code": "SEARCH_PAGE_FAILED", "error_type": type(error).__name__,
                                  "safe_response": getattr(error, "safe_response", None)})


@app.get("/search")
def api_search(q: str = Query(..., description="剧名"),
              limit: int = Query(None, ge=1, le=40, description="结果上限(越小越快; 默认走 HG_SEARCH_MAX_ITEMS=20)")):
    _q = (q or "").strip()
    if not _q or len(_q) > 80:
        raise HTTPException(400, "Invalid search query")
    try:
        return {"query": _q, "results": H.search(_q, max_items=limit)}
    except Exception as e:
        raise HTTPException(500, {"code": "SEARCH_FAILED", "error_type": type(e).__name__,
                                  "safe_response": getattr(e, "safe_response", None),
                                  "response": e.diagnostic if isinstance(e, H.UpstreamResponseError) else None,
                                  "signing_failed": "所有签名服务失败" in str(e),
                                  "certificate_failed": "CERTIFICATE_VERIFY_FAILED" in str(e),
                                  "invalid_json": "Expecting value" in str(e)})


@app.get("/rank")
def api_rank(board: str = "recommend", limit: int = 30):
    if board not in H.RANK_BOARDS:
        raise HTTPException(400, f"board必须是 {list(H.RANK_BOARDS)}")
    try:
        return {"board": board, "name": H.RANK_NAMES.get(board), "items": H.rank(board, limit)}
    except Exception as e:
        raise HTTPException(500, f"rank失败: {e}")


@app.get("/latest")
def api_latest(genre: str = "short_play", only_today: bool = True, limit: int = 120, refresh: bool = False, no_cache: bool = False):
    """最新上架/今日上新。genre: short_play(短剧)|comic_series(漫剧)|ai_series(AI短剧)。
    短剧支持精确'今日上新'(官方标签); 漫剧/AI官方无今日粒度,返回'7天内上新·最新上架'。"""
    if genre not in H.GENRES:
        raise HTTPException(400, f"genre必须是 {list(H.GENRES)}")
    try:
        items = H.latest(genre, only_today=only_today, max_items=limit, refresh=refresh or no_cache)
        # 诚实标注模式
        if genre == "short_play":
            mode = "今日上新" if only_today else "最新上架"
        else:
            mode = "7天内上新·最新上架"
        return {"genre": genre, "name": H.GENRE_NAMES.get(genre), "mode": mode,
                "only_today": only_today, "count": len(items), "items": items}
    except Exception as e:
        raise HTTPException(500, f"latest失败: {e}")


@app.get("/filters")
def api_filters(genre: str = "short_play"):
    """取某体裁的全部筛选条件(实时面板)。genre: short_play|comic_series|ai_series。
    返回各维度(type=select_items键) + 选项(id/name)。漫剧多一维 creation_status(状态)。"""
    if genre not in H.GENRES:
        raise HTTPException(400, f"genre必须是 {list(H.GENRES)}")
    try:
        return {"genre": genre, "name": H.GENRE_NAMES.get(genre), "rows": H.filters(genre)}
    except Exception as e:
        raise HTTPException(500, f"filters失败: {e}")


@app.get("/browse")
def api_browse(genre: str = "ai_series", theme: str = None, setting: str = None,
               background: str = None, sort: str = "online_time", gender: str = None,
               days: str = None, status: str = None, limit: int = 60):
    """按筛选条件浏览。各维度传中文名或id; 多选用逗号分隔(如 theme=玄幻,科幻)。可选项见 /filters。
    theme主题 setting设定 background背景 sort排序 gender受众 days时间(7/14/30/90) status状态(仅漫剧:已完结/连载中)。"""
    if genre not in H.GENRES:
        raise HTTPException(400, f"genre必须是 {list(H.GENRES)}")
    def _csv(v):
        return [x.strip() for x in v.split(",") if x.strip()] if v else None
    try:
        items = H.browse(genre, theme=_csv(theme), setting=_csv(setting), background=_csv(background),
                         sort=sort, gender=gender, days=days, status=status, max_items=limit)
        for it in items:                                  # 补服务端可播/取集链接(剧级→播第1集)
            sid = it["series_id"]
            vid = it.get("vid")
            # 有 vid(7.2.5.32 列表项自带)→ 直接 /stream?vid= 省服务端一次 get_episodes
            it["stream_url"] = f"/stream?vid={vid}" if vid else f"/stream?series_id={sid}&ep=1"
            it["episodes_url"] = f"/episodes?series_id={sid}"     # 列全集(拿各集再 /stream?...&ep=N)
        return {"genre": genre, "name": H.GENRE_NAMES.get(genre), "count": len(items),
                "note": "stream_url=播第1集; 其它集用 episodes_url 取集号后 /stream?series_id=&ep=N", "items": items}
    except Exception as e:
        raise HTTPException(500, f"browse失败: {e}")


@app.get("/episodes")
def api_episodes(series_id: str):
    # 本地维护: 与其它路由一致的剧号校验，避免把任意串透给上游。
    if not re.fullmatch(r"[0-9]{8,24}", str(series_id or "")):
        raise HTTPException(400, "Invalid series id")
    try:
        meta, eps = H.get_episodes(series_id)
        return {"meta": meta, "episodes": eps}
    except Exception as e:
        raise HTTPException(500, f"episodes失败: {e}")


@app.post("/metrics/batch")
def api_metrics_batch(payload: dict = Body(...)):
    """批量补齐指标和封面。series_ids 每批最多20个拼接调用真实 multi_video_detail。"""
    raw_ids = payload.get("series_ids") or payload.get("series_id") or []
    if isinstance(raw_ids, str):
        series_ids = [x.strip() for x in raw_ids.split(",") if x.strip()]
    else:
        series_ids = [str(x).strip() for x in raw_ids if str(x).strip()]
    if not series_ids:
        raise HTTPException(400, "series_ids不能为空")
    if len(series_ids) > 200:
        raise HTTPException(400, "series_ids最多200个")
    batch_size = int(payload.get("batch_size") or 20)
    try:
        items, failed = H.get_episodes_batch(series_ids, batch_size=batch_size)
        rows = [items[sid] for sid in series_ids if sid in items]
        return {"count": len(rows), "items": rows, "failed": failed, "batch_size": max(1, min(batch_size, 20))}
    except Exception as e:
        raise HTTPException(500, f"metrics batch失败: {e}")


@app.get("/play")
def api_play(series_id: str, ep: str = "all"):
    """返回剧集的真实视频直链(客户端可直接下载/播放,无需签名)"""
    stage = "episodes"
    try:
        meta, eps = H.get_episodes(series_id)
        want = set(parse_range(ep, len(eps)))
        sel = [e for e in eps if (e["index"] or 0) in want]
        stage = "video_model"
        urls = H.get_video_urls([e["vid"] for e in sel])
        out = []
        for e in sel:
            info = urls.get(e["vid"], {})
            out.append({"index": e["index"], "vid": e["vid"], "title": e["title"],
                        "duration": e["duration"],
                        # url 是 CDN 密文直链(CENC加密, 直接播放是花屏); 要可播用 stream_url(服务端已解密)
                        "encrypted_url": info.get("url"), "backup": info.get("backup"),
                        "size": info.get("size"), "definition": info.get("definition"),
                        "shape": info.get("shape"), "url_is_http": info.get("url_is_http"),
                        "stream_url": f"/stream?vid={e['vid']}"})
        return {"series_id": series_id, "title": meta["title"],
                "note": "encrypted_url 为CENC密文直链; 可播放用 stream_url(服务端纯离线解密)", "episodes": out}
    except Exception as e:
        import traceback
        frames = [{"file": os.path.basename(f.filename), "line": f.lineno, "function": f.name}
                  for f in traceback.extract_tb(e.__traceback__)]
        raise HTTPException(500, {"code": "PLAY_FAILED", "stage": stage, "frames": frames,
                                  "model_shape": getattr(e, "model_shape", None),
                                  "error_type": type(e).__name__,
                                  "response": e.diagnostic if isinstance(e, H.UpstreamResponseError) else None})


@app.get("/download")
def api_download(series_id: str, ep: str = "all", ep_covers: bool = False):
    """提交下载任务到服务器本地(并发+断点续传)。返回 task_id, 用 /download/status 查进度。"""
    try:
        tid = H.manager().submit(series_id, ep, ep_covers)
        return {"task_id": tid, "status_url": f"/download/status?task_id={tid}"}
    except Exception as e:
        raise HTTPException(500, f"download失败: {e}")


@app.get("/download/status")
def api_download_status(task_id: str = None):
    return H.manager().status(task_id)


@app.get("/video_url")
def api_video_url(vid: str):
    """按单个 vid 取真实视频直链(供外部源模块调用)。"""
    try:
        urls = H.get_video_urls([vid])
        info = urls.get(str(vid)) or {}
        if not info.get("url"):
            raise HTTPException(404, "无直链")
        return {"vid": vid, "url": info.get("url"), "backup": info.get("backup"),
                "size": info.get("size"), "definition": info.get("definition")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"video_url失败: {e}")


@app.get("/stream")
def api_stream(series_id: str = None, ep: str = "1", vid: str = None, quality: str = "best"):
    """服务器代理串流单集 —— 已做【纯离线解密】, 客户端拿到的是可播 mp4(非密文)。
    用法: /stream?series_id=xxx&ep=1  或  /stream?vid=xxx  [&quality=1080p&api_key=...]
    首次会下载+解密并缓存(downloads/.stream_cache), 之后秒回; FileResponse 支持 Range 拖动。
    注: <video> 标签无法带请求头, 用 ?api_key= 传密钥。"""
    try:
        fname = None
        if not vid:
            if not series_id:
                raise HTTPException(400, "需 series_id+ep 或 vid")
            meta, eps = H.get_episodes(series_id)
            idx = int(ep) if str(ep).isdigit() else 1
            target = next((e for e in eps if (e["index"] or 0) == idx), None)
            if not target:
                raise HTTPException(404, "集号不存在")
            vid = target["vid"]
            fname = f"{H.sanitize(meta['title'])}_第{idx:03d}集.mp4"
        path = _ensure_decrypted(vid, quality)   # 下载密文+离线解密+缓存
        if os.environ.get("HONGGUO_SESSION_API_KEY"):
            from desktop_encode import encode_h264
            with _dec_lock(f"desktop-h264-v1:{vid}:{quality}"):
                path = encode_h264(path)
        fname = fname or f"{vid}.mp4"
        from urllib.parse import quote as _q
        cd = f"inline; filename=\"{vid}.mp4\"; filename*=UTF-8''{_q(fname)}"
        # FileResponse 自动处理 HTTP Range(206), 支持播放器 seek
        return FileResponse(path, media_type="video/mp4", headers={"Content-Disposition": cd})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"stream失败: {e}")


if os.environ.get("HONGGUO_SESSION_API_KEY") and os.environ.get("HONGGUO_HLS_WORK_DIR"):
    from desktop_hls_service import HlsJobs, make_router, DESKTOP_ORIGINS
    from fastapi.middleware.cors import CORSMiddleware

    def _desktop_source(series_id, episode, quality="desktop-resolution-v1", cancelled=None):
        _, episodes = H.get_episodes(series_id)
        target = next((item for item in episodes if item.get("index") == episode), None)
        if not target or not re.fullmatch(r"[0-9]{8,24}", str(target.get("vid", ""))):
            raise ValueError("Episode media identity unavailable")
        # 清晰度由 HLS 路由校验后传到这里。
        decrypted = _ensure_decrypted(str(target["vid"]), quality or "desktop-resolution-v1")
        # 本地维护: 控制缓存上限（默认 4GB）。
        # 首集提速的关键：**不要**在这里把整集预转码。
        # 实测（2026-10-08，110~188s 的 1080p 集）：
        #   encode_h264(整集 HEVC->H.264) 要 12.9~24s，而 HLS 编码器本身是
        #   增量切片 —— 写完第一个 2s 分片就置 ready，用户马上能播。
        #   先整集转码等于把「能边转边播」退化成「转完才给看」。
        # 对比（同一集，同一台机器）：
        #   先整集转码再切片 = 12.91s 才出首片
        #   直接边转边播     =  0.57s 出首片（22.5x）
        # 已转码过的 H.264 缓存仍走 desktop_hls 里的 stream-copy 快路径
        # （encode_hls 内部会探测源编码），所以复看依旧快。
        _hq_cache_cap(int(os.environ.get("HONGGUO_CACHE_MAX_BYTES") or 0),
                      int(os.environ.get("HONGGUO_CACHE_KEEP_FILES") or 8))
        return decrypted

    try:
        _hq_cur = os.path.abspath(os.environ["HONGGUO_HLS_WORK_DIR"])
        _hq_parent = os.path.dirname(_hq_cur)
        import shutil as _hq_sh
        for _n in os.listdir(_hq_parent):
            if not _n.startswith("desktop-hls-"):
                continue
            _old = os.path.join(_hq_parent, _n)
            if os.path.abspath(_old) == _hq_cur:
                continue
            if not os.path.isdir(_old) or os.path.islink(_old):
                continue
            if os.path.dirname(os.path.abspath(_old)) != _hq_parent:
                continue
            try:
                _hq_sh.rmtree(_old)
            except OSError:
                pass
    except Exception:
        pass
    _desktop_jobs = HlsJobs(os.environ["HONGGUO_HLS_WORK_DIR"], _desktop_source)
    app.include_router(make_router(_desktop_jobs, _keys.is_valid))
    # Must wrap authentication so browser preflight can complete, but every
    # actual HLS request still requires the process-only key and reviewed origin.
    app.add_middleware(CORSMiddleware, allow_origins=DESKTOP_ORIGINS,
                       allow_methods=["GET", "HEAD", "POST", "DELETE"],
                       allow_headers=["x-api-key", "range"],
                       expose_headers=["content-range", "accept-ranges"])


if __name__ == "__main__":
    import uvicorn
    # 默认只绑本机(脱机直连由同机 xinge 走 127.0.0.1 调); 需对外可设 BIND_HOST=0.0.0.0
    uvicorn.run(app, host=os.environ.get("BIND_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))



# ---- 本地维护: 看过的集自动清理缓存 ----
# 注意：启动清扫 HLS 残留目录的逻辑内联在调用点（见 patch_server 的「启动清扫」步骤），
# 不在这里定义函数 —— 这里在文件末尾，定义在后、调用在前会 NameError。
# 曾经留过一个同名的 _hq_sweep_stale_sessions 定义但从未被调用（死代码），已删除。


def _hq_cleanup_episode(series_id, episode):
    """删掉这一集的本地缓存（解密源 + H.264 转码产物）。

    定位方式：先用章节接口把 episode 换成 vid，再按 vid 删。
    只删命名模式匹配的文件，绝不扫目录、绝不删目录本身。
    """
    import glob as _g
    try:
        _, episodes = H.get_episodes(series_id)
        target = next((it for it in episodes if it.get("index") == episode), None)
        if not target:
            return 0
        vid = str(target.get("vid", ""))
        if not re.fullmatch(r"[0-9]{8,24}", vid):
            return 0
        removed = 0
        for pattern in (f"{vid}_*.mp4", f"{vid}_*.desktop-h264-v1.mp4"):
            for path in _g.glob(os.path.join(STREAM_CACHE, pattern)):
                try:
                    if os.path.isfile(path):
                        os.remove(path)
                        removed += 1
                except OSError:
                    pass
        return removed
    except Exception:
        return 0


def _hq_cache_cap(max_bytes=0, keep_files=8):
    """控制本地缓存规模。

    1) 按最后修改时间保留最近 keep_files 个文件，其余删除。
       播放器一次只看一集，预取最多提前 2 集，
       所以被淘汰的文件必然是看过的集数。
    2) 若总量仍超过 max_bytes，继续从最旧的删。

    只删匹配 *.mp4 的普通文件，不扫目录、不删目录。
    """
    import glob as _g
    try:
        files = []
        total = 0
        for path in _g.glob(os.path.join(STREAM_CACHE, "*.mp4")):
            try:
                if os.path.isfile(path):
                    size = os.path.getsize(path)
                    files.append((os.path.getmtime(path), size, path))
                    total += size
            except OSError:
                pass
        if not files:
            return 0
        files.sort(key=lambda it: it[0], reverse=True)
        removed = 0
        for _, size, path in files[keep_files:]:
            try:
                os.remove(path)
                total -= size
                removed += 1
            except OSError:
                pass
        if max_bytes and total > max_bytes:
            target = int(max_bytes * 0.75)
            for _, size, path in files[:keep_files]:
                if total <= target:
                    break
                try:
                    if os.path.exists(path):
                        os.remove(path)
                        total -= size
                        removed += 1
                except OSError:
                    pass
        return removed
    except Exception:
        return 0



@app.get("/desktop/cleanup")
def desktop_cleanup(series_id: str, ep: int):
    """播放器告知某集已经看完，删掉它的本地缓存。"""
    if not re.fullmatch(r"[0-9]{8,24}", str(series_id)) or not 1 <= ep <= 100000:
        raise HTTPException(400, "Invalid episode identity")
    return {"removed": _hq_cleanup_episode(series_id, ep)}


def _hq_sweep_partial(max_age=900):
    """清掉转码/下载中途留下的孤儿文件。

    2026-10-07 实测：stream-cache 里积了 2 个 *.partial 共 71.5 MB。
    它们由 desktop_encode / desktop_remux 在异常退出时留下，
    而 _hq_cleanup_episode 只匹配 `*.mp4`、_hq_cache_cap 也只 glob `*.mp4`，
    所以这两个函数都碰不到它们 —— 属于永久泄漏。
    这里按 mtime 清理「超过 max_age 秒没被碰过」的 .partial / .part / .raw.mp4：
    正在写的文件 mtime 是新的，不会被误删。
    """
    import glob as _g
    removed = 0
    now = time.time()
    for pattern in ("*.partial", "*.part", "*.raw.mp4"):
        for path in _g.glob(os.path.join(STREAM_CACHE, pattern)):
            try:
                if not os.path.isfile(path):
                    continue
                if now - os.path.getmtime(path) < max_age:
                    continue
                os.remove(path)
                removed += 1
            except OSError:
                pass
    return removed


def _hq_prune_poster_cache(keep_files=400, max_age_days=14):
    """封面缓存（poster-cache-v1）没有上游清理逻辑，只写不清。

    2026-10-07 实测：624 个文件 / 113 MB，单日新增 333 个。
    目录由 Rust 侧写入（文件名形如 <seriesId>.cover），后端不参与写入，
    所以这里只做「按 mtime 淘汰」：先按年龄删，再按数量上限删。
    只删普通文件、只认 .cover 后缀，不碰目录。
    """
    import glob as _g
    root = os.environ.get("HONGGUO_POSTER_CACHE") or os.path.join(
        os.environ.get("HONGGUO_BACKEND_DATA_DIR") or "", "poster-cache-v1")
    if not root or not os.path.isdir(root):
        return 0
    removed = 0
    now = time.time()
    entries = []
    for path in _g.glob(os.path.join(root, "*.cover")):
        try:
            if not os.path.isfile(path):
                continue
            mtime = os.path.getmtime(path)
            entries.append((mtime, os.path.getsize(path), path))
        except OSError:
            pass
    if not entries:
        return 0
    entries.sort(reverse=True)
    cutoff = now - max_age_days * 86400
    for mtime, _size, path in entries:
        if mtime >= cutoff and len(entries) - removed <= keep_files:
            break
        try:
            os.remove(path)
            removed += 1
        except OSError:
            pass
    return removed



# ---- 本地维护: 启动时清掉「其它清理函数碰不到的」残留 ----
# 放在文件末尾，因为上面两个函数定义在 CLEANUP_BLOCK（也在这里）。
def _hq_startup_cache_sweep():
    try:
        n_partial = _hq_sweep_partial()
    except Exception:
        n_partial = 0
    try:
        n_poster = _hq_prune_poster_cache()
    except Exception:
        n_poster = 0
    if n_partial or n_poster:
        print("[server] 启动清扫: partial=%d poster=%d" % (n_partial, n_poster))
    return n_partial + n_poster


_hq_startup_cache_sweep()


@app.post("/desktop/cache/prune")
def desktop_cache_prune():
    """播放器关闭/切集时调一次，兜住「没看完就退出」的缓存。

    原先只有 onEnded 会触发清理：中途关播放器、快速切集、直接关软件
    这三条路径都不会清，缓存就一路涨。这里提供一个显式的兜底入口，
    按数量上限回收（保留最近的 keep_files 个），并清掉过期的 .partial。
    """
    keep = int(os.environ.get("HONGGUO_CACHE_KEEP_FILES") or 8)
    removed = _hq_cache_cap(int(os.environ.get("HONGGUO_CACHE_MAX_BYTES") or 0), keep)
    removed += _hq_sweep_partial()
    return {"removed": removed, "keepFiles": keep}


# ---- 本地维护: 红果账号同步（验证码登录 / 观看进度 / 收藏）----
try:
    import desktop_account_api as _hq_account_api
    _hq_account_api.register(app)
    # 本地维护: 更新检测指向本分支自己的仓库（Tauri 自带的 updater 需要
    # 原作者私钥签名，我们用不了，所以走自己的检测 + 打开下载页）。
    _hq_account_api.register_update(app)
    _hq_account_api.register_update_download(app)
except Exception as _hq_account_error:  # 账号同步不可用时不影响播放
    print("[server] 账号同步未启用:", type(_hq_account_error).__name__)
