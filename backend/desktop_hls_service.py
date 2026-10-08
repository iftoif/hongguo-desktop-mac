"""Authenticated desktop HLS sessions. No upstream credentials or protocol code.

The Rust parent owns the unique work directory and removes it AFTER killing its
backend job. Sessions additionally release their own output on player close/expiry.
"""
from dataclasses import dataclass, field
from pathlib import Path
import re
import math
import shutil
import threading
import time
import uuid

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import FileResponse, Response
from desktop_hls import encode_hls, EncodingCancelled
from desktop_hls_budget import EncodingBudgetExceeded


class InvalidStartPosition(ValueError):
    """A valid numeric request lies outside this source's known timeline."""


@dataclass
class Job:
    id: str
    directory: Path
    cancelled: threading.Event = field(default_factory=threading.Event)
    ready: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    failed: bool = False
    failure_code: str | None = None
    duration: float | None = None
    touched: float = field(default_factory=time.monotonic)
    start_seconds: float = 0.0
    window_origin: float | None = 0.0


class HlsJobs:
    def __init__(self, root, source_loader, *, encoder=encode_hls, max_jobs=8, max_workers=3, idle_seconds=300, queue_wait=6.0):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir() or self.root.is_symlink():
            raise ValueError("Desktop work directory is unavailable")
        self.source_loader, self.encoder = source_loader, encoder
        self.max_jobs, self.max_workers, self.idle_seconds = max_jobs, max_workers, idle_seconds
        self.queue_wait = float(queue_wait)
        self.jobs = {}
        self.guard = threading.RLock()

    def _remove_output(self, job):
        # Only our generated UUID child; never a source file or a caller's path.
        target = job.directory
        if target.parent != self.root or target.name != job.id or not re.fullmatch(r"[0-9a-f]{32}", job.id):
            raise ValueError("Unsafe session output")
        if target.is_symlink() or (target.exists() and target.resolve().parent != self.root):
            raise ValueError("Session output escaped work directory")
        if target.exists():
            shutil.rmtree(target)

    def _expire(self):
        for job in list(self.jobs.values()):
            if time.monotonic() - job.touched > self.idle_seconds:
                self.release(job.id)

    def create(self, series_id, episode, *, start_seconds=0, quality="auto"):
        if not re.fullmatch(r"[0-9]{8,24}", series_id) or not 1 <= episode <= 100000:
            raise HTTPException(400, "Invalid episode identity")
        if (not isinstance(start_seconds, (int, float)) or isinstance(start_seconds, bool)
                or not math.isfinite(start_seconds) or not 0 <= start_seconds <= 86400):
            raise HTTPException(400, "Invalid desktop start position")
        # 本地维护: 编码池改为「有界排队」。
        # 上游原来在槽位占满时立刻 503；而切集瞬间旧任务还在收尾，
        # 于是下一集必然报「媒体准备失败」。这里改为短暂等待槽位，
        # 并把「已取消、尚未收尾」的任务排除在占用之外。
        deadline = time.monotonic() + self.queue_wait
        while True:
            with self.guard:
                self._expire()
                live = sum(not job.cancelled.is_set() for job in self.jobs.values())
                active = sum(not job.done.is_set() and not job.cancelled.is_set()
                             for job in self.jobs.values())
                if live < self.max_jobs and active < self.max_workers:
                    identifier = uuid.uuid4().hex
                    job = Job(identifier, self.root / identifier,
                              start_seconds=float(start_seconds),
                              window_origin=None if start_seconds else 0.0)
                    self.jobs[identifier] = job
                    threading.Thread(target=self._run, args=(job, series_id, episode, quality),
                                     daemon=True).start()
                    return job
            if time.monotonic() >= deadline:
                raise HTTPException(503, "Desktop encoder is busy; retry shortly")
            time.sleep(0.15)

    def _run(self, job, series_id, episode, quality="auto"):
        try:
            # 本地维护: 把取消信号透传给取源/转码, 切集时旧任务能立刻停下,
            # 不再长时间占着工作槽位。上游 source_loader 只收 3 个参数。
            try:
                source = self.source_loader(series_id, episode, quality,
                                            cancelled=job.cancelled.is_set)
            except TypeError:
                source = self.source_loader(series_id, episode, quality)
            if job.cancelled.is_set():
                raise EncodingCancelled()
            import av
            with av.open(str(source)) as media:
                if media.duration and media.duration > 0:
                    job.duration = media.duration / av.time_base
            if job.start_seconds and (job.duration is None or job.start_seconds >= job.duration):
                raise InvalidStartPosition()
            if job.start_seconds:
                def window(origin, duration):
                    with self.guard:
                        if job.cancelled.is_set():
                            raise EncodingCancelled()
                        if (job.window_origin is not None
                                or not isinstance(origin, (int, float)) or isinstance(origin, bool)
                                or not isinstance(duration, (int, float)) or isinstance(duration, bool)
                                or not math.isfinite(origin) or not math.isfinite(duration)
                                or not job.start_seconds <= origin < duration <= 86400
                                or job.duration is None or abs(duration - job.duration) > 0.001):
                            raise ValueError("Invalid desktop window metadata")
                        job.window_origin = float(origin)

                def ready():
                    with self.guard:
                        if job.cancelled.is_set():
                            raise EncodingCancelled()
                        if job.window_origin is None:
                            raise ValueError("Desktop window origin is unavailable")
                        job.ready.set()
                self.encoder(source, job.directory, ready, cancelled=job.cancelled.is_set,
                             start_seconds=job.start_seconds, on_window=window)
            else:
                # Preserve the original zero-start encoder contract, including
                # callers that inject an older encoder for ordinary playback.
                self.encoder(source, job.directory, job.ready.set, cancelled=job.cancelled.is_set)
            if job.start_seconds and job.window_origin is None:
                raise ValueError("Desktop window completion is unavailable")
            if not (job.directory / "complete.marker").is_file():
                raise ValueError("Encoder completion was not verified")
        except InvalidStartPosition:
            job.failed = True
            job.failure_code = "start-position"
        except EncodingCancelled:
            job.failed = True
            job.failure_code = "cancelled"
        except EncodingBudgetExceeded:
            job.failed = True
            job.failure_code = "output-budget"
        except Exception:
            # Fixed categories only; never expose provider exception text.
            job.failed = True
            job.failure_code = "processing"
        finally:
            with self.guard:
                job.done.set()
                job.ready.set()
                if job.cancelled.is_set():
                    try:
                        self._remove_output(job)
                    except OSError:
                        # Keep it registered for a later cleanup attempt/quota.
                        return
                    self.jobs.pop(job.id, None)

    def get(self, identifier):
        with self.guard:
            job = self.jobs.get(identifier)
            if not job or job.cancelled.is_set():
                raise HTTPException(404, "Desktop session is unavailable")
            job.touched = time.monotonic()
            return job

    def release(self, identifier):
        with self.guard:
            job = self.jobs.get(identifier)
            if not job:
                return
            job.cancelled.set()
            job.ready.set()
            if job.done.is_set():
                try:
                    self._remove_output(job)
                except OSError:
                    return
                self.jobs.pop(identifier, None)

    def playlist(self, identifier, wait_seconds=90):
        job = self.get(identifier)
        if not job.ready.wait(wait_seconds):
            raise HTTPException(504, "Desktop media preparation timed out")
        if job.failed or job.cancelled.is_set():
            raise HTTPException(503, "Desktop media preparation failed")
        try:
            text = (job.directory / "index.m3u8").read_text(encoding="utf-8")
        except OSError:
            raise HTTPException(503, "Desktop playlist is not ready")
        # Encoder close can emit ENDLIST even during unwinding. Never expose it
        # until the worker has successfully committed its completion marker.
        complete = job.done.is_set() and not job.failed and (job.directory / "complete.marker").is_file()
        if not complete:
            text = text.replace("#EXT-X-ENDLIST", "")
        # Prefix fragments because the route itself has a file path component.
        # Only fixed local basenames are emitted; tokens are attached in headers.
        for line in text.splitlines():
            if line and not line.startswith("#") and not re.fullmatch(r"seg[0-9]{6}\.m4s", line):
                raise HTTPException(500, "Invalid desktop playlist")
            if line.startswith("#EXT-X-MAP:") and line != '#EXT-X-MAP:URI="init.mp4"':
                raise HTTPException(500, "Invalid desktop init fragment")
        return text


DESKTOP_ORIGINS = ["http://tauri.localhost", "tauri://localhost", "http://localhost:1420", "http://127.0.0.1:1420"]


def make_router(jobs, valid_key):
    def authorize(request: Request):
        if not valid_key(request.headers.get("x-api-key", "")):
            raise HTTPException(401, "Desktop session credential required")
        origin = request.headers.get("origin")
        if origin is not None and origin not in DESKTOP_ORIGINS:
            raise HTTPException(403, "Desktop origin required")
    router = APIRouter(prefix="/desktop/hls", dependencies=[Depends(authorize)])
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

    @router.get("/capabilities")
    def capabilities():
        return {"service": "guoban-desktop-hls", "version": 1,
                "seekWindow": True, "windowVersion": 1, "maxStartSeconds": 86400}

    @router.post("")
    def prepare(request: Request, series_id: str, ep: int, start_seconds: float = 0, quality: str = "auto"):
        names = [name for name, _ in request.query_params.multi_items()]
        if (any(name not in {"series_id", "ep", "start_seconds", "quality"} for name in names)
                or len(set(names)) != len(names)):
            raise HTTPException(400, "Invalid desktop request parameters")
        return {"id": jobs.create(series_id, ep, start_seconds=start_seconds, quality=normalize_desktop_quality(quality)).id}

    @router.get("/{identifier}/status")
    def status(identifier: str):
        with jobs.guard:
            job = jobs.get(identifier)
            return {"state": "failed" if job.failed else "complete" if job.done.is_set() else "preparing",
                    "duration": job.duration, "failureCode": job.failure_code,
                    "playlistReady": job.ready.is_set() and not job.failed and not job.cancelled.is_set(),
                    "startSeconds": job.start_seconds, "windowOrigin": job.window_origin}

    @router.delete("/{identifier}")
    def release(identifier: str):
        jobs.release(identifier)
        return Response(status_code=204)

    @router.get("/{identifier}/index.m3u8")
    def playlist(identifier: str):
        return Response(jobs.playlist(identifier), media_type="application/vnd.apple.mpegurl", headers=headers)

    @router.api_route("/{identifier}/{filename}", methods=["GET", "HEAD"])
    def fragment(identifier: str, filename: str):
        if filename != "init.mp4" and not re.fullmatch(r"seg[0-9]{6}\.m4s", filename):
            raise HTTPException(404, "Unknown desktop fragment")
        job = jobs.get(identifier)
        if job.failed:
            raise HTTPException(503, "Desktop encoding failed")
        path = job.directory / filename
        if not path.is_file() or path.is_symlink():
            raise HTTPException(404, "Desktop fragment is not ready")
        return FileResponse(path, media_type="video/mp4", headers=headers)

    return router


# ---- 本地维护: 播放器可选清晰度 ----
DESKTOP_QUALITY_CHOICES = ("auto", "1080p", "720p", "540p", "480p", "360p")


def normalize_desktop_quality(value):
    """把播放器传来的档位规范成选轨用的名称。

    auto 走上游原有的 desktop-resolution-v1 策略; 其余档位原样交给
    offline_dl._pick_track（不存在时回退到不超过请求的最高一档）。
    """
    text = (value or "auto").strip().lower()
    if text not in DESKTOP_QUALITY_CHOICES:
        raise HTTPException(400, "Unsupported desktop quality")
    return "desktop-resolution-v1" if text == "auto" else text
