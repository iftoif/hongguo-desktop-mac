"""Incremental desktop H.264/AAC encoding into an isolated, caller-owned directory.

Only complete segments and atomically published playlists are exposed. No URLs,
session keys, or upstream protocol handling belong in this module.
"""
from pathlib import Path
from fractions import Fraction
import math
from desktop_hls_budget import EncodingBudgetExceeded, video_budget_options


class EncodingCancelled(Exception):
    """A caller stopped this encode; its fragments are not a complete episode."""


def encode_hls(source, directory, on_ready=lambda: None, *, cancelled=lambda: False,
               max_output_bytes=512 * 1024 * 1024, start_seconds=0,
               on_window=lambda origin_seconds, full_duration_seconds: None):
    if (not isinstance(start_seconds, (int, float)) or isinstance(start_seconds, bool)
            or not math.isfinite(start_seconds) or start_seconds < 0):
        raise ValueError("Invalid desktop start position")
    import av

    source, directory = Path(source), Path(directory)
    # Never overwrite an existing session or mix segments from different encodes.
    # 本地维护: 已是 H.264 的整集缓存无需重编码（仅 start_seconds==0）。
    if not start_seconds:
        try:
            import av as _hq_av
            with _hq_av.open(str(source)) as _hq_probe:
                _hq_codec = (_hq_probe.streams.video[0].codec_context.name
                             if _hq_probe.streams.video else "")
        except Exception:
            _hq_codec = ""
        if _hq_codec == "h264":
            return _hq_copy_hls(source, directory, on_ready, cancelled, max_output_bytes)
    directory.mkdir(parents=False, exist_ok=False)
    ready = False
    packets_seen = 0
    with av.open(str(source)) as reader:
        if len(reader.streams.video) != 1:
            raise ValueError("Expected one video track")
        original = reader.streams.video[0]
        full_duration = reader.duration / av.time_base if reader.duration else None
        if start_seconds and (full_duration is None or start_seconds >= full_duration):
            raise ValueError("Desktop start position outside known duration")
        source_origin = Fraction((original.start_time or 0) * original.time_base.numerator,
                                 original.time_base.denominator)
        requested = source_origin + Fraction(str(start_seconds))
        window_origin = None if start_seconds else Fraction(0)
        pending_audio = []
        if start_seconds:
            ticks = requested / Fraction(original.time_base.numerator, original.time_base.denominator)
            reader.seek(ticks.numerator // ticks.denominator, backward=True,
                        any_frame=False, stream=original)
        else:
            on_window(0.0, full_duration)
        rate = original.average_rate or 30
        if not 0 < rate <= 120:
            raise ValueError("Unsupported frame rate")
        options = {
            "hls_time": "2", "hls_list_size": "0", "hls_playlist_type": "event",
            "hls_segment_type": "fmp4", "hls_fmp4_init_filename": "init.mp4",
            "hls_segment_filename": (directory / "seg%06d.m4s").as_posix(),
            "hls_flags": "temp_file+independent_segments",
        }
        if start_seconds:
            # fMP4 edit lists otherwise round a positive audio track offset
            # down to the default millisecond movie clock. Represent the
            # copied stream clocks exactly without changing source timing.
            movie_clock = math.lcm(1000, original.time_base.denominator,
                                   *(stream.time_base.denominator for stream in reader.streams.audio))
            if movie_clock > 2147483647:
                raise ValueError("Unsupported desktop movie clock")
            options["hls_segment_options"] = f"movie_timescale={movie_clock}"
        with av.open((directory / "index.m3u8").as_posix(), "w", format="hls", options=options) as writer:
            video = writer.add_stream("libx264", rate=rate)
            video.width = original.codec_context.width
            video.height = original.codec_context.height
            video.pix_fmt = "yuv420p"
            # Average rate can differ from actual presentation intervals.
            # Preserve the source clock instead of rounding frames to 1/rate.
            video.codec_context.time_base = original.time_base
            video.time_base = original.time_base
            video.codec_context.options = {
                "preset": "superfast", "crf": "20", "tune": "zerolatency",
                "g": str(max(1, round(float(rate) * 2))), "sc_threshold": "0",
            }
            video.codec_context.options.update(video_budget_options(
                max(0, full_duration - start_seconds) if full_duration else None,
                [stream.codec_context.bit_rate for stream in reader.streams.audio],
                max_output_bytes))
            buffered_video = None
            def push_video(encoded):
                nonlocal buffered_video
                if buffered_video is not None:
                    if (encoded.time_base != buffered_video.time_base or
                            encoded.dts is None or buffered_video.dts is None or
                            encoded.dts <= buffered_video.dts):
                        raise ValueError("Invalid desktop video timestamps")
                    # A fragment ending before a VFR gap needs the real
                    # sample duration, not a guess from average frame rate.
                    buffered_video.duration = encoded.dts - buffered_video.dts
                    writer.mux(buffered_video)
                buffered_video = encoded
            audio = {}
            for stream in reader.streams.audio:
                if stream.codec_context.name != "aac":
                    raise ValueError("Desktop profile currently requires AAC audio")
                audio[stream.index] = writer.add_stream_from_template(stream)
                audio[stream.index].codec_context.codec_tag = "mp4a"
            def push_audio(packet):
                if start_seconds:
                    if packet.pts is None:
                        raise ValueError("Missing desktop audio timestamp")
                    now = Fraction(packet.pts * packet.time_base.numerator, packet.time_base.denominator)
                    if now < window_origin:
                        return
                    # AAC stays copied. One common video origin is rounded to
                    # the audio clock, with a maximum half-tick phase error.
                    shift = round(window_origin / Fraction(packet.time_base.numerator,
                                                           packet.time_base.denominator))
                    packet.pts -= shift
                    packet.dts -= shift
                packet.stream = audio[packet.stream.index]
                writer.mux(packet)

            for packet in reader.demux():
                if cancelled():
                    raise EncodingCancelled("Desktop encode cancelled")
                packets_seen += 1
                if packets_seen % 32 == 0:
                    # A bounded overshoot of at most 32 demux packets is possible.
                    # Include unfinished .tmp data; never silently drop frames.
                    if sum(p.stat().st_size for p in directory.iterdir() if p.is_file()) > max_output_bytes - len(b"desktop-hls-v1\n"):
                        raise EncodingBudgetExceeded("Desktop segment budget exceeded")
                if packet.stream.index == original.index:
                    for frame in packet.decode():
                        if cancelled():
                            raise EncodingCancelled("Desktop encode cancelled")
                        if start_seconds:
                            if frame.pts is None:
                                raise ValueError("Missing desktop video timestamp")
                            now = Fraction(frame.pts * frame.time_base.numerator, frame.time_base.denominator)
                            if now < requested:
                                continue
                            if window_origin is None:
                                window_origin = now
                                on_window(float(now - source_origin), full_duration)
                                for queued in pending_audio:
                                    push_audio(queued)
                                pending_audio.clear()
                            frame.pts -= round(window_origin / Fraction(frame.time_base.numerator,
                                                                        frame.time_base.denominator))
                        for encoded in video.encode(frame):
                            push_video(encoded)
                elif packet.stream.index in audio and packet.dts is not None:
                    if window_origin is None:
                        if len(pending_audio) >= 4096:
                            raise ValueError("Desktop audio preroll exceeded")
                        pending_audio.append(packet)
                    else:
                        push_audio(packet)
                if not ready and (directory / "index.m3u8").is_file():
                    ready = True
                    on_ready()
            if start_seconds and window_origin is None:
                raise ValueError("No desktop video after start position")
            for packet in video.encode():
                push_video(packet)
            if buffered_video is not None:
                if not buffered_video.duration:
                    buffered_video.duration = max(1, round(float(1 / rate / buffered_video.time_base)))
                writer.mux(buffered_video)
    playlist = (directory / "index.m3u8").read_text(encoding="utf-8")
    if "#EXT-X-ENDLIST" not in playlist or not (directory / "seg000000.m4s").is_file():
        raise ValueError("No complete desktop segments")
    if sum(p.stat().st_size for p in directory.iterdir() if p.is_file()) > max_output_bytes - len(b"desktop-hls-v1\n"):
        raise EncodingBudgetExceeded("Desktop segment budget exceeded")
    # Closing the FFmpeg writer also emits ENDLIST on error/cancellation. Thus
    # ENDLIST alone is NEVER success evidence. The HTTP job owner must reject
    # failed jobs even if the partial playlist happens to contain ENDLIST.
    if not ready:
        on_ready()
    if cancelled():
        raise EncodingCancelled("Desktop encode cancelled")
    (directory / "complete.marker").write_text("desktop-hls-v1\n", encoding="ascii")
    return directory / "index.m3u8"


# ---- 本地维护: 已转码 H.264 源的 stream-copy 快路径 ----
def _hq_hls_options(directory):
    return {
        "hls_time": "2", "hls_list_size": "0", "hls_playlist_type": "event",
        "hls_segment_type": "fmp4", "hls_fmp4_init_filename": "init.mp4",
        "hls_segment_filename": (directory / "seg%06d.m4s").as_posix(),
        "hls_flags": "temp_file+independent_segments",
    }


def _hq_copy_hls(source, directory, on_ready, cancelled, max_output_bytes):
    """把已是 H.264/AAC 的源直接复制成 fmp4 HLS 分片（不重新编码）。

    只用于本机缓存产物: 整集、从 0 开始、编码已符合播放器要求。
    """
    import av
    source, directory = Path(source), Path(directory)
    # 快路径由 encode_hls 提前返回进入, 原路径的 mkdir 不会执行, 这里自行创建。
    directory.mkdir(parents=False, exist_ok=False)
    ready = False
    with av.open(str(source)) as reader:
        if len(reader.streams.video) != 1:
            raise ValueError("Expected one video track")
        with av.open((directory / "index.m3u8").as_posix(), "w", format="hls",
                     options=_hq_hls_options(directory)) as writer:
            streams = {}
            for stream in reader.streams:
                if stream.type not in ("video", "audio"):
                    continue
                target = writer.add_stream_from_template(stream)
                if stream.codec_context.name == "aac":
                    target.codec_context.codec_tag = "mp4a"
                streams[stream.index] = target
            if not streams:
                raise ValueError("No audio/video streams to copy")
            seen = 0
            for packet in reader.demux():
                if cancelled():
                    raise EncodingCancelled("Desktop encode cancelled")
                seen += 1
                if seen % 64 == 0 and sum(
                        p.stat().st_size for p in directory.iterdir() if p.is_file()) > max_output_bytes:
                    raise ValueError("Desktop segment budget exceeded")
                if packet.dts is None or packet.stream.index not in streams:
                    continue
                packet.stream = streams[packet.stream.index]
                writer.mux(packet)
                if not ready and (directory / "index.m3u8").is_file():
                    ready = True
                    on_ready()
    playlist = (directory / "index.m3u8").read_text(encoding="utf-8")
    if "#EXT-X-ENDLIST" not in playlist or not (directory / "seg000000.m4s").is_file():
        raise ValueError("No complete desktop segments")
    if not ready:
        on_ready()
    if cancelled():
        raise EncodingCancelled("Desktop encode cancelled")
    (directory / "complete.marker").write_text("desktop-hls-v1\n", encoding="ascii")
    return directory / "index.m3u8"
