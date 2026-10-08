"""Desktop-compatible H.264/AAC MP4 cache. Does not require a system codec pack."""
import os
from pathlib import Path
import uuid


def encode_h264(source, cancelled=None):
    import av
    source = Path(source)
    destination = source.with_name(source.stem + ".desktop-h264-v1.mp4")
    if destination.is_file() and destination.stat().st_size:
        return str(destination)
    partial = destination.with_name(destination.name + "." + uuid.uuid4().hex + ".partial")
    try:
        with av.open(str(source)) as reader:
            if len(reader.streams.video) != 1:
                raise ValueError("Expected one video track")
            original = reader.streams.video[0]
            with av.open(str(partial), "w", format="mp4", options={"movflags": "+faststart"}) as writer:
                video = writer.add_stream("libx264", rate=original.average_rate or 30)
                video.width = original.codec_context.width
                video.height = original.codec_context.height
                video.pix_fmt = "yuv420p"
                video.codec_context.options = {"preset": "ultrafast", "crf": "20"}
                audio = {}
                for stream in reader.streams.audio:
                    if stream.codec_context.name != "aac":
                        raise ValueError("Desktop profile currently requires AAC audio")
                    audio[stream.index] = writer.add_stream_from_template(stream)
                    audio[stream.index].codec_context.codec_tag = "mp4a"
                for packet in reader.demux():
                    # 本地维护: 切集/关播放器时立刻停止转码, 不空占编码槽位。
                    if cancelled is not None and cancelled():
                        raise ValueError("Desktop encode cancelled")
                    if packet.stream.index == original.index:
                        for frame in packet.decode():
                            for encoded in video.encode(frame):
                                writer.mux(encoded)
                    elif packet.stream.index in audio and packet.dts is not None:
                        packet.stream = audio[packet.stream.index]
                        writer.mux(packet)
                for packet in video.encode():
                    writer.mux(packet)
        if not partial.is_file() or partial.stat().st_size == 0:
            raise ValueError("Desktop encoding produced no media")
        os.replace(partial, destination)
        return str(destination)
    finally:
        if partial.exists():
            partial.unlink()
