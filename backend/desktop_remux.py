"""Remux decoded samples for strict desktop players without transcoding."""
import os
from pathlib import Path
import uuid


def remux(source, destination):
    import av
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Remux requires distinct input and output")
    temporary = destination.with_name(destination.name + "." + uuid.uuid4().hex + ".partial")
    try:
        with av.open(str(source)) as input_file:
            with av.open(str(temporary), "w", format="mp4", options={"movflags": "+faststart"}) as output_file:
                streams = {}
                for stream in input_file.streams:
                    if stream.type not in ("video", "audio"):
                        continue
                    target = output_file.add_stream_from_template(stream)
                    if stream.codec_context.name == "hevc":
                        target.codec_context.codec_tag = "hvc1"
                    elif stream.codec_context.name == "aac":
                        target.codec_context.codec_tag = "mp4a"
                    streams[stream.index] = target
                if not streams:
                    raise ValueError("No audio/video streams to remux")
                for packet in input_file.demux():
                    if packet.dts is not None and packet.stream.index in streams:
                        packet.stream = streams[packet.stream.index]
                        output_file.mux(packet)
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise ValueError("Remux produced no media")
        os.replace(temporary, destination)
        return str(destination)
    finally:
        if temporary.exists():
            temporary.unlink()  # Only the unique partial file created by this invocation.
