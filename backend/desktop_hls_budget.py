"""Plan CRF/VBV against the existing HLS disk quota; no URLs or transport logic."""
import math


class EncodingBudgetExceeded(ValueError):
    """Fixed, non-sensitive classification of an exhausted output budget."""


def video_budget_options(duration_seconds, audio_bitrates, max_output_bytes):
    """Leave 10% plus 64 KiB for muxing, copy audio, and a two-second VBV.

    This is a rate-control plan, not a replacement for actual byte checks.
    Unknown duration retains the previous CRF policy and its hard disk guard.
    Resolution, frame timing, CRF target, and copied AAC packets stay unchanged.
    VBV can increase quantization when the budget binds; quality is not identical.
    """
    if (not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool)
            or max_output_bytes <= 0):
        raise ValueError("Invalid desktop output budget")
    if (not isinstance(duration_seconds, (int, float)) or isinstance(duration_seconds, bool)
            or not math.isfinite(duration_seconds) or duration_seconds <= 0):
        return {}
    # Metadata can omit AAC bitrates. Reserve at least 256 kbit/s per track;
    # retain the byte guard if metadata or the actual stream exceeds estimates.
    audio_rate = 0
    for rate in audio_bitrates:
        if not isinstance(rate, int) or isinstance(rate, bool) or rate <= 0:
            rate = 256_000
        audio_rate += max(256_000, rate)
    audio_bytes = audio_rate * (duration_seconds + 2) / 8
    video_bytes = max_output_bytes * 0.90 - 65_536 - audio_bytes
    max_kbps = math.floor(video_bytes * 8 / ((duration_seconds + 2) * 1000))
    if max_kbps < 64:
        raise EncodingBudgetExceeded("Desktop segment budget cannot fit this duration")
    return {"x264-params": f"vbv-maxrate={max_kbps}:vbv-bufsize={2 * max_kbps}"}
