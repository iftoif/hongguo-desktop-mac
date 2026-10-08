"""Pure metadata selection for desktop playback; no media or network access."""
import re


def _positive_int(value):
    # API numbers may be decimal strings. Reject bool, fractional and signed data.
    if isinstance(value, int) and not isinstance(value, bool):
        return max(value, 0)
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,16}", value.strip()):
        return int(value.strip())
    return 0


def _metadata(track):
    meta = track.get("video_meta")
    return meta if isinstance(meta, dict) else {}


def _definition(meta):
    value = meta.get("definition")
    return value.strip().lower() if isinstance(value, str) else ""


def _resolution(meta):
    width, height = (_positive_int(meta.get(key)) for key in ("vwidth", "vheight"))
    if width and height:
        # Short edge makes 1080x1920 portrait and 1920x1080 landscape comparable.
        return min(width, height)
    match = re.fullmatch(r"([0-9]{3,4})p?", _definition(meta))
    return int(match[1]) if match else 0


def choose_desktop_track(tracks):
    """Choose known resolution first, bytes second; retain input order on ties.

    Missing dimensions fall back to a numeric definition; entirely unknown
    resolutions fall back to size. This is not a perceptual-quality assessment.
    Return the existing selector's (track, definition, fallback) tuple contract.
    """
    candidates = [track for track in (tracks or []) if isinstance(track, dict)]
    if not candidates:
        return None, None, False
    selected = max(candidates, key=lambda track: (
        _resolution(_metadata(track)), _positive_int(_metadata(track).get("size"))))
    meta = _metadata(selected)
    definition = _definition(meta)
    if not definition and (resolution := _resolution(meta)):
        definition = f"{resolution}p"
    return selected, definition, False
