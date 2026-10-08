"""Managed Windows entry point. No UI, persisted keys, or phone fallback."""
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import json
import re
import threading
import ctypes
import struct

_stage = "handshake"
_signer_exit_code = None
_signer_errors = set()

def drain_signer(stream):
    for raw in iter(stream.readline, b""):
        line = raw.decode("utf-8", errors="replace")
        _signer_errors.update(re.findall(r"\b[A-Za-z][A-Za-z0-9_.]*(?:Exception|Error)\b", line))
        for marker in ("jvm.cfg", "Could not find", "Could not reserve", "Error opening", "could not open"):
            if marker in line:
                _signer_errors.add(marker)

def stage(value):
    global _stage
    _stage = value


def validate_session(value):
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise RuntimeError("Invalid desktop session credential")

def launcher_path(value):
    # Rust canonicalize returns verbatim Windows paths. Some JVM launchers
    # cannot resolve their runtime/configuration from this spelling.
    text = str(value)
    if text.startswith("\\\\?\\UNC\\"):
        return "\\\\" + text[8:]
    if text.startswith("\\\\?\\") and len(text) > 6 and text[5:7] == ":\\":
        return text[4:]
    return text


def api_socket():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        # The OS chooses a free port; keep the exclusive socket until shutdown.
        # Never probe, release, and then try to reacquire an advertised port.
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        listener.setblocking(False)
        return listener
    except BaseException:
        listener.close()
        raise


def announce_endpoint(listener):
    # One bounded control line, only after START and successful socket ownership.
    # stdout is a private parent pipe, not a log or a persisted endpoint file.
    port = listener.getsockname()[1]
    # Binary output avoids Windows text-mode CRLF translation of the protocol.
    sys.stdout.buffer.write(f"HONGGUO_PORT_V1 {port}\n".encode("ascii"))
    sys.stdout.buffer.flush()
    # Providers may print. They must not retain or block the control pipe.
    with open(os.devnull, "w") as sink:
        os.dup2(sink.fileno(), sys.stdout.fileno())
    os.environ["PORT"] = str(port)
    return port


class TcpRow(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ("state", "address", "port", "remote_address", "remote_port", "pid")]


class TcpTable(ctypes.Structure):
    _fields_ = [("count", ctypes.c_uint32), ("rows", TcpRow * 1)]


def parse_listener_table(raw, pid):
    if len(raw) < ctypes.sizeof(ctypes.c_uint32):
        raise RuntimeError("Truncated listener count")
    count = ctypes.c_uint32.from_buffer_copy(raw).value
    offset, stride = TcpTable.rows.offset, ctypes.sizeof(TcpRow)
    if offset + count * stride > len(raw):
        raise RuntimeError("Truncated listener table")
    ports = []
    for index in range(count):
        row = TcpRow.from_buffer_copy(raw, offset + index * stride)
        if row.pid != pid or row.state != 2:  # MIB_TCP_STATE_LISTEN
            continue
        address = socket.inet_ntoa(struct.pack("=I", row.address))
        port = socket.ntohs(row.port & 0xffff)
        if address != "127.0.0.1" or not 1 <= port <= 65535:
            raise RuntimeError("Owned signer has an unexpected listener")
        ports.append(port)
    if len(ports) > 1:
        raise RuntimeError("Owned signer endpoint is ambiguous")
    return ports[0] if ports else None


def owned_listener_port(pid, query=None):
    if query is None:
        # System32 lookup prevents a current-directory DLL from being loaded.
        library = ctypes.WinDLL("iphlpapi.dll", winmode=0x00000800)
        query = library.GetExtendedTcpTable
        query.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                          ctypes.c_int, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        query.restype = ctypes.c_uint32
    size = ctypes.c_uint32(0)
    code = query(None, ctypes.byref(size), False, socket.AF_INET, 3, 0)
    if code not in (0, 122):  # ERROR_INSUFFICIENT_BUFFER
        raise OSError(code, "Cannot inspect owned signer listener")
    for _ in range(4):
        if not ctypes.sizeof(ctypes.c_uint32) <= size.value <= 1024 * 1024:
            raise RuntimeError("Unexpected listener table size")
        allocation = size.value
        buffer = ctypes.create_string_buffer(allocation)
        code = query(buffer, ctypes.byref(size), False, socket.AF_INET, 3, 0)
        if code == 122:
            continue  # Table can grow between the size query and the read.
        if code != 0:
            raise OSError(code, "Cannot inspect owned signer listener")
        if size.value > allocation:
            raise RuntimeError("Listener table exceeds allocated buffer")
        return parse_listener_table(buffer.raw[:size.value], pid)
    raise RuntimeError("Listener table repeatedly changed")


def wait_signer(process, timeout=45):
    global _signer_exit_code
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _signer_exit_code = process.returncode
            raise RuntimeError("Signing service exited")
        port = owned_listener_port(process.pid)
        if port is not None:
            if process.poll() is not None:
                _signer_exit_code = process.returncode
                raise RuntimeError("Signing service exited")
            return port
        time.sleep(0.05)
    raise RuntimeError("Signing service startup timed out")


def serve_owned_api(server, listener, signer):
    """Stop serving when our signer exits; never attach to or restart a signer."""
    global _signer_exit_code
    stopped = threading.Event()
    exited = []

    def watch():
        while not stopped.is_set():
            code = signer.poll()
            if code is not None:
                exited.append(code)
                server.should_exit = True
                return
            stopped.wait(0.25)

    monitor = threading.Thread(target=watch, name="desktop-signer-watch", daemon=True)
    monitor.start()
    try:
        server.run(sockets=[listener])
    finally:
        stopped.set()
        monitor.join()
    # Also catch an exit between the final poll and a normal API return. The
    # caller terminates a healthy signer only after this function has returned.
    code = exited[0] if exited else signer.poll()
    if code is not None:
        _signer_exit_code = code
        stage("signer_runtime")
        raise RuntimeError("Owned signing service exited while serving")


def main():
    # This must precede provider imports and subprocess creation: the parent
    # only sends START after successfully assigning this process to its job.
    if sys.stdin.readline(16) != "START\n":
        raise RuntimeError("Desktop parent handshake required")
    validate_session(os.environ.get("HONGGUO_SESSION_API_KEY", ""))
    stage("configuration")
    root = Path(launcher_path(Path(__file__).resolve())).parent
    data = Path(os.environ["HONGGUO_BACKEND_DATA_DIR"])
    if not data.is_absolute():
        raise RuntimeError("An absolute application data directory is required")
    data.mkdir(parents=True, exist_ok=True)
    content_config = Path(os.environ.get("HONGGUO_CONTENT_CONFIG") or data / "content-config.json")
    if not content_config.is_absolute() or not content_config.is_file():
        raise RuntimeError("Content configuration is missing")
    os.environ["HONGGUO_CONTENT_CONFIG"] = str(content_config)
    os.environ["ADMIN_TOKEN"] = secrets.token_hex(32)
    os.environ.pop("SIGN_SERVER", None)
    os.environ["BIND_HOST"] = "127.0.0.1"
    os.environ["HONGGUO_STREAM_CACHE"] = str(data / "stream-cache")
    if os.environ.get("HONGGUO_HLS_WORK_DIR"):
        os.environ["HONGGUO_HLS_WORK_DIR"] = launcher_path(os.environ["HONGGUO_HLS_WORK_DIR"])
    os.environ["IMPERSONATE"] = ""
    os.environ["DEVICE_POOL_SIZE"] = "0"  # Desktop never rotates device identities.
    os.environ.pop("API_KEYS", None)
    # Do not inherit arbitrary developer proxy settings in packaged mode.
    os.environ.pop("HONGGUO_PROXY", None)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(name, None)
    sys.path.insert(0, str(root))  # -I intentionally excludes the script directory.
    stage("api_bind")
    listener = api_socket()  # Keep ownership through uvicorn startup.
    signer = None
    try:
        port = announce_endpoint(listener)
        # The signer owns its OS-assigned port continuously from bind to exit.
        stage("signer_spawn")
        signer = subprocess.Popen(
            [str(root / "jre/bin/java.exe"), "-Djava.net.preferIPv4Stack=true", "--add-opens", "java.base/java.lang=ALL-UNNAMED",
             "-Xmx512m", "-XX:+ExitOnOutOfMemoryError", "-cp", "unidbg-sign.jar",
             "com.hongguo.sign.FqTrace", "serve", "0"],
            cwd=root / "sign", stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        reader = threading.Thread(target=drain_signer, args=(signer.stdout,), daemon=True)
        reader.start()
        stage("signer_ready")
        signer_port = wait_signer(signer)
        os.environ["SIGN_SERVER"] = f"http://127.0.0.1:{signer_port}"
        stage("provider_import")
        import server
        import uvicorn
        stage("api_run")
        config = uvicorn.Config(server.app, host="127.0.0.1", port=port,
                                log_config=None, access_log=False, log_level="critical")
        serve_owned_api(uvicorn.Server(config), listener, signer)
    finally:
        listener.close()
        if signer is not None:
            if signer.poll() is None:
                signer.terminate()
            try:
                signer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                signer.kill()
                signer.wait(timeout=5)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Only a fixed stage and exception type; never serialize error text.
        try:
            data = Path(os.environ["HONGGUO_BACKEND_DATA_DIR"])
            if data.is_absolute() and data.is_dir():
                (data / "startup-status.json").write_text(json.dumps({"stage": _stage, "error_type": type(error).__name__, "signer_exit_code": _signer_exit_code, "signer_errors": sorted(_signer_errors)}), encoding="utf-8")
        except Exception:
            pass
        # Parent detects process exit. Never emit raw exceptions containing URLs.
        sys.exit(1)
