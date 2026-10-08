#!/bin/zsh
# 红果桌面版 · macOS 启动器
# 用法: ./start.sh [端口]
set -euo pipefail
HERE="${0:A:h}"
PORT="${1:-8787}"

# Python venv(首次自动创建)
if [ ! -x "$HERE/venv/bin/python" ]; then
  echo "[start] 创建 venv…"
  uv venv --python 3.11 "$HERE/venv"
  "$HERE/venv/bin/python" -m ensurepip 2>/dev/null || true
  uv pip install --python "$HERE/venv/bin/python" \
    "requests==2.34.2" "fastapi==0.141.1" "uvicorn[standard]==0.52.4" \
    "pycryptodome==3.23.0" "av==18.1.0" "curl_cffi"
fi

# Java: 优先用仓库内 runtime, 否则系统 java
JAVA="${HONGGUO_JAVA:-}"
if [ -z "$JAVA" ]; then
  if [ -x "$HERE/../runtime/jdk-17.0.2.jdk/Contents/Home/bin/java" ]; then
    JAVA="$HERE/../runtime/jdk-17.0.2.jdk/Contents/Home/bin/java"
  elif command -v java >/dev/null; then
    JAVA="$(command -v java)"
  fi
fi
export HONGGUO_JAVA="$JAVA"

exec "$HERE/venv/bin/python" "$HERE/start_mac.py" --port "$PORT" "$@"
