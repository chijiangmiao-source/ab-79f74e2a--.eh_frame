"""零依赖 HTTP 服务：页面、健康检查、解栈 API。"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ehframe import FrameError, InputError, REG_NAMES, unwind

MAX_SECTION = 192 * 1024  # 192 KiB 原始节
MAX_BODY = 320 * 1024

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))


def _parse_int(value, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{what} 必须是整数或十六进制字符串")
    if isinstance(value, int):
        v = value
    else:
        s = value.strip()
        if not s:
            raise ValueError(f"{what} 为空")
        v = int(s, 16 if s.lower().startswith("0x") else 10)
    if v < 0 or v > (1 << 64) - 1:
        raise ValueError(f"{what} 超出 64 位无符号范围")
    return v


def _parse_registers(raw) -> dict[int, int]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("registers 必须是名称到值的对象")
    by_name = {name: i for i, name in enumerate(REG_NAMES[:-1])}
    out: dict[int, int] = {}
    for key, val in raw.items():
        k = str(key).strip().upper()
        if k not in by_name:
            raise ValueError(f"未知寄存器名称：{key}")
        out[by_name[k]] = _parse_int(val, f"寄存器 {k}")
    return out


def _b64_decode(s: str, what: str) -> bytes:
    if not isinstance(s, str):
        raise ValueError(f"{what} 必须是 Base64 字符串")
    clean = re.sub(r"\s+", "", s)
    try:
        return base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{what} 不是合法的 Base64")


def handle_unwind(payload: dict) -> tuple[int, dict]:
    if not isinstance(payload, dict):
        return 400, {"error": "请求体必须是 JSON 对象", "raw_offset": None}
    try:
        data = _b64_decode(payload.get("eh_frame", ""), ".eh_frame 节")
    except ValueError as e:
        return 400, {"error": str(e), "raw_offset": None}
    if len(data) == 0:
        return 400, {"error": ".eh_frame 节为空", "raw_offset": None}
    if len(data) > MAX_SECTION:
        return 413, {
            "error": f".eh_frame 原始节不得超过 192 KiB，当前 {len(data)} 字节",
            "raw_offset": None,
            "section_size": len(data),
        }
    try:
        pc = _parse_int(payload.get("pc"), "PC")
        regs = _parse_registers(payload.get("registers"))
        mem = None
        mem_base = None
        mem_field = payload.get("memory")
        if mem_field:
            if not isinstance(mem_field, dict):
                raise ValueError("memory 必须是包含 base 与 data 的对象")
            mem_base = _parse_int(mem_field.get("base"), "内存转储基址")
            mem = _b64_decode(mem_field.get("data", ""), "内存转储")
    except ValueError as e:
        return 400, {"error": str(e), "raw_offset": None}

    try:
        result = unwind(data, pc, regs, mem_base=mem_base, mem=mem)
    except FrameError as e:
        # 任何节数据错误：定位首个原始偏移，且不返回部分寄存器结果
        return 422, {"error": e.message, "raw_offset": e.raw_offset}
    except InputError as e:
        return 422, {"error": str(e), "raw_offset": None}
    result["section_size"] = len(data)
    return 200, result


def _json_safe(obj):
    """递归把超出 JS 安全整数范围的 int 转为 hex 字符串，避免前端丢精度。"""
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, int) and not isinstance(obj, bool) \
            and (obj >= (1 << 53) or obj < -(1 << 53)):
        return hex(obj)
    return obj


class Handler(BaseHTTPRequestHandler):
    server_version = "EhFrameUnwind/1.0"

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        payload = json.dumps(_json_safe(obj), ensure_ascii=False).encode("utf-8")
        self._send(code, payload, "application/json; charset=utf-8")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._json(200, {"status": "ok"})
            return
        if path in ("/", "/index.html"):
            with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/unwind":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._json(400, {"error": "空请求体", "raw_offset": None})
            return
        if length > MAX_BODY:
            self._json(413, {"error": "请求体过大", "raw_offset": None})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "请求体不是合法 UTF-8 JSON",
                             "raw_offset": None})
            return
        code, body = handle_unwind(payload)
        self._json(code, body)

    def log_message(self, fmt, *args):  # 简洁日志
        import sys
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(),
                                        fmt % args))


def serve(host: str, port: int) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"eh_frame 解栈服务监听 http://{host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    serve(host, port)
