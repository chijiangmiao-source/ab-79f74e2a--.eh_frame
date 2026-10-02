"""HTTP service for the x86-64 ``.eh_frame`` on-call analyzer.

Endpoints
---------
``GET  /``        single-page UI (paste Base64 section, PC, registers)
``GET  /healthz`` liveness probe -> ``{"status":"ok"}``
``POST /api/analyze`` JSON API, see :func:`handle_analyze`.

Only the Python standard library is used.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .eh_frame import (
    EHFrameError, MAX_SECTION_SIZE, analyze, parse_section, reg_name,
    parse_reg_number,
)
from . import samplegen

HOST = os.environ.get("EHF_HOST", "0.0.0.0")
PORT = int(os.environ.get("EHF_PORT", "8080"))
MAX_BODY = 512 * 1024  # generous envelope; the *decoded section* is capped

_INDEX_HTML = os.path.join(os.path.dirname(__file__), "static", "index.html")


def _b64_decode(text: str) -> bytes:
    compact = re.sub(r"\s+", "", text)
    if not compact:
        raise EHFrameError("未提供 Base64 节内容", 0)
    # Add standard padding back if the paste omitted it.
    pad = (-len(compact)) % 4
    compact += "=" * pad
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        try:
            raw = base64.urlsafe_b64decode(compact)
        except (binascii.Error, ValueError) as exc:
            raise EHFrameError("Base64 解码失败：%s" % exc, 0)
    if len(raw) > MAX_SECTION_SIZE:
        raise EHFrameError(
            "解码后原始节 %d 字节超过 192 KiB 上限" % len(raw), 0)
    return raw


def _parse_kv_lines(text: str, what: str) -> dict:
    out = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("%s 第 %d 行缺少 '='：%s" % (what, lineno, line))
        key, val = line.split("=", 1)
        out[key.strip()] = val.strip()
    return out


def _parse_int(text: str, what: str) -> int:
    try:
        return int(text.strip(), 0)
    except (AttributeError, ValueError):
        raise ValueError("%s 不是合法整数（支持 0x 十六进制）：%r"
                         % (what, text))


def _coerce_int(val) -> int:
    """Accept JSON numbers or 0x-prefixed/decimal strings."""
    if isinstance(val, bool):
        raise ValueError("寄存器/内存值必须是整数，不能是布尔值")
    if isinstance(val, int):
        return val
    return _parse_int(str(val), "数值")


def build_response(payload: dict) -> dict:
    """Pure transformation: request dict -> response dict (raises)."""
    raw = _b64_decode(payload.get("section_base64", ""))
    pc = _parse_int(str(payload.get("pc", "")), "PC")
    if pc < 0 or pc > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("PC 必须是 64 位无符号地址（支持 0x 十六进制）")

    regs_in: dict = {}
    if isinstance(payload.get("registers"), dict):
        for key, val in payload["registers"].items():
            regs_in[parse_reg_number(str(key))] = _coerce_int(val)
    elif isinstance(payload.get("registers_text"), str):
        for key, val in _parse_kv_lines(payload["registers_text"],
                                        "寄存器").items():
            regs_in[parse_reg_number(key)] = _parse_int(val, "寄存器值 %s" % key)

    mem_in: dict = {}
    if isinstance(payload.get("memory"), dict):
        for key, val in payload["memory"].items():
            mem_in[int(str(key), 0)] = _coerce_int(val)
    elif isinstance(payload.get("memory_text"), str):
        for key, val in _parse_kv_lines(payload["memory_text"],
                                        "内存快照").items():
            mem_in[_parse_int(key, "内存地址")] = _parse_int(val, "内存值")

    section = parse_section(raw)
    result = analyze(section, pc, regs_in, mem_in)

    if not result.hit:
        return {"hit": False, "pc": pc, "miss_reason": result.miss_reason}

    fde, cie, row = result.fde, result.cie, result.matched_row
    return {
        "hit": True,
        "pc": pc,
        "fde": {
            "length_field_offset": fde.offset,
            "cie_pointer_field_offset": fde.pointer_field_offset,
            "cie_pointer": fde.cie_pointer,
            "initial_location": fde.initial_location,
            "address_range": fde.address_range,
            "end_address": fde.end_address,
            "instructions_offset": fde.instructions_offset,
        },
        "cie": {
            "length_field_offset": cie.offset,
            "version": cie.version,
            "augmentation": cie.augmentation.decode("latin1"),
            "code_alignment_factor": cie.code_align,
            "data_alignment_factor": cie.data_align,
            "return_address_column": cie.ra_column,
            "return_address_register": reg_name(cie.ra_column),
            "initial_instructions_offset":
                cie.initial_instructions_offset,
        },
        "matched_row": {
            "fde_relative_location": result.relative_location,
            "absolute_location_start":
                fde.initial_location + result.relative_location,
        },
        "hit_range": [fde.initial_location, fde.end_address],
        "cfa": {
            "value": result.cfa_value,
            "rule": result.matched_row.cfa.describe(),
            "reason": result.cfa_reason,
            "origin_offset": result.matched_row.cfa_origin,
        },
        "caller_pc": result.caller_pc,
        "caller_pc_rule": result.caller_pc_rule.describe(
            cie.data_align),
        "caller_pc_reason": result.caller_pc_reason,
        "registers": [{
            "number": r.number,
            "name": r.name,
            "rule_kind": r.rule.kind.value,
            "rule": r.rule.describe(cie.data_align),
            "origin_offset": r.origin,
            "value": r.value,
            "recoverable": r.recoverable,
            "reason": r.reason,
        } for r in result.registers],
        "memory_reads": [{"address": a, "value": v}
                         for a, v in result.memory_reads],
        "timeline": [{
            "fde_relative_location": row.location,
            "absolute_location_start":
                fde.initial_location + row.location,
            "cfa": row.cfa.describe() if row.cfa else None,
            "regs": [
                {"register": reg_name(num), "number": num,
                 "kind": rule.kind.value,
                 "operand": rule.operand,
                 "operand_register": (reg_name(rule.operand)
                                      if rule.kind.value == "register"
                                      else None),
                 "byte_offset": (rule.operand * cie.data_align
                                 if rule.kind.value == "offset" else None),
                 "text": rule.describe(cie.data_align)}
                for num, rule in sorted(row.regs.items())
            ],
        } for row in result.timeline],
    }


# ---------------------------------------------------------------------------
# Demo sample
# ---------------------------------------------------------------------------


def static_sample_payload() -> dict:
    data, inputs = samplegen.main_section()
    return {
        "section_base64": base64.b64encode(data).decode("ascii"),
        "pc": hex(inputs["pc_rewritten"]),
        "registers_text": inputs["registers_text"],
        "memory_text": inputs["memory_text"],
    }


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    server_version = "EHFrameAnalyzer/1.0"

    def _send_json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/healthz":
            self._send_json(200, {"status": "ok", "service":
                                  "eh-frame-analyzer"})
            return
        if path in ("/", "/index.html"):
            try:
                with open(_INDEX_HTML, "rb") as fh:
                    body = fh.read()
            except OSError:
                self._send_json(500, {"error": "页面资源缺失"})
                return
            self.send_response(200)
            self.send_header("Content-Type",
                             "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/static_sample":
            self._send_json(200, static_sample_payload())
            return
        self._send_json(404, {"error": "not found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/analyze":
            self._send_json(404, {"error": "not found", "path": path})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self._send_json(400, {"error": "请求体为空"})
            return
        if length > MAX_BODY:
            self._send_json(413, {"error": "请求体超过 %d 字节" % MAX_BODY})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": "JSON 解析失败：%s" % exc})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "请求体必须是 JSON 对象"})
            return
        try:
            response = build_response(payload)
        except EHFrameError as exc:
            # Anchor the first raw section offset; never partial output.
            self._send_json(422, {"error": exc.message,
                                  "offset": exc.offset})
            return
        except (ValueError, KeyError) as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, response)

    def log_message(self, fmt, *args):  # quiet, structured
        msg = "%s - %s" % (self.address_string(), fmt % args)
        print("[http] %s" % msg, flush=True)


def make_server(host: str = HOST, port: int = PORT) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    return httpd


def serve() -> None:
    httpd = make_server()
    print("[http] .eh_frame analyzer listening on http://%s:%d"
          % (HOST, PORT), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve()
