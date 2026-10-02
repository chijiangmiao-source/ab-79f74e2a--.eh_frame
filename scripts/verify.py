"""Compose 内验收入口：代码测试 + 构建检查 + API/HTTP 冒烟。

用法（在 compose 的 verify 服务内自动执行）：
    TARGET_URL=http://web:8080 python3 scripts/verify.py

全部通过退出码 0，任一失败退出码 1。
"""

from __future__ import annotations

import base64
import json
import os
import py_compile
import struct
import sys
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from _framegen import FrameBuilder, standard_cie, uleb  # noqa: E402

BASE = 0x401000
CFA = 0x7FF000000000
failures: list[str] = []


def section(title: str) -> None:
    print("\n=== " + title + " ===", flush=True)


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def build_checks() -> None:
    section("构建检查（字节码编译）")
    for rel in ("app/ehframe.py", "app/server.py",
                "tests/test_ehframe.py", "tests/_framegen.py",
                "scripts/verify.py"):
        path = os.path.join(ROOT, rel)
        try:
            py_compile.compile(path, doraise=True, quiet=1)
            check(f"编译 {rel}", True)
        except py_compile.PyCompileError as e:
            check(f"编译 {rel}", False, str(e))


def code_tests() -> None:
    section("代码测试（嵌套规则 / 恢复回退 / 截断 FDE 等）")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(_import_test_module())
    runner = unittest.TextTestRunner(verbosity=1, stream=sys.stdout)
    result = runner.run(suite)
    check("unittest 全部通过",
          result.wasSuccessful(),
          f"运行 {result.testsRun}，失败 {len(result.failures)}，"
          f"错误 {len(result.errors)}")


def _import_test_module():
    import importlib
    return importlib.import_module("test_ehframe")


def _request(method: str, url: str, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _valid_payload() -> dict:
    b = FrameBuilder()
    ci = b.add_cie(standard_cie())
    b.add_fde(ci, BASE, 0x100, b"")
    frame = b.build()
    mem = bytearray(0x80)
    mem[0x38:0x40] = struct.pack("<Q", 0x400500)  # [CFA-8]
    return {
        "eh_frame": base64.b64encode(frame).decode(),
        "pc": hex(BASE + 0x10),
        "registers": {"RSP": hex(CFA - 8)},
        "memory": {"base": hex(CFA - 0x40),
                   "data": base64.b64encode(bytes(mem)).decode()},
    }


def _truncated_payload() -> dict:
    g = FrameBuilder()
    g.add_cie(standard_cie())
    cie = g.build()
    ptr_field = len(cie) + 4
    payload = struct.pack("<III", ptr_field, BASE, 0x10) + bytes([0x80])
    raw = cie + struct.pack("<I", len(payload)) + payload
    return {"eh_frame": base64.b64encode(raw).decode(), "pc": hex(BASE)}


def _dangling_payload() -> dict:
    b = FrameBuilder()
    ci = b.add_cie(standard_cie())
    b.add_fde(ci, BASE, 0x10, b"")
    raw = bytearray(b.build())
    # 定位 FDE 的 CIE 指针字段并改写为不存在的反向距离
    ptr_field = b.fde_offsets[0] + 4
    struct.pack_into("<I", raw, ptr_field, 0x12345678)
    return {"eh_frame": base64.b64encode(bytes(raw)).decode(),
            "pc": hex(BASE + 1)}


def http_smoke(base_url: str) -> None:
    section(f"HTTP/API 冒烟（{base_url}）")

    # 健康检查
    try:
        with urllib.request.urlopen(base_url + "/healthz", timeout=5) as r:
            body = json.loads(r.read().decode())
            check("GET /healthz 200 且 status=ok",
                  r.status == 200 and body.get("status") == "ok")
    except Exception as e:  # noqa: BLE001
        check("GET /healthz 200 且 status=ok", False, repr(e))

    # 页面
    try:
        with urllib.request.urlopen(base_url + "/", timeout=5) as r:
            html = r.read().decode()
            check("GET / 返回页面",
                  r.status == 200 and "eh_frame" in html)
    except Exception as e:  # noqa: BLE001
        check("GET / 返回页面", False, repr(e))

    # 有效输入：命中、CFA、调用者 PC
    code, body = _request("POST", base_url + "/api/unwind", _valid_payload())
    ok = (code == 200 and body.get("hit")
          and body.get("return_address", {}).get("value") == 0x400500
          and body.get("cfa", {}).get("value") == CFA)
    check("POST 有效输入命中 FDE 并恢复调用者 PC/CFA", ok,
          f"code={code}")

    # 未命中：清除上次结论
    p = _valid_payload()
    p["pc"] = hex(BASE + 0x999)
    code, body = _request("POST", base_url + "/api/unwind", p)
    check("POST 未命中 PC 返回 hit=false 且无寄存器结论",
          code == 200 and body.get("hit") is False
          and "registers" not in body and "cfa" not in body,
          f"code={code}")

    # 截断 ULEB128：422 + 首个原始偏移 + 无部分寄存器结果
    code, body = _request("POST", base_url + "/api/unwind", _truncated_payload())
    check("POST 截断 FDE（ULEB128）422 并定位原始偏移，无部分结果",
          code == 422 and body.get("raw_offset") is not None
          and "ULEB128" in body.get("error", "")
          and "registers" not in body,
          f"code={code}, off={body.get('raw_offset')}")

    # 悬空 CIE 引用
    code, body = _request("POST", base_url + "/api/unwind", _dangling_payload())
    check("POST 悬空 CIE 引用 422 并定位指针字段",
          code == 422 and body.get("raw_offset") is not None
          and "悬空" in body.get("error", ""),
          f"code={code}, off={body.get('raw_offset')}")

    # 非法 Base64
    code, body = _request("POST", base_url + "/api/unwind",
                          {"eh_frame": "@@", "pc": "0x1"})
    check("POST 非法 Base64 返回 400", code == 400, f"code={code}")


def main() -> int:
    build_checks()
    code_tests()
    target = os.environ.get("TARGET_URL", "http://127.0.0.1:8080").rstrip("/")
    http_smoke(target)

    section("验收汇总")
    if failures:
        print(f"验收失败：{len(failures)} 项 —— {failures}")
        return 1
    print("验收全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
