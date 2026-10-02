"""Acceptance verifier for the .eh_frame on-call analyzer.

Run directly (spins up an in-process HTTP server on an ephemeral port)::

    python -m app.verify

or inside Compose against the running web service::

    EHF_SMOKE_URL=http://web:8080 python -m app.verify

Exit code is 0 only when every check passes:

1. build check (byte-compile all sources);
2. engine code tests — valid nested remember/restore rules, later-PC
   evidence rollback after restore_state, caller-PC recovery, misses;
3. rejection tests — truncated FDE, dangling CIE pointer, truncated
   ULEB128/SLEB128, rule-stack underflow, unsupported CIE version,
   out-of-bounds CFA memory read, unrecoverable caller PC — each
   anchored at its first raw section offset with no partial results;
4. API/HTTP smoke using both valid and failing inputs.
"""

from __future__ import annotations

import base64
import compileall
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer
from typing import Optional, Tuple

from .eh_frame import EHFrameError, analyze, parse_section
from . import samplegen as sg
from .server import _Handler, build_response, static_sample_payload

FAILURES = []
PASSED = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSED
    if cond:
        PASSED += 1
        print("  PASS  %s" % name)
    else:
        FAILURES.append("%s %s" % (name, detail))
        print("  FAIL  %s  %s" % (name, detail))


def expect_error(name: str, fn, offset: Optional[int] = None) -> None:
    try:
        fn()
    except EHFrameError as exc:
        ok = offset is None or exc.offset == offset
        check(name + "（拒绝并定位偏移 0x%x）" % exc.offset, ok,
              "期望偏移 0x%s，实际 0x%x：%s"
              % (None if offset is None else format(offset, "x"),
                 exc.offset, exc.message))
        return
    except Exception as exc:  # noqa: BLE001
        check(name, False, "抛出了非预期异常类型 %s: %s"
              % (type(exc).__name__, exc))
        return
    check(name, False, "应当拒绝但成功返回")


# Map friendly register names used in sample fixtures to DWARF numbers.
_REG_ALIAS = {
    "RAX": sg.RAX, "RDX": sg.RDX, "RCX": sg.RCX, "RBX": sg.RBX,
    "RSI": sg.RSI, "RDI": sg.RDI, "RBP": sg.RBP, "RSP": sg.RSP,
    "R8": sg.R8, "R9": sg.R9, "R10": sg.R10, "R11": sg.R11,
    "R12": sg.R12, "R13": sg.R13, "R14": sg.R14, "R15": sg.R15,
    "RIP": sg.RIP,
}


def parse_inputs2(inputs: dict):
    regs, mem = {}, {}
    for line in inputs["registers_text"].splitlines():
        k, v = line.split("=", 1)
        regs[_REG_ALIAS[k.strip().upper()]] = int(v, 0)
    for line in inputs["memory_text"].splitlines():
        a, v = line.split("=", 1)
        mem[int(a, 0)] = int(v, 0)
    return regs, mem


# ---------------------------------------------------------------------------
# Engine tests
# ---------------------------------------------------------------------------


def test_engine() -> None:
    print("[1/4] 引擎代码测试")
    data, inputs = sg.main_section()
    section = parse_section(data)
    check("解析出 1 个 CIE 与 1 个 FDE",
          len(section.cies) == 1 and len(section.fdes) == 1)
    regs, mem = parse_inputs2(inputs)

    # --- later PC with rewritten rules (loc 2) ---
    res2 = analyze(section, inputs["pc_rewritten"], regs, mem)
    check("pc_rewritten 命中", res2.hit)
    check("命中范围半开区间 [0x401000,0x401030)",
          res2.fde.initial_location == 0x401000
          and res2.fde.end_address == 0x401030)
    check("命中行 FDE 相对位置 = 2", res2.relative_location == 2)
    check("改写期 CFA = rbp+16 = 0x2010", res2.cfa_value == 0x2010,
          hex(res2.cfa_value or 0))
    check("改写期调用者 PC = 0x50001", res2.caller_pc == 0x50001,
          hex(res2.caller_pc or 0))
    by_name = {r.name: r for r in res2.registers}
    check("r12 same_value 取输入值 0x222",
          by_name["r12"].rule.kind.value == "same_value"
          and by_name["r12"].value == 0x222)
    check("r13 undefined 标记不可恢复",
          by_name["r13"].rule.kind.value == "undefined"
          and by_name["r13"].recoverable is False
          and by_name["r13"].value is None)
    check("r14 register(r15) = 0x444",
          by_name["r14"].rule.kind.value == "register"
          and by_name["r14"].rule.operand == sg.R15
          and by_name["r14"].value == 0x444)
    check("rbx offset 规则恢复 0x334", by_name["rbx"].value == 0x334)
    check("时间线含 5 个归约行", len(res2.timeline) == 5,
          str(len(res2.timeline)))

    # --- later PC after restore_state (loc 3): evidence must roll back ---
    res3 = analyze(section, inputs["pc_restored"], regs, mem)
    check("pc_restored 命中", res3.hit)
    check("回退后命中行相对位置 = 3", res3.relative_location == 3)
    check("回退后 CFA 退回保存时规则 rsp+16 = 0x1010",
          res3.cfa_value == 0x1010, hex(res3.cfa_value or 0))
    check("回退后调用者 PC = 0x50000", res3.caller_pc == 0x50000,
          hex(res3.caller_pc or 0))
    names3 = {r.name: r for r in res3.registers}
    check("回退后 r12 的 same_value 改写消失", "r12" not in names3)
    check("回退后 r13 的 undefined 改写消失", "r13" not in names3)
    check("回退后 r14 的 register 改写消失", "r14" not in names3)
    check("回退后 rbx 仍为保存快照中的 offset 规则 = 0x333",
          names3["rbx"].rule.kind.value == "offset"
          and names3["rbx"].value == 0x333)

    # --- PC at the exact end address must NOT hit (half-open) ---
    res_end = analyze(section, 0x401030, regs, mem)
    check("PC == end_address 未命中（半开区间）", not res_end.hit)

    # --- explicit miss; conclusion carries no register data ---
    res_miss = analyze(section, inputs["pc_miss"], regs, mem)
    check("区间外 PC 未命中", not res_miss.hit and res_miss.fde is None)
    check("未命中结论不含调用者 PC / CFA / 寄存器",
          res_miss.caller_pc is None and res_miss.cfa_value is None
          and res_miss.registers == [])

    # --- nested remember/restore ---
    nested = parse_section(sg.nested_section())
    nregs = {sg.RSP: 0x1000, sg.R12: 0x777}
    nmem = {0x1000: 0xAAA0}
    r_n2 = analyze(nested, 0x500002, nregs, nmem)
    n2 = {r.name: r for r in r_n2.registers}
    check("嵌套 loc2：r12 same、r13 undefined 同时存在",
          "r12" in n2 and n2["r12"].rule.kind.value == "same_value"
          and "r13" in n2
          and n2["r13"].rule.kind.value == "undefined")
    r_n3 = analyze(nested, 0x500003, nregs, nmem)
    n3 = {r.name: r for r in r_n3.registers}
    check("嵌套 loc3：内层 restore 后 r13 消失、r12 保留",
          "r13" not in n3 and "r12" in n3)
    r_n4 = analyze(nested, 0x500004, nregs, nmem)
    n4 = {r.name: r for r in r_n4.registers}
    check("嵌套 loc4：外层 restore 后 r12 也消失",
          "r12" not in n4 and "r13" not in n4)

    # --- CFA out-of-bounds memory read: no partial results ---
    expect_error("offset 恢复读取未提供的内存地址（越界）",
                 lambda: analyze(section, inputs["pc_restored"],
                                 regs, {}),
                 None)

    # --- unrecoverable caller PC (return column marked undefined) ---
    init = (bytes([sg.DEF_CFA]) + sg.uleb(sg.RSP) + sg.uleb(8)
            + bytes([0x80 | sg.RIP]) + sg.uleb(1))
    insns = (bytes([sg.ADV | 1])
             + bytes([sg.UNDEF]) + sg.uleb(sg.RIP))
    undef_ra = parse_section(
        sg.cie(init) + sg.fde(0, 0x900000, 0x10, insns))
    expect_error("返回地址列 undefined：调用者 PC 不可恢复即整体拒绝",
                 lambda: analyze(undef_ra, 0x900001,
                                 {sg.RSP: 0x2000}, {0x2000: 0x1})),

    # --- caller PC via register() chain ending in undefined ---
    insns_ru = (bytes([sg.ADV | 1])
                + bytes([sg.REG]) + sg.uleb(sg.RIP) + sg.uleb(sg.RAX)
                + bytes([sg.UNDEF]) + sg.uleb(sg.RAX))
    sec_ru = parse_section(
        sg.cie(init) + sg.fde(0, 0x910000, 0x10, insns_ru))
    expect_error("返回地址 register(rax) 且 rax undefined：调用者 PC 不可恢复",
                 lambda: analyze(sec_ru, 0x910001,
                                 {sg.RSP: 0x2000, sg.RAX: 0x55},
                                 {0x2000: 0x1}))

    # --- general register() chain ending in undefined: not recoverable ---
    insns_rr = (bytes([sg.ADV | 1])
                + bytes([sg.REG]) + sg.uleb(sg.R14) + sg.uleb(sg.R13)
                + bytes([sg.UNDEF]) + sg.uleb(sg.R13))
    sec_rr = parse_section(
        sg.cie(init) + sg.fde(0, 0x920000, 0x10, insns_rr))
    rr = analyze(sec_rr, 0x920001, {sg.RSP: 0x2000},
                 {0x2000: 0x1})
    rrmap = {r.name: r for r in rr.registers}
    check("register 链落到 undefined：r14 标记不可恢复且无值",
          not rrmap["r14"].recoverable and rrmap["r14"].value is None)
    check("register 链落到 undefined：调用者 PC 仍由 rip 规则正常恢复",
          rr.caller_pc == 0x1)

    # --- section too large ---
    big = b"\x00" * (192 * 1024 + 1)
    expect_error("超过 192 KiB 的节被拒绝",
                 lambda: parse_section(big), 0)

    test_extended_ops_and_multi_fde()


def test_extended_ops_and_multi_fde() -> None:
    """Coverage for advance_loc1/2/4, set_loc, extended offset/restore,
    'z' augmentation blocks and multiple FDEs sharing one CIE."""
    import struct

    def rec(body: bytes) -> bytes:
        return struct.pack("<I", len(body)) + body

    # CIE 'zR' with a 1-byte augmentation block (length 1, byte 0x1b).
    cie_body = (struct.pack("<I", 0) + bytes([1]) + b"zR\x00"
                + sg.uleb(1) + sg.sleb(-8) + sg.uleb(sg.RIP)
                + sg.uleb(1) + bytes([0x1B])
                + bytes([sg.DEF_CFA]) + sg.uleb(sg.RSP) + sg.uleb(8)
                + bytes([0x80 | sg.RIP]) + sg.uleb(1)
                + bytes([0x80 | sg.RBX]) + sg.uleb(2))
    c = rec(cie_body)
    cie_off = 0

    def zfde(initial_location: int, rng: int, insns: bytes) -> bytes:
        body = (struct.pack("<I", cie_off)
                + struct.pack("<II", initial_location, rng)
                + sg.uleb(0)          # FDE augmentation length 0
                + insns)
        return rec(body)

    # FDE A exercises advance_loc1 + extended offset (r12, factor 3).
    insns_a = bytes([sg.ADV1, 2]) + bytes([sg.OFF_EXT]) + sg.uleb(sg.R12) \
        + sg.uleb(3)
    fa = zfde(0xA00000, 0x10, insns_a)
    off_a = len(c)

    # FDE B exercises advance_loc2, advance_loc4, set_loc (absolute),
    # extended restore of rbx, and a later rule change.
    insns_b = b"".join([
        bytes([sg.ADV2, 3, 0]),               # +3
        bytes([sg.DEF_CFA_OFF]) + sg.uleb(16),
        bytes([sg.ADV4, 2, 0, 0, 0]),         # +2 -> loc 5
        bytes([sg.RES_EXT]) + sg.uleb(sg.RBX),  # restore rbx to CIE rule
        bytes([sg.DEF_CFA_OFF]) + sg.uleb(24),
    ])
    fb = zfde(0xB00000, 0x20, insns_b)

    # FDE C uses set_loc with an absolute 32-bit address (jumps to
    # initial_location + 4 directly).
    insns_c = bytes([0x01]) + struct.pack("<I", 0xC00004) \
        + bytes([sg.SAME]) + sg.uleb(sg.RBP)
    fc = zfde(0xC00000, 0x10, insns_c)

    section = parse_section(c + fa + fb + fc)
    check("多 FDE：解析出 1 CIE / 3 FDE",
          len(section.cies) == 1 and len(section.fdes) == 3)
    check("FDE 指针均为绝对偏移并正确关联同一 CIE",
          all(f.cie is section.cies[0] for f in section.fdes))

    # FDE A at loc 2: r12 offset factor 3 -> [CFA-24].
    # CFA = rsp+8 = 0x1008: rip@[0x1000], rbx(CIE f2)@[0xff8],
    # r12(f3)@[0xff0].
    ra = analyze(section, 0xA00002, {sg.RSP: 0x1000},
                 {0x1000: 0xAA00, 0x0FF8: 0xBB, 0x0FF0: 0xBEEF})
    a = {r.name: r for r in ra.registers}
    check("advance_loc1 + extended offset：r12 = [CFA-24] = 0xbeef",
          "r12" in a and a["r12"].value == 0xBEEF
          and a["r12"].rule.kind.value == "offset"
          and a["r12"].rule.operand == 3)

    # FDE B at loc 5: def_cfa_offset changed to 24 after restore.
    # CFA=rsp+24=0x2018; rip@[0x2010]=0xcc00; rbx(CIE f2)@[0x2008].
    rb = analyze(section, 0xB00005, {sg.RSP: 0x2000},
                 {0x2010: 0xCC00, 0x2008: 0xB1})
    check("advance_loc2/4 + extended restore + offset 24：CFA=0x2018，"
          "调用者 PC=0xcc00",
          rb.cfa_value == 0x2018 and rb.caller_pc == 0xCC00)
    bnames = {r.name: r for r in rb.registers}
    check("extended restore 后 rbx 回到 CIE offset(factor 2) 规则",
          "rbx" in bnames and bnames["rbx"].rule.kind.value == "offset"
          and bnames["rbx"].rule.operand == 2
          and bnames["rbx"].value == 0xB1)

    # FDE C at absolute set_loc: rbp same_value.
    # CFA=rsp+8=0x3008; rip@[0x3000]; rbx(CIE f2)@[0x2ff8].
    cmem = {0x3000: 0xDD00, 0x2FF8: 0xB2}
    rc = analyze(section, 0xC00004,
                 {sg.RSP: 0x3000, sg.RBP: 0x77}, cmem)
    cnames = {r.name: r for r in rc.registers}
    check("set_loc 绝对 32 位定位到 loc 4，rbp same_value=0x77",
          rc.relative_location == 4
          and cnames.get("rbp", None) is not None
          and cnames["rbp"].rule.kind.value == "same_value"
          and cnames["rbp"].value == 0x77
          and rc.caller_pc == 0xDD00)
    # Before the set_loc boundary (loc 0) rbp must not be same_value.
    rc0 = analyze(section, 0xC00000,
                  {sg.RSP: 0x3000, sg.RBP: 0x77}, cmem)
    check("set_loc 之前（loc 0）不含 rbp same_value 改写",
          all(not (r.name == "rbp"
                   and r.rule.kind.value == "same_value")
              for r in rc0.registers))

    # set_loc that moves the location backwards must be rejected.
    bad_fde = zfde(0xC00000, 0x20,
                   bytes([0x01]) + struct.pack("<I", 0xC00002)
                   + bytes([sg.ADV1, 5])
                   + bytes([0x01]) + struct.pack("<I", 0xC00003))
    expect_error("set_loc 地址回退被拒绝",
                 lambda: analyze(parse_section(c + bad_fde), 0xC00003,
                                 {sg.RSP: 0x1}, {0x1: 0x0}))



def test_failures() -> None:
    print("[2/4] 畸形输入拒绝测试（定位首个原始偏移，无部分结果）")
    # truncated FDE: length word overrun anchored at the FDE start.
    trunc = sg.truncated_fde_section()
    cie_len = len(sg.cie(
        bytes([sg.DEF_CFA]) + sg.uleb(sg.RSP) + sg.uleb(8)
        + bytes([0x80 | sg.RIP]) + sg.uleb(1)))
    expect_error("截断 FDE（长度越界）", lambda: parse_section(trunc),
                 cie_len)

    # dangling CIE pointer: anchored at the FDE pointer field.
    dangling = sg.dangling_cie_section()
    expect_error("悬空 CIE 引用", lambda: parse_section(dangling),
                 cie_len + 4)

    expect_error("截断的 ULEB128",
                 lambda: parse_section(sg.truncated_uleb_section()), 10)
    expect_error("截断的 SLEB128",
                 lambda: parse_section(sg.truncated_sleb_section()), 11)

    under = sg.stack_underflow_section()
    sec = parse_section(under)  # parses fine; reduction must fail
    fde_insn = sec.fdes[0].instructions_offset
    expect_error("规则栈下溢（restore_state 无匹配 remember）",
                 lambda: analyze(sec, 0x800001, {sg.RSP: 0x10},
                                 {0x10: 0x0}),
                 fde_insn + 1)

    expect_error("CIE version 3 被拒绝",
                 lambda: parse_section(sg.unsupported_version_section()),
                 8)


# ---------------------------------------------------------------------------
# Build check
# ---------------------------------------------------------------------------


def test_build() -> None:
    print("[3/4] 构建检查（compileall）")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ok = compileall.compile_dir(os.path.join(root, "app"), quiet=1)
    check("全部 Python 源字节码编译通过", bool(ok))


# ---------------------------------------------------------------------------
# HTTP smoke
# ---------------------------------------------------------------------------


def _start_local_server() -> Tuple[ThreadingHTTPServer, str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def _request(method: str, url: str, payload=None, timeout: float = 5.0):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_http() -> None:
    print("[4/4] API / HTTP 冒烟")
    base = os.environ.get("EHF_SMOKE_URL")
    httpd = None
    if base:
        print("  使用外部冒烟目标：%s（Compose 内的 web 服务）" % base)
        # Wait briefly for the dependency to become ready.
        for _ in range(30):
            try:
                status, body = _request("GET", base + "/healthz")
                if status == 200:
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
    else:
        httpd, base = _start_local_server()

    try:
        status, body = _request("GET", base + "/healthz")
        check("GET /healthz → 200 ok",
              status == 200 and body.get("status") == "ok", str(body))

        with urllib.request.urlopen(base + "/", timeout=5) as resp:
            page = resp.read().decode("utf-8")
        check("GET / 返回分析台页面",
              resp.status == 200 and ".eh_frame" in page)

        status, sample = _request("GET", base + "/static_sample")
        check("GET /static_sample → 200", status == 200
              and "section_base64" in sample)

        data, inputs = sg.main_section()
        b64 = base64.b64encode(data).decode("ascii")
        regs_text, mem_text = inputs["registers_text"], inputs["memory_text"]

        # valid input: later PC after restore_state
        status, body = _request("POST", base + "/api/analyze", {
            "section_base64": b64, "pc": hex(inputs["pc_restored"]),
            "registers_text": regs_text, "memory_text": mem_text})
        check("有效输入（回退 PC）→ 200 命中",
              status == 200 and body.get("hit") is True
              and body.get("caller_pc") == 0x50000
              and body.get("cfa", {}).get("value") == 0x1010,
              json.dumps(body, ensure_ascii=False)[:300])

        # valid input: rewritten-rules PC
        status, body = _request("POST", base + "/api/analyze", {
            "section_base64": b64, "pc": hex(inputs["pc_rewritten"]),
            "registers_text": regs_text, "memory_text": mem_text})
        regmap = {r["name"]: r for r in body.get("registers", [])}
        check("有效输入（改写 PC）→ 200，嵌套规则取值正确",
              status == 200 and body.get("caller_pc") == 0x50001
              and regmap.get("r12", {}).get("value") == 0x222
              and regmap.get("r14", {}).get("value") == 0x444
              and regmap.get("r13", {}).get("recoverable") is False,
              json.dumps(body, ensure_ascii=False)[:300])

        # miss: 200 with hit=false and no conclusion fields
        status, body = _request("POST", base + "/api/analyze", {
            "section_base64": b64, "pc": hex(inputs["pc_miss"]),
            "registers_text": regs_text, "memory_text": mem_text})
        check("未命中输入 → 200 hit=false 且无结论字段",
              status == 200 and body.get("hit") is False
              and "caller_pc" not in body and "registers" not in body
              and "miss_reason" in body,
              json.dumps(body, ensure_ascii=False)[:200])

        # failing inputs -> 422, first raw offset, no partial results
        for name, raw, expect_off in (
            ("截断 FDE", sg.truncated_fde_section(), None),
            ("悬空 CIE", sg.dangling_cie_section(), None),
            ("截断 ULEB128", sg.truncated_uleb_section(), 10),
            ("截断 SLEB128", sg.truncated_sleb_section(), 11),
            ("栈下溢 FDE", sg.stack_underflow_section(), None),
        ):
            status, body = _request("POST", base + "/api/analyze", {
                "section_base64": base64.b64encode(raw).decode("ascii"),
                "pc": "0x800001",
                "registers_text": "rsp=0x10",
                "memory_text": "0x10=0x0"})
            ok = (status == 422 and isinstance(body.get("offset"), int)
                  and "registers" not in body)
            if expect_off is not None:
                ok = ok and body.get("offset") == expect_off
            check("失败输入（%s）→ 422 且带首个偏移、无部分寄存器" % name,
                  ok, "status=%s body=%s"
                  % (status, json.dumps(body, ensure_ascii=False)[:200]))

        # invalid Base64
        status, body = _request("POST", base + "/api/analyze", {
            "section_base64": "!!!not-base64!!!", "pc": "0x1"})
        check("非法 Base64 → 422", status == 422 and "offset" in body,
              str(body))

        # CFA memory out of bounds through the API
        status, body = _request("POST", base + "/api/analyze", {
            "section_base64": b64, "pc": hex(inputs["pc_restored"]),
            "registers_text": regs_text, "memory_text": "0x1=0x1"})
        check("内存越界 → 422 且无部分结果",
              status == 422 and isinstance(body.get("offset"), int)
              and "registers" not in body, json.dumps(
                  body, ensure_ascii=False)[:200])

        # unknown route
        status, _ = _request("GET", base + "/nope")
        check("未知路径 → 404", status == 404)
    finally:
        if httpd is not None:
            httpd.shutdown()


def main() -> int:
    print("=" * 68)
    print(".eh_frame 值班分析台 — 验收 verify")
    print("=" * 68)
    try:
        test_build()
        test_engine()
        test_failures()
        test_http()
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        FAILURES.append("verify 自身异常：%s" % exc)

    print("=" * 68)
    print("通过 %d 项，失败 %d 项" % (PASSED, len(FAILURES)))
    if FAILURES:
        print("验收结果：失败（退出码 1）")
        for f in FAILURES:
            print("  - %s" % f)
        return 1
    print("验收结果：全部通过（退出码 0）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
