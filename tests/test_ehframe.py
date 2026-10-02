import base64
import os
import struct
import sys
import threading
import time
import unittest
from http.client import HTTPConnection

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
sys.path.insert(0, os.path.dirname(__file__))

from ehframe import FrameError, InputError, parse_section, reduce_to_pc, unwind  # noqa
from server import handle_unwind, Handler, ThreadingHTTPServer  # noqa
from _framegen import FrameBuilder, sleb, standard_cie, uleb  # noqa

BASE = 0x401000
CFA_BASE = 0x7FF000000000


def mem_image(base: int, writes: dict[int, int], size: int = 0x80) -> bytes:
    m = bytearray(size)
    for addr, val in writes.items():
        idx = addr - base
        m[idx:idx + 8] = struct.pack("<Q", val)
    return bytes(m)


def standard_frame(insns: bytes):
    b = FrameBuilder()
    ci = b.add_cie(standard_cie())
    fi = b.add_fde(ci, BASE, 0x100, insns)
    return b.build()


class ParseTests(unittest.TestCase):
    def test_basic_hit_and_values(self):
        data = standard_frame(b"")
        cies, fdes = parse_section(data)
        self.assertEqual(len(cies), 1)
        self.assertEqual(len(fdes), 1)
        fde = fdes[0]
        self.assertEqual(fde.initial_location, BASE)
        self.assertIn(fde.cie_offset, cies)

        # CFA = RBP+8，RA 在 [CFA-8]
        pc = BASE + 0x10
        cfa = CFA_BASE
        ret = 0x400500
        mem = mem_image(cfa - 0x40, {cfa - 8: ret})
        r = unwind(data, pc, {7: cfa - 8}, mem_base=cfa - 0x40, mem=mem)
        self.assertTrue(r["hit"])
        self.assertEqual(r["cfa"]["value"], cfa)
        self.assertEqual(r["return_address"]["value"], ret)
        self.assertEqual(r["fde"]["range_end"], BASE + 0x100)

    def test_pc_miss_clears_conclusion(self):
        data = standard_frame(b"")
        r = unwind(data, BASE + 0x200, {7: CFA_BASE})
        self.assertFalse(r["hit"])
        self.assertNotIn("registers", r)
        self.assertNotIn("cfa", r)
        r2 = unwind(data, BASE - 1, {})
        self.assertFalse(r2["hit"])

    def test_pc_at_range_end_excluded(self):
        data = standard_frame(b"")
        self.assertFalse(unwind(data, BASE + 0x100, {})["hit"])
        cies, fdes = parse_section(data)
        self.assertTrue(BASE >= fdes[0].initial_location
                        and BASE < fdes[0].initial_location + fdes[0].address_range)

    def test_remember_restore_rollback_later_pc(self):
        # loc 2: remember；随后改写 CFA offset 与 RBX 规则；
        # loc 4: 再改 CFA；loc 6: restore —— 更晚 PC 必须回到保存时规则
        insns = bytes([
            0x42,                       # advance_loc 2
            0x0A,                       # remember_state
            0x0E]) + uleb(40) + bytes([ # def_cfa_offset 40
            0x83]) + uleb(2) + bytes([  # offset RBX(3) factored 2 => -16
            0x42,                       # advance_loc 2 -> loc 4
            0x0E]) + uleb(56) + bytes([ # def_cfa_offset 56
            0x42,                       # advance_loc 2 -> loc 6
            0x0B,                       # restore_state
        ])
        data = standard_frame(insns)
        cies, fdes = parse_section(data)

        # loc 5（restore 之前）：CFA = RBP+56，RBX=[CFA-16]
        st5 = reduce_to_pc(cies[fdes[0].cie_offset], fdes[0], BASE + 5)
        self.assertEqual(st5.cfa, ("reg", 7, 56))
        self.assertEqual(st5.rules[3], ("o", -16))

        # loc 7（restore 之后）：回退到保存时 CFA=RBP+8，RBX 无规则
        st7 = reduce_to_pc(cies[fdes[0].cie_offset], fdes[0], BASE + 7)
        self.assertEqual(st7.cfa, ("reg", 7, 8))
        self.assertNotIn(3, st7.rules)
        # RA 的 CIE 初始 offset 规则仍在
        self.assertEqual(st7.rules[16], ("o", -8))

    def test_nested_remember_restore(self):
        # 两层快照：内层改写后 restore 到外层，外层再 restore 到 CIE 初始
        insns = bytes([
            0x41, 0x0A,                       # loc1 remember L1
            0x0E]) + uleb(24) + bytes([       # CFA+24
            0x41, 0x0A,                       # loc2 remember L2
            0x0E]) + uleb(48) + bytes([       # CFA+48
            0x41, 0x0B,                       # loc3 restore -> L1 (24)
            0x41, 0x0B,                       # loc4 restore -> 初始 (8)
        ])
        data = standard_frame(insns)
        cies, fdes = parse_section(data)
        s = reduce_to_pc(cies[fdes[0].cie_offset], fdes[0], BASE + 2)
        self.assertEqual(s.cfa[2], 48)
        s = reduce_to_pc(cies[fdes[0].cie_offset], fdes[0], BASE + 3)
        self.assertEqual(s.cfa[2], 24)
        s = reduce_to_pc(cies[fdes[0].cie_offset], fdes[0], BASE + 4)
        self.assertEqual(s.cfa[2], 8)

    def test_rule_stack_underflow(self):
        data = standard_frame(bytes([0x0B]))  # 无 remember 的 restore
        cies, fdes = parse_section(data)
        with self.assertRaises(FrameError) as cm:
            reduce_to_pc(cies[fdes[0].cie_offset], fdes[0], BASE)
        self.assertIn("下溢", cm.exception.message)
        # 指向 restore_state 操作码的原始偏移
        self.assertEqual(cm.exception.raw_offset,
                         fdes[0].instructions[0].raw_offset)

    def test_dangling_cie_pointer(self):
        data = bytearray(standard_frame(b""))
        cies, fdes = parse_section(bytes(data))
        fde = fdes[0]
        # 把 CIE 指针改成一个不存在的反向距离
        struct.pack_into("<I", data, fde.cie_ptr_field, 0x12345678)
        with self.assertRaises(FrameError) as cm:
            parse_section(bytes(data))
        self.assertIn("悬空", cm.exception.message)
        self.assertEqual(cm.exception.raw_offset, fde.cie_ptr_field)

    def test_length_overrun(self):
        data = bytearray(standard_frame(b""))
        struct.pack_into("<I", data, 0, 0xFFFFFF)
        with self.assertRaises(FrameError) as cm:
            parse_section(bytes(data))
        self.assertEqual(cm.exception.raw_offset, 0)

    def test_truncated_uleb_in_fde_auglen(self):
        # FDE 的增强数据长度写一个永不结束的 ULEB128 后截断。
        # 先取得 CIE 字节，再手工拼接畸形 FDE。
        good = FrameBuilder()
        good.add_cie(standard_cie())
        cie = good.build()
        ptr_field = len(cie) + 4
        payload = (struct.pack("<III", ptr_field, BASE, 0x100)
                   + bytes([0x80, 0x80]))  # 截断 ULEB
        bad = cie + struct.pack("<I", len(payload)) + payload
        with self.assertRaises(FrameError) as cm:
            parse_section(bad)
        self.assertIn("ULEB128", cm.exception.message)
        self.assertEqual(cm.exception.raw_offset,
                         len(cie) + 4 + 4 + 4 + 4)

    def test_truncated_sleb(self):
        # def_cfa_sf 的 SLEB 操作数被截断
        bad_insn = bytes([0x12, 7, 0x80, 0x80])  # reg=7，SLEB 不结束
        b = FrameBuilder()
        b.add_cie(bad_insn)
        raw = b.build()
        with self.assertRaises(FrameError) as cm:
            parse_section(raw)
        self.assertIn("SLEB128", cm.exception.message)

    def test_unsupported_version(self):
        b = FrameBuilder()
        body = (struct.pack("<I", 0) + bytes([3]) + b"zR\x00" + uleb(1)
                + sleb(-8) + uleb(16) + uleb(1) + bytes([0x03]))
        raw = struct.pack("<I", len(body)) + body
        with self.assertRaises(FrameError) as cm:
            parse_section(raw)
        self.assertIn("v1", cm.exception.message)

    def test_unsupported_fde_encoding(self):
        b = FrameBuilder()
        b.add_cie(standard_cie(), fde_enc=0x1B)  # pcrel sdata4
        with self.assertRaises(FrameError) as cm:
            parse_section(b.build())
        self.assertIn("udata4", cm.exception.message)

    def test_caller_pc_unrecoverable(self):
        # CIE 不给 RA 规则；FDE 显式 undefined RA
        cie_insns = bytes([0x0C]) + uleb(7) + uleb(8)  # def_cfa rbp,8
        fde_insns = bytes([0x07]) + uleb(16)           # undefined RA
        b = FrameBuilder()
        ci = b.add_cie(cie_insns)
        b.add_fde(ci, BASE, 0x10, fde_insns)
        data = b.build()
        with self.assertRaises(FrameError) as cm:
            unwind(data, BASE + 1, {7: 1000})
        self.assertIn("调用者 PC", cm.exception.message)
        cies, fdes = parse_section(data)
        # undefined 指令在 FDE 指令区起始
        fde = fdes[0]
        self.assertEqual(cm.exception.raw_offset, fde.end - 2)

    def test_memory_read_out_of_bounds(self):
        data = standard_frame(b"")
        with self.assertRaises(FrameError) as cm:
            unwind(data, BASE + 1, {7: CFA_BASE - 8},
                   mem_base=CFA_BASE, mem=b"\x00" * 8)
        self.assertIn("越界", cm.exception.message)

    def test_no_memory_provided(self):
        data = standard_frame(b"")
        with self.assertRaises(FrameError) as cm:
            unwind(data, BASE + 1, {7: CFA_BASE - 8})
        self.assertIn("内存", cm.exception.message)

    def test_supported_rule_kinds(self):
        # same_value RBX / register R12<-RBP / offset_extended_sf / def_cfa_register
        fde_insns = (
            bytes([0x41])                          # loc 1
            + bytes([0x08]) + uleb(3)              # same_value RBX
            + bytes([0x09]) + uleb(12) + uleb(6)   # register R12 <- RBP
            + bytes([0x0D]) + uleb(6)              # def_cfa_register RBP
            + bytes([0x11]) + uleb(13) + sleb(3)   # offset_extended_sf R13 => -24
        )
        data = standard_frame(fde_insns)
        cies, fdes = parse_section(data)
        st = reduce_to_pc(cies[fdes[0].cie_offset], fdes[0], BASE + 1)
        self.assertEqual(st.rules[3], ("s",))
        self.assertEqual(st.rules[12], ("r", 6))
        self.assertEqual(st.rules[13], ("o", -24))
        self.assertEqual(st.cfa[1], 6)

        cfa = CFA_BASE
        mem = mem_image(cfa - 0x40, {cfa - 8: 0xAA, cfa - 24: 0xBB})
        r = unwind(data, BASE + 1, {7: cfa - 8, 6: cfa - 8, 3: 0x99},
                   mem_base=cfa - 0x40, mem=mem)
        by = {g["reg"]: g for g in r["registers"]}
        self.assertEqual(by[3]["value"], 0x99)
        self.assertEqual(by[12]["value"], cfa - 8)
        self.assertEqual(by[13]["value"], 0xBB)
        # 此时 CFA 基址寄存器已换为 RBP(6)
        self.assertEqual(r["cfa"]["rule"]["register"], 6)

    def test_instruction_runs_past_entry_boundary(self):
        # FDE 增强数据声明 1 字节，随后一条操作数截断的 def_cfa_offset
        good = FrameBuilder()
        good.add_cie(standard_cie())
        raw0 = good.build()
        cie_len = struct.unpack_from("<I", raw0, 0)[0] + 4
        cie_part = raw0[:cie_len]
        ptr_field = len(cie_part) + 4
        payload = (struct.pack("<III", ptr_field, BASE, 0x10)
                   + uleb(1) + b"X" + bytes([0x0E, 0x80]))
        raw = cie_part + struct.pack("<I", len(payload)) + payload
        with self.assertRaises(FrameError) as cm:
            parse_section(raw)
        self.assertIsNotNone(cm.exception.raw_offset)


class ApiTests(unittest.TestCase):
    def _payload(self, data: bytes, pc=hex(BASE + 0x10), regs=None, mem=None):
        p = {"eh_frame": base64.b64encode(data).decode(), "pc": pc,
             "registers": regs or {}}
        if mem is not None:
            p["memory"] = mem
        return p

    def test_api_hit(self):
        data = standard_frame(b"")
        cfa = CFA_BASE
        ret = 0x400500
        m = mem_image(cfa - 0x40, {cfa - 8: ret})
        payload = self._payload(data, regs={"RSP": hex(cfa - 8)},
                                mem={"base": hex(cfa - 0x40),
                                     "data": base64.b64encode(m).decode()})
        code, r = handle_unwind(payload)
        self.assertEqual(code, 200)
        self.assertTrue(r["hit"])
        self.assertEqual(r["return_address"]["value"], ret)

    def test_api_miss(self):
        code, r = handle_unwind(self._payload(standard_frame(b""),
                                              pc=hex(BASE + 0x999)))
        self.assertEqual(code, 200)
        self.assertFalse(r["hit"])
        self.assertNotIn("registers", r)

    def test_api_bad_base64(self):
        code, r = handle_unwind({"eh_frame": "@@not b64@@", "pc": "0x1"})
        self.assertEqual(code, 400)
        self.assertIn("Base64", r["error"])

    def test_api_size_limit(self):
        b = FrameBuilder()
        b.add_cie(standard_cie())
        data = b.build()
        data = data + b"\x00" * (192 * 1024 + 1 - len(data))
        code, r = handle_unwind(self._payload(data, pc="0x1"))
        self.assertEqual(code, 413)
        self.assertIn("192 KiB", r["error"])

    def test_api_dangling_offset_reported(self):
        data = bytearray(standard_frame(b""))
        cies, fdes = parse_section(bytes(data))
        struct.pack_into("<I", data, fdes[0].cie_ptr_field, 7)
        code, r = handle_unwind(self._payload(bytes(data)))
        self.assertEqual(code, 422)
        self.assertEqual(r["raw_offset"], fdes[0].cie_ptr_field)
        self.assertNotIn("registers", r)

    def test_api_truncated_uleb(self):
        good = FrameBuilder()
        good.add_cie(standard_cie())
        cie = good.build()
        ptr_field = len(cie) + 4
        payload = struct.pack("<III", ptr_field, BASE, 0x10) + bytes([0x80])
        raw = cie + struct.pack("<I", len(payload)) + payload
        code, r = handle_unwind(self._payload(raw))
        self.assertEqual(code, 422)
        self.assertIsNotNone(r["raw_offset"])
        self.assertIn("ULEB128", r["error"])


class HttpSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def post(self, payload):
        c = HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("POST", "/api/unwind", body=__import__("json").dumps(payload))
        resp = c.getresponse()
        return resp.status, resp.read()

    def test_health_page_and_smoke(self):
        c = HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/healthz")
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertIn(b"ok", r.read())

        c.request("GET", "/")
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertIn(b"eh_frame", r.read())

        # 有效输入
        import json, base64 as b64
        data = standard_frame(b"")
        cfa = CFA_BASE
        m = mem_image(cfa - 0x40, {cfa - 8: 0x400500})
        ok = {"eh_frame": b64.b64encode(data).decode(),
              "pc": hex(BASE + 5), "registers": {"RSP": hex(cfa - 8)},
              "memory": {"base": hex(cfa - 0x40),
                         "data": b64.b64encode(m).decode()}}
        st, body = self.post(ok)
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["hit"])

        # 失败输入（截断 ULEB）
        good = FrameBuilder()
        good.add_cie(standard_cie())
        cie = good.build()
        ptr_field = len(cie) + 4
        payload = struct.pack("<III", ptr_field, BASE, 0x10) + bytes([0x80])
        bad = cie + struct.pack("<I", len(payload)) + payload
        st, body = self.post({"eh_frame": b64.b64encode(bad).decode(),
                              "pc": hex(BASE)})
        self.assertEqual(st, 422)
        self.assertIsNotNone(json.loads(body)["raw_offset"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class EndToEndTests(unittest.TestCase):
    """仿 x86-64 gcc 输出：多个 FDE 共享 CIE，序言 push rbp/建栈帧，
    尾声 remember+restore_state 回退，跨函数解栈取值。"""

    def build_realistic(self):
        b = FrameBuilder()
        # CIE: def_cfa RSP(7),8 ; RA=[CFA-8]
        cie = b.add_cie(bytes([0x0C, 7, 8, 0x90, 0x01]))

        # caller: 0x4000..0x4100，仅标准规则
        # callee: 0x5000..0x5100：
        #   push rbp        -> CFA=RSP+16, RBP=[CFA-16]
        #   sub rsp,0x20    -> CFA=RSP+48（函数体状态）
        #   尾声 remember / 改写为 RSP+16 / restore_state 回退到 RSP+48
        callee = bytes([
            0x41,                                # loc 1 (push rbp)
            0x0E]) + uleb(16) + bytes([          # def_cfa_offset 16
            0x86]) + uleb(2) + bytes([           # offset RBP(6), factor2 => -16
            0x43,                                # advance loc 3 -> loc4
            0x0E]) + uleb(48) + bytes([          # sub rsp,0x20 -> CFA=RSP+48
            0x02, 0xDC,                          # advance_loc1 0xDC -> loc 0xE0
            0x0A,                                # remember_state
            0x42,                                # advance 2 -> loc 0xE2
            0x0E]) + uleb(16) + bytes([          # 尾声 add rsp,0x20: RSP+16
            0x48,                                # advance 8 -> loc 0xEA
            0x0B,                                # restore_state -> RSP+48
        ])
        b.add_fde(cie, 0x4000, 0x100, b"")
        b.add_fde(cie, 0x5000, 0x100, callee)
        return b.build()

    def test_inner_frame_unwind(self):
        data = self.build_realistic()
        cies, fdes = parse_section(data)
        self.assertEqual(len(fdes), 2)
        self.assertEqual(fdes[0].cie_offset, fdes[1].cie_offset)

        # 崩溃点位于 callee 深处（loc 0x10），CFA=RSP+48
        cfa = 0x7F0000001000
        saved_ra = 0x4050
        saved_bp = 0x7F0000001080
        mem = mem_image(cfa - 0x60, {cfa - 8: saved_ra, cfa - 16: saved_bp})
        r = unwind(data, 0x5000 + 0x10, {7: cfa - 48, 6: cfa - 16},
                   mem_base=cfa - 0x60, mem=mem)
        self.assertTrue(r["hit"])
        self.assertEqual(r["fde"]["index"], 1)
        self.assertEqual(r["cfa"]["value"], cfa)
        self.assertEqual(r["cfa"]["rule"]["text"], "RSP+48")
        self.assertEqual(r["return_address"]["value"], saved_ra)
        by = {g["reg"]: g for g in r["registers"]}
        self.assertEqual(by[6]["value"], saved_bp)
        self.assertEqual(by[6]["rule"]["kind"], "offset")

    def test_epilogue_rolls_back(self):
        data = self.build_realistic()
        cies, fdes = parse_section(data)
        cie = cies[fdes[1].cie_offset]
        # 尾声改写后、restore 之前（loc 0xE4）：RSP+16
        st = reduce_to_pc(cie, fdes[1], 0x5000 + 0xE4)
        self.assertEqual(st.cfa, ("reg", 7, 16))
        # restore 之后（loc 0xEA 起）：回退到保存时的 RSP+48
        st = reduce_to_pc(cie, fdes[1], 0x5000 + 0xEA)
        self.assertEqual(st.cfa, ("reg", 7, 48))
        # RBP 的 offset 规则属于保存状态，同样保留
        self.assertEqual(st.rules[6], ("o", -16))

    def test_other_fde_still_hits(self):
        data = self.build_realistic()
        cfa = 0x7F0000002000
        mem = mem_image(cfa - 0x40, {cfa - 8: 0x3000})
        r = unwind(data, 0x4080, {7: cfa - 8},
                   mem_base=cfa - 0x40, mem=mem)
        self.assertTrue(r["hit"])
        self.assertEqual(r["fde"]["index"], 0)
        self.assertEqual(r["return_address"]["value"], 0x3000)
