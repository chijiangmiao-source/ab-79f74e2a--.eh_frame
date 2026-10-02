"""手工构造 ``.eh_frame`` 节字节，供测试使用。"""

from __future__ import annotations

import struct


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = n & 0x7F
        n >>= 7
        sign = b & 0x40
        if (n == 0 and not sign) or (n == -1 and sign):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


class FrameBuilder:
    """按 (length, id, ...) 顺序拼装，最后回填 FDE 的绝对 CIE 指针。"""

    def __init__(self):
        self.cies: list[bytes] = []
        self.fdes: list[tuple[int, int, int, bytes]] = []
        self.cie_offsets: dict[int, int] = {}
        self.fde_offsets: list[int] = {}

    def add_cie(self, insns: bytes, aug: bytes = b"zR",
                fde_enc: int = 0x03) -> int:
        # version1 / augmentation / code_align=1 / data_align=-8 / RA=16
        body = bytes([1]) + aug + b"\x00" + uleb(1) + sleb(-8) + bytes([16])
        if aug.startswith(b"z"):
            augdata = bytes([fde_enc]) if b"R" in aug else b""
            body += uleb(len(augdata)) + augdata
        body += insns
        idx = len(self.cies)
        self.cies.append(struct.pack("<I", 0) + body)
        return idx

    def add_fde(self, cie_idx: int, init_loc: int, addr_range: int,
                insns: bytes) -> int:
        idx = len(self.fdes)
        # ptr 先放占位 0；payload = ptr(4) + loc(4) + range(4) + auglen(0) + insns
        payload = (struct.pack("<I", 0) + struct.pack("<II", init_loc, addr_range)
                   + uleb(0) + insns)
        self.fdes.append((cie_idx, init_loc, addr_range, payload))
        return idx

    def build(self) -> bytes:
        # 先计算各条目起始偏移
        off = 0
        cie_starts: dict[int, int] = {}
        for i, payload in enumerate(self.cies):
            cie_starts[i] = off
            off += 4 + len(payload)
        fde_starts: list[int] = []
        fde_ptrs: list[int] = []
        for cie_idx, _loc, _rng, payload in self.fdes:
            fde_starts.append(off)
            fde_ptrs.append(off + 4)  # 长度字段之后即指针字段
            off += 4 + len(payload)

        out = bytearray()
        for i, payload in enumerate(self.cies):
            out += struct.pack("<I", len(payload))
            out += payload
        for i, (cie_idx, _loc, _rng, payload) in enumerate(self.fdes):
            ptr_field = fde_ptrs[i]
            ptr_value = ptr_field - cie_starts[cie_idx]
            fixed = payload[:0] + struct.pack("<I", ptr_value) + payload[4:]
            out += struct.pack("<I", len(fixed))
            out += fixed
        self.fde_offsets = fde_starts
        self.cie_offsets = cie_starts
        return bytes(out)


def standard_cie() -> bytes:
    # def_cfa RBP(7),8 ; offset RA(16), factored 1 => [CFA-8]
    return bytes([0x0C, 7, 8, 0x90, 0x01])
