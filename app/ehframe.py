"""x86-64 ``.eh_frame`` 解析与按地址规则归约（CIE v1，FDE 指针编码 udata4）。

只依赖 Python 标准库。所有错误都通过 :class:`FrameError` 抛出，并携带
**首个原始字节偏移**（相对于用户粘贴的整段 section 数据）。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

# .eh_frame 里的 CIE 标记（32 位 DWARF 格式下 FDE 头部该字段为 0xffffffff）
CIE_ID32 = 0
FDE_TAG32 = 0xFFFFFFFF
DWARF64_MARK = 0xFFFFFFFF

# x86-64: 代码对齐因子 1，数据对齐因子 -8，返回地址寄存器编号 16
X64_CODE_ALIGNMENT = 1
X64_DATA_ALIGNMENT = -8
X64_RA_REG = 16
MAX_REG = 16

REG_NAMES = [
    "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RA",
]

# FDE 指针编码：绝对、无间接、4 字节无符号（DW_EH_PE_udata4）
ABS_UDATA4 = 0x03

# CFI 操作码
CFA_nop = 0x00
CFA_set_loc = 0x01
CFA_advance_loc1 = 0x02
CFA_advance_loc2 = 0x03
CFA_advance_loc4 = 0x04
CFA_offset_extended = 0x05
CFA_restore_extended = 0x06
CFA_undefined = 0x07
CFA_same_value = 0x08
CFA_register = 0x09
CFA_remember_state = 0x0A
CFA_restore_state = 0x0B
CFA_def_cfa = 0x0C
CFA_def_cfa_register = 0x0D
CFA_def_cfa_offset = 0x0E
CFA_def_cfa_expression = 0x0F
CFA_expression = 0x10
CFA_offset_extended_sf = 0x11
CFA_def_cfa_sf = 0x12
CFA_def_cfa_offset_sf = 0x13
CFA_val_offset = 0x14
CFA_val_offset_sf = 0x15
CFA_val_expression = 0x16

MASK64 = (1 << 64) - 1


class FrameError(Exception):
    """携带首个原始偏移的处理错误。"""

    def __init__(self, message: str, raw_offset: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.raw_offset = raw_offset


class InputError(Exception):
    """调用方提供的寄存器/内存等求值输入不完整。"""


@dataclass
class Instr:
    op: int
    args: tuple
    raw_offset: int  # 操作码在原始 section 中的偏移


@dataclass
class CIE:
    offset: int
    end: int
    augmentation: str
    code_alignment: int
    data_alignment: int
    ra_register: int
    initial_instructions: list[Instr] = field(default_factory=list)


@dataclass
class FDE:
    index: int
    offset: int
    end: int
    cie_ptr_field: int
    cie_ptr_value: int
    cie_mode: str = "relative"   # relative（.eh_frame 反向偏移）/ absolute
    cie_offset: int = -1
    initial_location: int = 0
    address_range: int = 0
    instructions: list[Instr] = field(default_factory=list)

    @property
    def range_end(self) -> int:
        return (self.initial_location + self.address_range) & MASK64


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _need(self, n: int, start: int, what: str) -> None:
        if start < 0 or start + n > len(self.data):
            raise FrameError(f"{what}截断：需要 {n} 字节但越过节尾", start)

    def u8(self, what="字节") -> int:
        start = self.pos
        self._need(1, start, what)
        v = self.data[start]
        self.pos = start + 1
        return v

    def u16(self, what="16 位立即数") -> int:
        start = self.pos
        self._need(2, start, what)
        v = struct.unpack_from("<H", self.data, start)[0]
        self.pos = start + 2
        return v

    def u32(self, what="32 位立即数") -> int:
        start = self.pos
        self._need(4, start, what)
        v = struct.unpack_from("<I", self.data, start)[0]
        self.pos = start + 4
        return v

    def fixed(self, n: int, what="地址") -> int:
        start = self.pos
        self._need(n, start, what)
        v = int.from_bytes(self.data[start:start + n], "little")
        self.pos = start + n
        return v

    def uleb(self, what="ULEB128") -> int:
        start = self.pos
        result = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise FrameError(f"截断的 ULEB128（{what}）：末字节缺失", start)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7
            if shift > 63:
                raise FrameError(f"ULEB128（{what}）超出 64 位", start)

    def sleb(self, what="SLEB128") -> int:
        start = self.pos
        result = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise FrameError(f"截断的 SLEB128（{what}）：末字节缺失", start)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if b & 0x40:
                    result |= -(1 << shift)
                return result
            if shift > 70:
                raise FrameError(f"{what}超出 64 位", start)

    def cstring(self) -> bytes:
        start = self.pos
        end = self.data.find(b"\x00", start)
        if end == -1 or end >= len(self.data):
            raise FrameError("增强字符串缺少 NUL 终止", start)
        raw = self.data[start:end]
        self.pos = end + 1
        return raw


def _decode_instructions(data: bytes, start: int, end: int,
                         code_align: int, data_align: int) -> list[Instr]:
    """解码 [start, end) 区间内的 CFI 指令；不支持的操作码立即报错。"""
    r = _Reader(data)
    r.pos = start
    out: list[Instr] = []

    def check_reg(reg: int, off: int) -> None:
        if reg > MAX_REG:
            raise FrameError(f"寄存器编号 {reg} 超出 x86-64 范围(0..16)", off)

    while r.pos < end:
        op_off = r.pos
        op = r.u8("操作码")

        if op == CFA_nop:
            out.append(Instr(op, (), op_off))
        elif op == CFA_set_loc:
            addr = r.fixed(4, "set_loc 绝对地址")
            out.append(Instr(op, (addr,), op_off))
        elif op == CFA_advance_loc1:
            out.append(Instr(op, (r.u8("advance_loc1") * code_align,), op_off))
        elif op == CFA_advance_loc2:
            out.append(Instr(op, (r.u16("advance_loc2") * code_align,), op_off))
        elif op == CFA_advance_loc4:
            out.append(Instr(op, (r.u32("advance_loc4") * code_align,), op_off))
        elif op & 0xC0 == 0x40:  # DW_CFA_advance_loc
            out.append(Instr(op, ((op & 0x3F) * code_align,), op_off))
        elif op & 0xC0 == 0x80:  # DW_CFA_offset
            reg = op & 0x3F
            check_reg(reg, op_off)
            factored = r.uleb("offset 操作数")
            out.append(Instr(op, (reg, factored * data_align), op_off))
        elif op & 0xC0 == 0xC0:  # DW_CFA_restore
            reg = op & 0x3F
            check_reg(reg, op_off)
            out.append(Instr(op, (reg,), op_off))
        elif op == CFA_offset_extended:
            reg_off = r.pos
            reg = r.uleb("offset_extended 寄存器")
            check_reg(reg, reg_off)
            factored = r.uleb("offset_extended 偏移")
            out.append(Instr(op, (reg, factored * data_align), op_off))
        elif op == CFA_offset_extended_sf:
            reg_off = r.pos
            reg = r.uleb("offset_extended_sf 寄存器")
            check_reg(reg, reg_off)
            factored = r.sleb("offset_extended_sf 偏移")
            out.append(Instr(op, (reg, factored * data_align), op_off))
        elif op == CFA_restore_extended:
            reg_off = r.pos
            reg = r.uleb("restore_extended 寄存器")
            check_reg(reg, reg_off)
            out.append(Instr(op, (reg,), op_off))
        elif op in (CFA_undefined, CFA_same_value, CFA_def_cfa_register,
                    CFA_def_cfa_offset, CFA_def_cfa_offset_sf):
            arg_off = r.pos
            if op == CFA_def_cfa_offset_sf:
                val = r.sleb("def_cfa_offset_sf 偏移") * data_align
            elif op == CFA_def_cfa_offset:
                val = r.uleb("def_cfa_offset 偏移")
            else:
                val = r.uleb("寄存器编号")
                check_reg(val, arg_off)
            out.append(Instr(op, (val,), op_off))
        elif op in (CFA_register, CFA_def_cfa, CFA_def_cfa_sf):
            a_off = r.pos
            a = r.uleb("第一操作数")
            b_off = r.pos
            if op == CFA_def_cfa_sf:
                b = r.sleb("def_cfa_sf 偏移") * data_align
            else:
                b = r.uleb("第二操作数")
            if op == CFA_register:
                check_reg(a, a_off)
                check_reg(b, b_off)
            else:
                check_reg(a, a_off)
            out.append(Instr(op, (a, b), op_off))
        elif op in (CFA_remember_state, CFA_restore_state):
            out.append(Instr(op, (), op_off))
        elif op in (CFA_def_cfa_expression, CFA_expression,
                    CFA_val_offset, CFA_val_offset_sf, CFA_val_expression):
            raise FrameError(f"不支持的 CFI 操作码 0x{op:02x}（表达式/val 规则）",
                             op_off)
        else:
            raise FrameError(f"不支持或保留的 CFI 操作码 0x{op:02x}", op_off)

        if r.pos > end:
            raise FrameError("指令越过该 CIE/FDE 的长度边界", op_off)

    return out


def parse_section(data: bytes) -> tuple[dict[int, CIE], list[FDE]]:
    """遍历整个 ``.eh_frame`` section，返回 CIE 表与 FDE 列表。"""
    cies: dict[int, CIE] = {}
    fdes: list[FDE] = []
    r = _Reader(data)

    while r.pos < len(data):
        entry_start = r.pos
        length = r.u32("条目长度")
        if length == 0:
            # 零长度终止项；节中其后不应再有数据
            if r.pos != len(data):
                raise FrameError("零长度终止项之后仍有数据", r.pos)
            break
        if length == DWARF64_MARK:
            raise FrameError("不支持 64 位 DWARF 格式的 .eh_frame", entry_start)
        payload_start = r.pos
        end = payload_start + length
        if end > len(data):
            raise FrameError(
                f"条目长度 {length} 越过节尾（节长 {len(data)}）", entry_start)

        ident = r.u32("CIE 指针/标记")
        if ident == CIE_ID32:
            version_off = r.pos
            version = r.u8("CIE 版本")
            if version != 1:
                raise FrameError(f"仅支持 CIE v1，遇到版本 {version}", version_off)
            aug_off = r.pos
            aug_raw = r.cstring()
            try:
                aug = aug_raw.decode("ascii")
            except UnicodeDecodeError:
                raise FrameError("增强字符串非 ASCII", aug_off)

            ca_off = r.pos
            code_align = r.uleb("代码对齐因子")
            da_off = r.pos
            data_align = r.sleb("数据对齐因子")
            ra_off = r.pos
            ra_reg = r.u8("返回地址寄存器（CIE v1 为单字节）")
            if code_align != X64_CODE_ALIGNMENT:
                raise FrameError(
                    f"仅处理 x86-64：代码对齐因子应为 1，实为 {code_align}",
                    ca_off)
            if data_align != X64_DATA_ALIGNMENT:
                raise FrameError(
                    f"仅处理 x86-64：数据对齐因子应为 -8，实为 {data_align}",
                    da_off)
            if ra_reg != X64_RA_REG:
                raise FrameError(
                    f"仅处理 x86-64：返回地址寄存器应为 16，实为 {ra_reg}",
                    ra_off)
            if not aug.startswith("z"):
                raise FrameError("仅处理带 'z' 增强的 .eh_frame CIE", aug_off)

            aug_data_end = r.pos
            if "z" in aug:
                aug_len_off = r.pos
                aug_len = r.uleb("增强数据长度")
                aug_data_start = r.pos
                aug_data_end = aug_data_start + aug_len
                if aug_data_end > end:
                    raise FrameError("增强数据越过条目边界", aug_len_off)
                fde_enc = None
                for ch in aug[1:]:
                    if ch == "L":
                        r.u8("LSDA 编码")
                    elif ch == "R":
                        enc_off = r.pos
                        fde_enc = r.u8("FDE 指针编码")
                        if fde_enc != ABS_UDATA4:
                            raise FrameError(
                                "仅支持绝对 32 位 FDE 指针编码 udata4(0x03)，"
                                f"遇到 0x{fde_enc:02x}", enc_off)
                    elif ch == "P":
                        p_off = r.pos
                        p_enc = r.u8("personality 编码")
                        if p_enc != ABS_UDATA4:
                            raise FrameError(
                                "仅支持绝对 32 位 personality 指针 udata4(0x03)，"
                                f"遇到 0x{p_enc:02x}", p_off)
                        r.fixed(4, "personality 指针")
                    elif ch == "S":
                        pass
                    else:
                        raise FrameError(f"不支持的增强字符 {ch!r}", r.pos)
                if fde_enc is None:
                    raise FrameError("CIE 增强缺少 'R'（FDE 指针编码）", aug_off)
                if r.pos != aug_data_end:
                    raise FrameError(
                        "增强数据声明长度与实际解析长度不一致", aug_data_start)

            insns = _decode_instructions(data, aug_data_end, end,
                                         code_align, data_align)
            cie = CIE(entry_start, end, aug, code_align, data_align,
                      ra_reg, insns)
            cies[entry_start] = cie
        elif ident == FDE_TAG32:
            # .debug_frame 风格：0xffffffff 标记 + 其后为 CIE 绝对偏移
            ptr_field = r.pos
            cie_ptr = r.u32("CIE 绝对偏移")
            cie_mode = "absolute"
            init_loc = r.fixed(4, "FDE 初始位置")
            addr_range = r.fixed(4, "FDE 地址范围")
            aug_off = r.pos
            aug_len = r.uleb("FDE 增强数据长度")
            aug_end = r.pos + aug_len
            if aug_end > end:
                raise FrameError("FDE 增强数据越过条目边界", aug_off)
            r.pos = aug_end  # LSDA 等增强数据整体跳过
            insns = _decode_instructions(data, aug_end, end, 1, -8)
            fde = FDE(len(fdes), entry_start, end, ptr_field, cie_ptr,
                      initial_location=init_loc, address_range=addr_range,
                      instructions=insns)
            fde.cie_mode = cie_mode
            fdes.append(fde)
        else:
            # 标准 .eh_frame FDE：该字段是相对自身的反向偏移，指向 CIE。
            # 不在这里限定取值，越界/指向非 CIE 的情况统一报“悬空 CIE 引用”。
            ptr_field = payload_start
            cie_ptr = ident
            init_loc = r.fixed(4, "FDE 初始位置")
            addr_range = r.fixed(4, "FDE 地址范围")
            aug_off = r.pos
            aug_len = r.uleb("FDE 增强数据长度")
            aug_end = r.pos + aug_len
            if aug_end > end:
                raise FrameError("FDE 增强数据越过条目边界", aug_off)
            r.pos = aug_end  # LSDA 等增强数据整体跳过
            insns = _decode_instructions(data, aug_end, end, 1, -8)
            fde = FDE(len(fdes), entry_start, end, ptr_field, cie_ptr,
                      initial_location=init_loc, address_range=addr_range,
                      instructions=insns)
            fde.cie_mode = "relative"
            fdes.append(fde)

        r.pos = end

    # 解析 CIE 指针：
    #   .eh_frame 标准：指针字段处绝对偏移 - 反向相对值 = CIE 起始偏移
    #   绝对形式(0xffffffff 标记)：字段值直接为 CIE 起始偏移
    for fde in fdes:
        if fde.cie_mode == "relative":
            target = fde.cie_ptr_field - fde.cie_ptr_value
        else:
            target = fde.cie_ptr_value
        if target not in cies:
            raise FrameError(
                f"悬空 CIE 引用：FDE@0x{fde.offset:x} 的 CIE 指针 "
                f"0x{fde.cie_ptr_value:08x} 未指向任何 CIE",
                fde.cie_ptr_field)
        fde.cie_offset = target

    return cies, fdes


# ---------------------------------------------------------------------------
# 规则归约
# ---------------------------------------------------------------------------

# 规则元组：
#   ("u",)               未定义
#   ("s",)               同值（规则恢复为被调用者保有的原值）
#   ("o", cfa_offset)    偏移：保存在 [CFA + offset]
#   ("r", reg)           寄存器：保存在另一个寄存器中
@dataclass
class _State:
    cfa: Optional[tuple] = None          # ("reg", regnum, offset)
    cfa_origin: Optional[int] = None
    rules: dict[int, tuple] = field(default_factory=dict)
    origins: dict[int, int] = field(default_factory=dict)
    stack: list[tuple] = field(default_factory=list)

    def clone(self) -> "_State":
        return _State(self.cfa, self.cfa_origin,
                      dict(self.rules), dict(self.origins),
                      [(c, o, dict(rs), dict(og))
                       for c, o, rs, og in self.stack])


def _apply(state: _State, ins: Instr, initial_rules: dict[int, tuple],
           initial_origins: dict[int, int], is_cie: bool) -> None:
    op = ins.op
    a = ins.args
    if op == CFA_nop:
        return
    if op in (CFA_advance_loc1, CFA_advance_loc2, CFA_advance_loc4) or \
            op & 0xC0 == 0x40:
        if is_cie:
            raise FrameError("CIE 初始指令中不允许地址推进", ins.raw_offset)
        return  # loc 由调用方处理
    if op == CFA_set_loc:
        if is_cie:
            raise FrameError("CIE 初始指令中不允许 set_loc", ins.raw_offset)
        return
    if op & 0xC0 == 0x80:  # offset
        reg, off = a
        state.rules[reg] = ("o", off)
        state.origins[reg] = ins.raw_offset
    elif op == CFA_offset_extended or op == CFA_offset_extended_sf:
        reg, off = a
        state.rules[reg] = ("o", off)
        state.origins[reg] = ins.raw_offset
    elif op & 0xC0 == 0xC0 or op == CFA_restore_extended:  # restore
        reg = a[0]
        if reg in initial_rules:
            state.rules[reg] = initial_rules[reg]
            state.origins[reg] = ins.raw_offset
        else:
            state.rules.pop(reg, None)
            state.origins[reg] = ins.raw_offset
    elif op == CFA_undefined:
        state.rules[a[0]] = ("u",)
        state.origins[a[0]] = ins.raw_offset
    elif op == CFA_same_value:
        state.rules[a[0]] = ("s",)
        state.origins[a[0]] = ins.raw_offset
    elif op == CFA_register:
        state.rules[a[0]] = ("r", a[1])
        state.origins[a[0]] = ins.raw_offset
    elif op == CFA_def_cfa or op == CFA_def_cfa_sf:
        state.cfa = ("reg", a[0], a[1])
        state.cfa_origin = ins.raw_offset
    elif op == CFA_def_cfa_register:
        if state.cfa is None:
            raise FrameError("def_cfa_register 之前未定义 CFA", ins.raw_offset)
        state.cfa = ("reg", a[0], state.cfa[2])
        state.cfa_origin = ins.raw_offset
    elif op in (CFA_def_cfa_offset, CFA_def_cfa_offset_sf):
        if state.cfa is None:
            raise FrameError("def_cfa_offset 之前未定义 CFA", ins.raw_offset)
        state.cfa = ("reg", state.cfa[1], a[0])
        state.cfa_origin = ins.raw_offset
    elif op == CFA_remember_state:
        state.stack.append((state.cfa, state.cfa_origin,
                            dict(state.rules), dict(state.origins)))
    elif op == CFA_restore_state:
        if not state.stack:
            raise FrameError("规则栈下溢：restore_state 没有对应的 remember_state",
                             ins.raw_offset)
        cfa, cfa_origin, rules, origins = state.stack.pop()
        state.cfa, state.cfa_origin = cfa, cfa_origin
        state.rules, state.origins = rules, origins
    else:
        raise FrameError(f"不支持的 CFI 操作码 0x{op:02x}", ins.raw_offset)


def _initial_state(cie: CIE) -> tuple[_State, dict, dict]:
    """应用 CIE 初始指令，返回工作状态与初始规则的独立快照。"""
    state = _State()
    for ins in cie.initial_instructions:
        _apply(state, ins, {}, {}, is_cie=True)
    return state, dict(state.rules), dict(state.origins)


def reduce_to_pc(cie: CIE, fde: FDE, pc: int) -> _State:
    """以 CIE 初始规则为底，按 FDE 指令逐地址归约到 ``pc`` 处生效的规则。"""
    state, initial_rules, initial_origins = _initial_state(cie)

    target = pc - fde.initial_location
    loc = 0
    for ins in fde.instructions:
        op = ins.op
        if op == CFA_set_loc:
            new_loc = ins.args[0] - fde.initial_location
            if new_loc > target:
                break
            loc = new_loc
            continue
        delta = None
        if op & 0xC0 == 0x40:
            delta = ins.args[0]
        elif op in (CFA_advance_loc1, CFA_advance_loc2, CFA_advance_loc4):
            delta = ins.args[0]
        if delta is not None:
            if loc + delta > target:
                break
            loc += delta
            continue
        _apply(state, ins, initial_rules, initial_origins, is_cie=False)
    return state


# ---------------------------------------------------------------------------
# 取值
# ---------------------------------------------------------------------------

def _rule_text(reg: int, rule: tuple) -> str:
    kind = rule[0]
    if kind == "u":
        return "未定义 (undefined)"
    if kind == "s":
        return f"同值 ({REG_NAMES[reg]})"
    if kind == "o":
        off = rule[1]
        sign = "+" if off >= 0 else "-"
        return f"[CFA{sign}{abs(off)}]"
    if kind == "r":
        return f"寄存器 {REG_NAMES[rule[1]]}"
    return "未知规则"


def _rule_json(reg: int, rule: Optional[tuple]) -> Optional[dict]:
    if rule is None:
        return None
    kind = rule[0]
    return {
        "kind": {"u": "undefined", "s": "same_value",
                 "o": "offset", "r": "register"}[kind],
        "text": _rule_text(reg, rule),
        "offset": rule[1] if kind == "o" else None,
        "register": rule[1] if kind == "r" else None,
    }


def unwind(data: bytes, pc: int, regs: dict[int, int],
           mem_base: Optional[int] = None,
           mem: Optional[bytes] = None) -> dict:
    """完整入口：解析 → 命中判定 → 归约 → 取值。

    任何错误都抛出 :class:`FrameError`（带 raw_offset）或
    :class:`InputError`，绝不返回部分寄存器结果。
    """
    cies, fdes = parse_section(data)

    fde_summary = [{
        "index": f.index,
        "raw_offset": f.offset,
        "initial_location": f.initial_location,
        "address_range": f.address_range,
        "range_end": f.range_end,
    } for f in fdes]

    hit: Optional[FDE] = None
    for f in fdes:
        end = f.initial_location + f.address_range  # 不回绕：解析自两个 u32
        if f.initial_location <= pc < end:
            hit = f
            break

    if hit is None:
        # 明确未命中；不携带任何上次成功的寄存器结论
        return {"hit": False, "pc": pc, "fdes": fde_summary,
                "message": "PC 未落入任何 FDE 的地址范围"}

    cie = cies[hit.cie_offset]
    state = reduce_to_pc(cie, hit, pc)

    if state.cfa is None:
        raise FrameError("归约结束时 CFA 仍未定义", state.cfa_origin)

    cfa_reg = state.cfa[1]
    cfa_off = state.cfa[2]
    if cfa_reg not in regs:
        raise InputError(f"计算 CFA 需要寄存器 {REG_NAMES[cfa_reg]} 的当前值")
    cfa_value = (regs[cfa_reg] + cfa_off) & MASK64

    def read_mem64(addr: int, origin: int, what: str) -> int:
        if mem is None or mem_base is None:
            raise FrameError(f"{what}需要在地址 0x{addr:x} 读取 8 字节内存，"
                             "但未提供覆盖该地址的内存转储", origin)
        idx = addr - mem_base
        if idx < 0 or idx + 8 > len(mem):
            raise FrameError(
                f"内存读取越界：地址 0x{addr:x} 不在内存转储区间 "
                f"[0x{mem_base:x}, 0x{mem_base + len(mem):x}) 内", origin)
        return int.from_bytes(mem[idx:idx + 8], "little")

    # 先在临时结构中取全部值，任何一个失败都不返回部分结果
    values: dict[int, Optional[int]] = {}
    for reg in range(MAX_REG + 1):
        rule = state.rules.get(reg)
        if rule is None:
            # x86-64 CIE 通常覆盖 RA；其余未提及者按未定义展示
            rule = ("u",)
        kind = rule[0]
        if kind == "u":
            values[reg] = None
        elif kind == "s":
            if reg not in regs:
                raise InputError(f"寄存器 {REG_NAMES[reg]} 规则为同值，"
                                 "但未提供其当前值")
            values[reg] = regs[reg] & MASK64
        elif kind == "r":
            src = rule[1]
            if src not in regs:
                raise InputError(f"寄存器 {REG_NAMES[reg]} 规则要求从 "
                                 f"{REG_NAMES[src]} 取值，但未提供该寄存器")
            values[reg] = regs[src] & MASK64
        elif kind == "o":
            addr = (cfa_value + rule[1]) & MASK64
            values[reg] = read_mem64(
                addr, state.origins.get(reg, hit.offset),
                f"寄存器 {REG_NAMES[reg]} ")

    # 调用者 PC = 返回地址寄存器(16)的恢复值
    ra_rule = state.rules.get(X64_RA_REG, ("u",))
    caller_pc = values[X64_RA_REG]
    if caller_pc is None:
        origin = state.origins.get(X64_RA_REG, hit.offset)
        raise FrameError("调用者 PC 不可恢复：返回地址寄存器(RA)规则为未定义",
                         origin)

    registers = []
    for reg in range(MAX_REG + 1):
        rule = state.rules.get(reg, ("u",))
        registers.append({
            "reg": reg,
            "name": REG_NAMES[reg],
            "rule": _rule_json(reg, rule),
            "rule_raw_offset": state.origins.get(reg),
            "value": values[reg],
            "recovered": values[reg] is not None and rule[0] in ("o", "r"),
        })

    return {
        "hit": True,
        "pc": pc,
        "fde": {
            "index": hit.index,
            "raw_offset": hit.offset,
            "end_offset": hit.end,
            "initial_location": hit.initial_location,
            "address_range": hit.address_range,
            "range_end": hit.initial_location + hit.address_range,
        },
        "cie": {
            "raw_offset": cie.offset,
            "version": 1,
            "augmentation": cie.augmentation,
            "code_alignment": cie.code_alignment,
            "data_alignment": cie.data_alignment,
            "return_address_register": cie.ra_register,
        },
        "cfa": {
            "rule": {"kind": "reg+offset",
                     "register": cfa_reg,
                     "register_name": REG_NAMES[cfa_reg],
                     "offset": cfa_off,
                     "text": f"{REG_NAMES[cfa_reg]}{'+' if cfa_off >= 0 else '-'}"
                             f"{abs(cfa_off)}"},
            "rule_raw_offset": state.cfa_origin,
            "value": cfa_value,
        },
        "return_address": {
            "rule": _rule_json(X64_RA_REG, ra_rule),
            "rule_raw_offset": state.origins.get(X64_RA_REG),
            "value": caller_pc,
        },
        "registers": registers,
        "fdes": fde_summary,
    }
