"""Minimal, strict x86-64 ``.eh_frame`` parser and CFA rule reductor.

Supported subset (exactly what the on-call tool accepts):

* 32-bit DWARF ``.eh_frame`` records, little-endian raw section bytes;
* CIE version 1 (``zR``/``zPR``-style augmentation length blocks are
  validated and skipped, augmentation contents are not interpreted);
* **absolute 32-bit** CIE pointers inside FDEs (byte offset of the
  target CIE's length word within the section);
* CFI instructions: ``DW_CFA_def_cfa`` / ``def_cfa_register`` /
  ``def_cfa_offset``, ``DW_CFA_offset`` (+high-bit form),
  ``DW_CFA_restore`` (+high-bit form), ``DW_CFA_same_value``,
  ``DW_CFA_undefined``, ``DW_CFA_register``, the ``DW_CFA_advance_loc``
  family (incl. ``set_loc`` with an absolute 32-bit address) and
  ``DW_CFA_remember_state`` / ``DW_CFA_restore_state``.

Every malformed input raises :class:`EHFrameError` anchored at the
*first* raw byte offset where the problem is detectable.  Analyses
either return a complete :class:`AnalysisResult` or raise — partial
register results are never produced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CIE_MARKER = 0  # the 4-byte id word of a CIE is exactly zero

MAX_SECTION_SIZE = 192 * 1024  # 192 KiB raw section limit


class Op:
    """DWARF call-frame instruction opcodes (DWARF 3 / .eh_frame v1)."""

    ADVANCE_LOC = 0x40          # high two bits 01; low 6 bits: delta
    OFFSET = 0x80               # high two bits 10; low 6 bits: register
    RESTORE = 0xC0              # high two bits 11; low 6 bits: register
    NOP = 0x00
    SET_LOC = 0x01
    ADVANCE_LOC1 = 0x02
    ADVANCE_LOC2 = 0x03
    ADVANCE_LOC4 = 0x04
    OFFSET_EXTENDED = 0x05
    RESTORE_EXTENDED = 0x06
    UNDEFINED = 0x07
    SAME_VALUE = 0x08
    REGISTER = 0x09
    REMEMBER_STATE = 0x0A
    RESTORE_STATE = 0x0B
    DEF_CFA = 0x0C
    DEF_CFA_REGISTER = 0x0D
    DEF_CFA_OFFSET = 0x0E


# x86-64 DWARF register numbers (DWARF is the ABI numbering here).
X86_64_REGS = {
    0: "rax", 1: "rdx", 2: "rcx", 3: "rbx", 4: "rsi", 5: "rdi",
    6: "rbp", 7: "rsp",
    8: "r8", 9: "r9", 10: "r10", 11: "r11", 12: "r12", 13: "r13",
    14: "r14", 15: "r15", 16: "rip",
}
for _i in range(17, 33):
    X86_64_REGS[_i] = "xmm%d" % (_i - 17)


def reg_name(num: int) -> str:
    return X86_64_REGS.get(num, "r%d" % num)


def parse_reg_number(text: str) -> int:
    """Resolve ``rsp``/``r16``/``7`` style register names to DWARF numbers."""
    t = text.strip().lower()
    if t == "rip":
        return 16
    for num, name in X86_64_REGS.items():
        if name == t:
            return num
    return int(t, 0)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EHFrameError(Exception):
    """Parsing or reduction failure anchored at a raw section offset."""

    def __init__(self, message: str, offset: int):
        super().__init__("%s（首个原始偏移 0x%x / %d）"
                         % (message, offset, offset))
        self.message = message
        self.offset = offset


# ---------------------------------------------------------------------------
# Bounds-checked reader
# ---------------------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def need(self, n: int) -> None:
        if self.pos + n > len(self.data) or self.pos < 0 or n < 0:
            raise EHFrameError(
                "读取越界：在偏移 %d 需要 %d 字节，节长度仅 %d"
                % (self.pos, n, len(self.data)),
                self.pos,
            )

    def u8(self) -> int:
        self.need(1)
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        self.need(2)
        v = int.from_bytes(self.data[self.pos:self.pos + 2], "little")
        self.pos += 2
        return v

    def u32(self) -> int:
        self.need(4)
        v = int.from_bytes(self.data[self.pos:self.pos + 4], "little")
        self.pos += 4
        return v

    def uleb128(self) -> int:
        start = self.pos
        result = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise EHFrameError(
                    "截断的 ULEB128：末字节缺失最高位清零标志", start)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
            shift += 7
            if shift > 63:
                raise EHFrameError("ULEB128 编码超长", start)

    def sleb128(self) -> int:
        start = self.pos
        result = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise EHFrameError(
                    "截断的 SLEB128：末字节缺失最高位清零标志", start)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if b & 0x40:
                    result -= 1 << shift
                return result
            if shift > 63:
                raise EHFrameError("SLEB128 编码超长", start)

    def cstr(self) -> bytes:
        start = self.pos
        end = self.data.find(b"\x00", start)
        if end < 0:
            raise EHFrameError("增强字符串缺少 NUL 终止符", start)
        s = self.data[start:end]
        self.pos = end + 1
        return s


# ---------------------------------------------------------------------------
# Decoded records
# ---------------------------------------------------------------------------


@dataclass
class CIE:
    offset: int                       # raw offset of the length field
    version: int
    augmentation: bytes
    code_align: int
    data_align: int
    ra_column: int
    initial_instructions: bytes
    initial_instructions_offset: int
    end_offset: int                   # first byte past the record
    marker_offset: int                # raw offset of the 0x00000000 word


@dataclass
class FDE:
    offset: int                       # raw offset of the length field
    pointer_field_offset: int        # raw offset of the CIE pointer word
    cie_pointer: int                  # absolute 32-bit pointer value
    cie: Optional[CIE]
    initial_location: int
    address_range: int
    instructions: bytes
    instructions_offset: int
    end_offset: int

    @property
    def end_address(self) -> int:
        return self.initial_location + self.address_range


@dataclass
class FrameSection:
    data: bytes
    cies: Dict[int, CIE] = field(default_factory=dict)
    fdes: List[FDE] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------


def parse_section(data) -> FrameSection:
    """Parse raw little-endian ``.eh_frame`` bytes into CIEs and FDEs."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise EHFrameError("节数据必须是原始字节", 0)
    data = bytes(data)
    if len(data) == 0:
        raise EHFrameError("节为空：至少需要一个 CIE", 0)
    if len(data) > MAX_SECTION_SIZE:
        raise EHFrameError(
            "节大小 %d 字节超过 192 KiB 上限" % len(data), 0)

    section = FrameSection(data=data)
    r = _Reader(data)

    # Pass 1: walk record headers, recording exact spans.
    headers: List[Tuple[int, int, int, int]] = []  # start,id_off,end,ptr
    while r.pos < len(data):
        record_start = r.pos
        length = r.u32()
        if length == 0:
            if r.pos != len(data):
                raise EHFrameError("零长度终止记录后仍有多余字节", record_start)
            break
        if length == 0xFFFFFFFF:
            raise EHFrameError(
                "不支持 DWARF64（64 位长度），仅支持 32 位 .eh_frame",
                record_start)
        body_end = r.pos + length
        if body_end > len(data):
            raise EHFrameError(
                "记录长度 %d 越过节边界（记录起始 0x%x）"
                % (length, record_start), record_start)
        id_off = r.pos
        pointer = r.u32()
        headers.append((record_start, id_off, body_end, pointer))
        r.pos = body_end

    # Pass 2: classify records and parse CIEs.
    #
    # Dialect note: the .eh_frame CIE marker word is 0, while this
    # analyzer also accepts *absolute* 32-bit FDE CIE pointers, so an
    # FDE referencing the CIE at section offset 0 carries the same word
    # 0.  We disambiguate structurally: the first record of a section
    # must be a CIE; any later zero word is a CIE only when its bytes
    # form a valid CIE header (version byte == 1, augmentation string
    # terminates, code/data alignment and the augmentation block stay
    # inside the record).  Otherwise it is an FDE whose absolute
    # pointer is 0 (resolved against the CIE at section offset 0).
    for idx, (start, id_off, body_end, pointer) in enumerate(headers):
        if pointer != CIE_MARKER:
            continue
        if idx == 0:
            cie = _parse_cie(data, start, id_off, body_end)  # hard error
        elif not _probe_cie_header(data, id_off, body_end):
            continue  # zero word: FDE -> CIE at absolute offset 0
        else:
            cie = _parse_cie(data, start, id_off, body_end)
        if cie.offset in section.cies:
            raise EHFrameError("CIE 偏移 0x%x 重复定义" % start, start)
        section.cies[cie.offset] = cie

    # Pass 3: parse FDEs and resolve absolute 32-bit CIE pointers.
    for start, id_off, body_end, pointer in headers:
        is_cie = (pointer == CIE_MARKER
                  and (start in section.cies))
        if is_cie:
            continue
        cie = section.cies.get(pointer)
        if cie is None:
            raise EHFrameError(
                "悬空 CIE 引用：FDE@0x%x 的绝对指针 0x%x 不指向任何 CIE"
                % (start, pointer), id_off)
        section.fdes.append(
            _parse_fde(data, start, id_off, body_end, pointer, cie))

    if not section.cies:
        raise EHFrameError("节中没有任何 CIE", 0)

    return section


def _probe_cie_header(data: bytes, id_off: int, body_end: int) -> bool:
    """Return True when a zero-id record parses as a CIE header."""
    try:
        r = _Reader(data)
        r.pos = id_off + 4
        if r.u8() != 1:
            return False
        r.cstr()
        if r.uleb128() <= 0:
            return False
        if r.sleb128() >= 0:
            return False
        r.u8()  # return-address column
        # If a 'z' augmentation is present we cannot fully validate its
        # block without CIE context; the NUL-terminated prefix check is
        # sufficient for disambiguation (FDE payloads virtually never
        # mimic a negative data-alignment SLEB at this position).
        return r.pos <= body_end
    except EHFrameError:
        return False


def _parse_cie(data: bytes, start: int, id_off: int, body_end: int) -> CIE:
    r = _Reader(data)
    r.pos = id_off + 4

    version_off = r.pos
    version = r.u8()
    if version != 1:
        raise EHFrameError(
            "仅支持 CIE version 1，遇到 version %d" % version, version_off)

    augmentation = r.cstr()
    code_align = r.uleb128()
    data_align = r.sleb128()
    if code_align <= 0:
        raise EHFrameError("CIE code alignment factor 必须为正数", r.pos)
    if data_align >= 0:
        raise EHFrameError(
            "x86-64 CIE data alignment factor 必须为负数（如 -8），得到 %d"
            % data_align, r.pos)

    # In .eh_frame the return-address column is always ULEB128
    # encoded (unlike .debug_frame v1, which uses a single byte).
    ra_off = r.pos
    ra_column = r.uleb128()
    if ra_column > 16:
        raise EHFrameError(
            "x86-64 返回地址列应为 16 (rip)，得到 %d" % ra_column, ra_off)

    if augmentation.startswith(b"z"):
        aug_len_off = r.pos
        aug_len = r.uleb128()
        aug_end = r.pos + aug_len
        if aug_end > body_end:
            raise EHFrameError(
                "CIE 增强块长度 %d 越过记录边界" % aug_len, aug_len_off)
        r.pos = aug_end

    if r.pos > body_end:
        raise EHFrameError("CIE 头部越过记录边界", r.pos)

    init_off = r.pos
    return CIE(
        offset=start,
        version=version,
        augmentation=augmentation,
        code_align=code_align,
        data_align=data_align,
        ra_column=ra_column,
        initial_instructions=data[init_off:body_end],
        initial_instructions_offset=init_off,
        end_offset=body_end,
        marker_offset=id_off,
    )


def _parse_fde(data: bytes, start: int, id_off: int, body_end: int,
               pointer: int, cie: CIE) -> FDE:
    r = _Reader(data)
    r.pos = id_off + 4
    initial_location = r.u32()
    address_range = r.u32()

    if cie.augmentation.startswith(b"z"):
        aug_len_off = r.pos
        aug_len = r.uleb128()
        aug_end = r.pos + aug_len
        if aug_end > body_end:
            raise EHFrameError(
                "FDE 增强块长度 %d 越过记录边界" % aug_len, aug_len_off)
        r.pos = aug_end

    if r.pos > body_end:
        raise EHFrameError("FDE 头部越过记录边界", r.pos)

    return FDE(
        offset=start,
        pointer_field_offset=id_off,
        cie_pointer=pointer,
        cie=cie,
        initial_location=initial_location,
        address_range=address_range,
        instructions=data[r.pos:body_end],
        instructions_offset=r.pos,
        end_offset=body_end,
    )


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


class RuleKind(str, Enum):
    UNDEFINED = "undefined"
    SAME_VALUE = "same_value"
    OFFSET = "offset"
    REGISTER = "register"


@dataclass(frozen=True)
class RegRule:
    kind: RuleKind
    operand: int = 0  # factored offset (OFFSET) or partner reg (REGISTER)

    def describe(self, data_align: int) -> str:
        if self.kind is RuleKind.UNDEFINED:
            return "undefined（未定义，调用者值不可恢复）"
        if self.kind is RuleKind.SAME_VALUE:
            return "same_value（同值，调用者值与当前输入一致）"
        if self.kind is RuleKind.OFFSET:
            byte_off = self.operand * data_align
            return "offset：[CFA %s 0x%x]（%d × data-align %d）" % (
                "+" if byte_off >= 0 else "-", abs(byte_off),
                self.operand, data_align)
        return "register：取寄存器 %s 的恢复值" % reg_name(self.operand)


@dataclass(frozen=True)
class CFARule:
    register: int
    offset: int

    def describe(self) -> str:
        return "CFA = %s + 0x%x (%d)" % (
            reg_name(self.register), self.offset, self.offset)


@dataclass
class Row:
    """Complete rule row at one FDE-relative location."""

    location: int
    cfa: Optional[CFARule]
    cfa_origin: int
    regs: Dict[int, RegRule]
    origins: Dict[int, int]

    def snapshot(self) -> "Row":
        return Row(self.location,
                   CFARule(self.cfa.register, self.cfa.offset)
                   if self.cfa else None,
                   self.cfa_origin, dict(self.regs), dict(self.origins))


# ---------------------------------------------------------------------------
# CFI abstract machine
# ---------------------------------------------------------------------------


class _Machine:
    def __init__(self, cie: CIE, cfa, cfa_origin, regs, origins,
                 address_base: int = 0, allow_location_ops: bool = True):
        self.cie = cie
        # Locations are tracked FDE-relative; set_loc gives an absolute
        # 32-bit address translated via ``address_base``.
        self.address_base = address_base
        # CIE initial instructions must not move the location.
        self.allow_location_ops = allow_location_ops
        self.loc = 0
        self.cfa = cfa
        self.cfa_origin = cfa_origin
        self.regs = dict(regs)
        self.origins = dict(origins)
        self._initial_regs = dict(regs)
        self._initial_origins = dict(origins)
        # remember_state stack: (cfa, cfa_origin, regs, origins).
        # Per DWARF, the current *location* is neither saved nor
        # restored — restore_state only replaces rules in the current
        # row.
        self.stack: List[Tuple] = []

    def run(self, insn: bytes, base_offset: int) -> List[Row]:
        """Execute one instruction stream, returning committed rows.

        Row 0 (location 0) carries the incoming state.  Rule
        instructions modify the row at the current location; an
        advance/set_loc commits that row and begins a new row which
        starts as a copy of it.
        """
        r = _Reader(insn)
        rows: List[Row] = [self._snapshot_row(0)]

        def forbid_location(op_off: int) -> None:
            if not self.allow_location_ops:
                raise EHFrameError(
                    "CIE 初始指令中不允许出现地址推进类指令", op_off)

        def commit(new_loc: int) -> None:
            # Finalize the row left behind at self.loc.
            snap = self._snapshot_row(self.loc)
            if rows and rows[-1].location == self.loc:
                rows[-1] = snap
            else:
                rows.append(snap)
            self.loc = new_loc

        def advance(delta_factored: int) -> None:
            forbid_location(self._last_op_off)
            # Zero-delta advances do not open a new row.
            if delta_factored == 0:
                return
            commit(self.loc + delta_factored * self.cie.code_align)

        def finalize() -> None:
            snap = self._snapshot_row(self.loc)
            if rows and rows[-1].location == self.loc:
                rows[-1] = snap
            else:
                rows.append(snap)

        while r.pos < len(insn):
            op_off = base_offset + r.pos
            self._last_op_off = op_off
            op = r.u8()
            high = op & 0xC0

            if high == Op.ADVANCE_LOC:
                advance(op & 0x3F)
            elif high == Op.OFFSET:
                reg = op & 0x3F
                factored = r.uleb128()
                self.regs[reg] = RegRule(RuleKind.OFFSET, factored)
                self.origins[reg] = op_off
            elif high == Op.RESTORE:
                self._restore(op & 0x3F, op_off)
            elif op == Op.NOP:
                pass
            elif op == Op.SET_LOC:
                forbid_location(op_off)
                # Absolute 32-bit address in the supported format.
                absolute = r.u32()
                new_rel = absolute - self.address_base
                if new_rel < self.loc:
                    raise EHFrameError(
                        "DW_CFA_set_loc 地址 0x%x 使位置回退（当前 0x%x）"
                        % (absolute, self.address_base + self.loc), op_off)
                if new_rel != self.loc:
                    commit(new_rel)
            elif op == Op.ADVANCE_LOC1:
                advance(r.u8())
            elif op == Op.ADVANCE_LOC2:
                advance(r.u16())
            elif op == Op.ADVANCE_LOC4:
                advance(r.u32())
            elif op == Op.OFFSET_EXTENDED:
                reg = r.uleb128()
                factored = r.uleb128()
                self.regs[reg] = RegRule(RuleKind.OFFSET, factored)
                self.origins[reg] = op_off
            elif op == Op.RESTORE_EXTENDED:
                self._restore(r.uleb128(), op_off)
            elif op == Op.UNDEFINED:
                reg = r.uleb128()
                self.regs[reg] = RegRule(RuleKind.UNDEFINED)
                self.origins[reg] = op_off
            elif op == Op.SAME_VALUE:
                reg = r.uleb128()
                self.regs[reg] = RegRule(RuleKind.SAME_VALUE)
                self.origins[reg] = op_off
            elif op == Op.REGISTER:
                reg1 = r.uleb128()
                reg2 = r.uleb128()
                self.regs[reg1] = RegRule(RuleKind.REGISTER, reg2)
                self.origins[reg1] = op_off
            elif op == Op.REMEMBER_STATE:
                self.stack.append((
                    CFARule(self.cfa.register, self.cfa.offset)
                    if self.cfa else None,
                    self.cfa_origin,
                    dict(self.regs), dict(self.origins)))
            elif op == Op.RESTORE_STATE:
                if not self.stack:
                    raise EHFrameError(
                        "规则栈下溢：restore_state 没有匹配的 remember_state",
                        op_off)
                cfa, cfa_origin, regs, origins = self.stack.pop()
                self.cfa = (CFARule(cfa.register, cfa.offset)
                            if cfa else None)
                self.cfa_origin = cfa_origin
                self.regs = dict(regs)
                self.origins = dict(origins)
                # Location is deliberately left unchanged; the restored
                # rules amend the row at self.loc, so refresh it.
                snap = self._snapshot_row(self.loc)
                if rows and rows[-1].location == self.loc:
                    rows[-1] = snap
                else:
                    rows.append(snap)
            elif op == Op.DEF_CFA:
                reg = r.uleb128()
                off = r.uleb128()
                self.cfa = CFARule(reg, off)
                self.cfa_origin = op_off
            elif op == Op.DEF_CFA_REGISTER:
                if self.cfa is None:
                    raise EHFrameError(
                        "def_cfa_register 之前没有任何 def_cfa", op_off)
                reg = r.uleb128()
                self.cfa = CFARule(reg, self.cfa.offset)
                self.cfa_origin = op_off
            elif op == Op.DEF_CFA_OFFSET:
                if self.cfa is None:
                    raise EHFrameError(
                        "def_cfa_offset 之前没有任何 def_cfa", op_off)
                off = r.uleb128()
                self.cfa = CFARule(self.cfa.register, off)
                self.cfa_origin = op_off
            else:
                raise EHFrameError(
                    "不支持或保留的 CFI 操作码 0x%02x" % op, op_off)

        finalize()
        return rows

    def _restore(self, reg: int, op_off: int) -> None:
        # DW_CFA_restore: the register returns to the rule it had at
        # the end of the CIE initial instructions.  Registers the CIE
        # never mentioned retain the abstract-machine default rule,
        # which is "undefined" — represented here by dropping the
        # explicit rule (absence == default undefined).
        if reg in self._initial_regs:
            self.regs[reg] = self._initial_regs[reg]
            self.origins[reg] = self._initial_origins[reg]
        else:
            self.regs.pop(reg, None)
            self.origins.pop(reg, None)

    def _snapshot_row(self, loc: int) -> Row:
        return Row(
            loc,
            CFARule(self.cfa.register, self.cfa.offset) if self.cfa else None,
            self.cfa_origin,
            dict(self.regs), dict(self.origins))


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


@dataclass
class RegisterRecovery:
    number: int
    name: str
    rule: RegRule
    origin: int
    value: Optional[int] = None
    recoverable: bool = True
    reason: str = ""


@dataclass
class AnalysisResult:
    hit: bool
    pc: int
    fde: Optional[FDE] = None
    cie: Optional[CIE] = None
    matched_row: Optional[Row] = None
    relative_location: int = 0
    cfa_value: Optional[int] = None
    cfa_reason: str = ""
    caller_pc: Optional[int] = None
    caller_pc_rule: Optional[RegRule] = None
    caller_pc_reason: str = ""
    registers: List[RegisterRecovery] = field(default_factory=list)
    memory_reads: List[Tuple[int, int]] = field(default_factory=list)
    timeline: List[Row] = field(default_factory=list)
    miss_reason: str = ""


def _build_initial(cie: CIE):
    """Reduce CIE initial instructions into the row-0 state."""
    mach = _Machine(cie, None, cie.initial_instructions_offset, {}, {},
                    allow_location_ops=False)
    # CIE initial streams contain no location ops, but run the same
    # machine so every encoding is validated uniformly.
    rows = mach.run(cie.initial_instructions,
                    cie.initial_instructions_offset)
    row = rows[-1]
    if row.cfa is None:
        raise EHFrameError(
            "CIE 初始指令未建立 CFA 规则，无法归约",
            cie.initial_instructions_offset)
    return row


def analyze(section: FrameSection, pc: int,
            registers: Dict[int, int],
            memory: Optional[Dict[int, int]] = None) -> AnalysisResult:
    """Reduce rules for ``pc`` and recover caller state.

    ``registers``: DWARF reg number -> unsigned 64-bit current value.
    ``memory``:    byte address -> unsigned 64-bit little-endian value.
                    Any read absent from the map is an out-of-bounds
                    error anchored at the raw CFI offset demanding it.
    """
    memory = dict(memory or {})
    registers = {n: v & 0xFFFFFFFFFFFFFFFF for n, v in registers.items()}

    target_fde: Optional[FDE] = None
    for fde in section.fdes:
        if fde.initial_location <= pc < fde.end_address:
            if target_fde is not None:
                raise EHFrameError(
                    "PC 0x%x 同时命中 FDE@0x%x 与 FDE@0x%x，区间冲突"
                    % (pc, target_fde.offset, fde.offset), fde.offset)
            target_fde = fde

    if target_fde is None:
        # Explicit miss — the UI must drop any previous conclusion.
        return AnalysisResult(
            hit=False, pc=pc,
            miss_reason="PC 0x%x 未落入任何 FDE 的 "
                        "[initial_location, initial_location + "
                        "address_range) 半开区间，未命中；上次成功结论已清除"
                        % pc)

    cie = target_fde.cie
    assert cie is not None
    initial = _build_initial(cie)

    mach = _Machine(cie, initial.cfa, initial.cfa_origin,
                    initial.regs, initial.origins,
                    address_base=target_fde.initial_location)
    timeline = mach.run(target_fde.instructions,
                        target_fde.instructions_offset)

    target_rel = pc - target_fde.initial_location
    applicable: Optional[Row] = None
    for row in timeline:  # rows are emitted in address order
        if row.location <= target_rel:
            applicable = row
    assert applicable is not None and applicable.cfa is not None

    result = AnalysisResult(
        hit=True, pc=pc, fde=target_fde, cie=cie,
        matched_row=applicable, relative_location=applicable.location,
        timeline=timeline)

    # --- CFA -----------------------------------------------------------
    cfa_reg = applicable.cfa.register
    if cfa_reg not in registers:
        raise EHFrameError(
            "计算 CFA 需要寄存器 %s 的当前值，但输入未提供"
            % reg_name(cfa_reg), applicable.cfa_origin)
    cfa_value = (registers[cfa_reg] + applicable.cfa.offset) \
        & 0xFFFFFFFFFFFFFFFF
    result.cfa_value = cfa_value
    result.cfa_reason = "%s；%s=0x%x ⇒ CFA=0x%x" % (
        applicable.cfa.describe(), reg_name(cfa_reg),
        registers[cfa_reg], cfa_value)

    def read_mem(addr: int, anchor: int) -> int:
        if addr not in memory:
            raise EHFrameError(
                "内存读取越界：CFA 规则要求读取地址 0x%x，但该地址不在提供的"
                "内存快照内；拒绝推测读取，且不返回部分寄存器结果" % addr,
                anchor)
        val = memory[addr] & 0xFFFFFFFFFFFFFFFF
        result.memory_reads.append((addr, val))
        return val

    def recover(reg: int, rule: RegRule, stack: Tuple[int, ...],
                anchor: int) -> Optional[int]:
        if reg in stack:
            raise EHFrameError(
                "寄存器恢复规则循环：%s"
                % " -> ".join(reg_name(x) for x in stack + (reg,)),
                anchor)
        if rule.kind is RuleKind.UNDEFINED:
            return None
        if rule.kind is RuleKind.SAME_VALUE:
            if reg not in registers:
                raise EHFrameError(
                    "寄存器 %s 规则为 same_value，但未提供其当前输入值"
                    % reg_name(reg), anchor)
            return registers[reg]
        if rule.kind is RuleKind.REGISTER:
            other = rule.operand
            other_rule = applicable.regs.get(other)
            if other_rule is None:
                # No explicit rule for the partner register: per the
                # abstract-machine default its caller value is
                # undefined, but REG_SAVED_REG reads the partner's
                # *current-frame* value.  When that live value is
                # supplied, use it; otherwise the register is not
                # recoverable (None) — not a hard error for a general
                # register, but fatal for the return-address column.
                return registers.get(other)
            return recover(other, other_rule, stack + (reg,), anchor)
        # OFFSET
        addr = (cfa_value + rule.operand * cie.data_align) \
            & 0xFFFFFFFFFFFFFFFF
        return read_mem(addr, anchor)

    # --- Caller PC (return-address column) ----------------------------
    ra = cie.ra_column
    ra_rule = applicable.regs.get(ra)
    if ra_rule is None:
        raise EHFrameError(
            "返回地址列 %s 在命中行没有任何恢复规则，调用者 PC 不可恢复"
            % reg_name(ra), target_fde.instructions_offset)
    if ra_rule.kind is RuleKind.UNDEFINED:
        raise EHFrameError(
            "返回地址列 %s 的规则为 undefined，调用者 PC 不可恢复"
            % reg_name(ra), applicable.origins.get(
                ra, target_fde.instructions_offset))
    ra_value = recover(ra, ra_rule, (),
                       applicable.origins.get(ra,
                                              target_fde.instructions_offset))
    if ra_value is None:
        raise EHFrameError(
            "返回地址列 %s 的恢复链最终为 undefined / 缺失，"
            "调用者 PC 不可恢复" % reg_name(ra),
            applicable.origins.get(ra, target_fde.instructions_offset))
    result.caller_pc = ra_value
    result.caller_pc_rule = ra_rule
    result.caller_pc_reason = "返回地址列 %s；%s ⇒ 调用者 PC = 0x%x" % (
        reg_name(ra), ra_rule.describe(cie.data_align), ra_value)

    # --- Every register with a rule -----------------------------------
    for num in sorted(applicable.regs.keys()):
        if num == ra:
            continue
        rule = applicable.regs[num]
        origin = applicable.origins.get(num,
                                        cie.initial_instructions_offset)
        rec = RegisterRecovery(number=num, name=reg_name(num),
                               rule=rule, origin=origin)
        val = recover(num, rule, (), origin)
        if rule.kind is RuleKind.UNDEFINED or val is None:
            rec.recoverable = False
            rec.value = None
            if rule.kind is RuleKind.REGISTER:
                rec.reason = ("register：伙伴寄存器 %s 的值不可恢复，"
                              "本寄存器调用者值不可恢复"
                              % reg_name(rule.operand))
            else:
                rec.reason = "undefined：调用者值不可恢复"
        elif rule.kind is RuleKind.SAME_VALUE:
            rec.value = val
            rec.reason = "same_value：采用当前输入 %s=0x%x" % (rec.name, val)
        elif rule.kind is RuleKind.REGISTER:
            rec.value = val
            rec.reason = "register：采用 %s 的恢复值 0x%x" % (
                reg_name(rule.operand), val)
        else:
            byte_off = rule.operand * cie.data_align
            addr = (cfa_value + byte_off) & 0xFFFFFFFFFFFFFFFF
            rec.value = val
            rec.reason = "offset：[CFA%+d] = [0x%x] = 0x%x" % (
                byte_off, addr, val)
        result.registers.append(rec)

    return result
