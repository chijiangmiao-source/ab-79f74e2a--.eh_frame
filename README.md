# 飞控固件异常 `.eh_frame` FDE 命中与寄存器恢复工具

值班工程师在浏览器粘贴 **Base64 编码的小端 ELF64 `.eh_frame` 原始节**（≤ 192 KiB），
填写当前 PC 与寄存器值，即可查看：

- 命中的 FDE、关联的 CIE、命中范围（半开区间 `[initial_location, end)`）
- CFA 规则与取值、调用者 PC（RA 寄存器恢复值）
- 17 个寄存器（含 RA）的恢复规则与当前恢复取值，以及规则对应的**原始字节偏移**

仅依赖 Python 3.11 标准库，无第三方包。

## 支持范围（严格）

- x86-64：CIE 版本 **v1**；代码对齐因子 1、数据对齐因子 -8、RA 寄存器 16
- CIE 增强带 `zR`；FDE 指针编码 **绝对 32 位 `DW_EH_PE_udata4` (0x03)**；
  FDE 中 CIE 引用按 `.eh_frame` 标准反向相对偏移解析（同时兼容
  `0xffffffff` 标记 + 绝对偏移形式）
- CFI 指令：`advance_loc`(1/2/4 及高位形式)、`set_loc`、`offset`(高位及
  extended / extended_sf)、`restore`(高位及 extended)、`undefined`、
  `same_value`、`register`、`def_cfa`/`def_cfa_sf`、`def_cfa_register`、
  `def_cfa_offset`/`def_cfa_offset_sf`、`remember_state`、`restore_state`、
  `nop`
- 表达式 / `val_*` 规则、64 位 DWARF、非 udata4 编码等一律拒绝并定位偏移

## 归约语义

- 以 **CIE 初始指令**建立初始规则，再按 FDE 指令**逐地址**归约到目标 PC
- `remember_state` / `restore_state` 用规则栈做深拷贝快照与回退；
  较晚 PC 位于 restore 之后时，证据（含 CFA 与全部寄存器规则）
  **必须回退到保存时规则**
- PC 不落入任何 FDE 时返回 `hit=false`，且**不携带** CFA / 寄存器结论
- CFA 计算与每次 8 字节内存读取都做边界校验；内存转储由页面/API 提供
- 调用者 PC 不可恢复（RA 未定义 / 无法读取）时报错

## 错误定位

悬空 CIE 引用、条目长度越界、截断的 ULEB128/SLEB128、指令越过条目边界、
规则栈下溢、RA 不可恢复、内存越界等，统一返回首个**原始字节偏移**
（`raw_offset`，相对粘贴节起始），且**绝不返回部分寄存器结果**。

## 本地运行（无需 Docker）

```bash
python3 app/server.py                 # 默认 0.0.0.0:8080
PORT=9090 python3 app/server.py       # 指定端口
curl http://127.0.0.1:8080/healthz
```

## Compose 运行（宿主端口可配置）

```bash
HOST_PORT=9090 docker compose up --build
# 健康检查: curl http://127.0.0.1:9090/healthz
```

## 验收（在 Compose 内）

```bash
docker compose build
docker compose run --rm verify
```

`verify` 服务对**嵌套 remember/restore 规则、恢复回退、截断 FDE** 等执行
代码测试与构建检查，并以**有效及失败输入**完成 API/HTTP 冒烟后退出；
退出码即验收结果：`0` 全部通过，非 `0` 存在失败（`docker compose run`
会透传该退出码）。

## API

`POST /api/unwind`

```json
{
  "eh_frame": "<Base64 原始节>",
  "pc": "0x401020",
  "registers": {"RSP": "0x7ffdeadbeff0", "RBP": "0x7ffdeadc0000"},
  "memory": {"base": "0x7ffdeadbe000", "data": "<Base64 字节>"}
}
```

- 命中：`200 {"hit": true, "fde": ..., "cie": ..., "cfa": ...,
  "return_address": ..., "registers": [...]}`
- 未命中：`200 {"hit": false, "fdes": [...], "message": ...}`
- 节数据错误：`422 {"error": ..., "raw_offset": 26}`（无部分寄存器结果）
- 输入格式错误：`400`；超过 192 KiB：`413`

## 测试

```bash
python3 -m unittest tests.test_ehframe -v
```
