# x86-64 `.eh_frame` 值班分析台

飞控固件异常后，值班工程师在页面粘贴**不超过 192 KiB** 的 Base64
小端 ELF64 `.eh_frame` 原始节，填写当前 PC 与寄存器值（以及供
`offset` 恢复使用的内存快照），即可通过真实 HTTP 接口查看：

* 命中的 FDE、关联 CIE、命中范围（半开区间）；
* CFA 规则与取值、调用者 PC；
* 各寄存器的恢复规则（offset / same_value / undefined / register）、
  规则来源的**原始节偏移**与恢复取值；
* 逐地址归约时间线（含 `remember_state` / 规则改写 / `restore_state`）。

## 支持的方言（严格子集）

| 项目 | 范围 |
| --- | --- |
| 记录格式 | 32 位 DWARF `.eh_frame`，小端 |
| CIE | version 1 |
| FDE 的 CIE 指针 | **绝对 32 位**（目标 CIE 长度字段的节内字节偏移） |
| CFA 指令 | `def_cfa` / `def_cfa_register` / `def_cfa_offset` |
| 寄存器规则 | `offset`（含高位紧凑形式与 extended）、`restore`、`same_value`、`undefined`、`register` |
| 地址推进 | `advance_loc` / `advance_loc1/2/4`、`set_loc`（绝对 32 位） |
| 规则快照 | `remember_state` / `restore_state` |

不支持：DWARF64、CIE version ≠ 1、增强数据解释（'z' 块仅做长度校验后跳过）、
expression 规则等。出现这些情况会在**首个原始偏移**处明确报错。

## 安全归约保证

1. **CIE 初始规则 + FDE 指令逐地址归约**：行边界由地址推进指令提交，
   行内规则修改作用于当前行；`set_loc` 按 FDE 初始位置换算相对位置。
2. **remember/restore 语义**：快照只保存规则（含 CFA），**不保存位置**；
   对于包含 `remember_state`、规则改写和 `restore_state` 的 FDE，较晚
   PC 的证据会回退到保存时的规则。
3. **未命中即清除**：PC 不落入任何 FDE 的 `[start, start+range)` 半开区间
   （包括 PC 恰为结束地址）时返回 `hit=false`，响应不含任何上次成功的
   CFA/调用者 PC/寄存器结论。
4. **无部分结果**：悬空 CIE 引用、记录长度越界、截断的 ULEB128/SLEB128、
   规则栈下溢、CIE version 错误、CFA 所需寄存器缺失、**CFA 或 offset
   内存读取越界**（地址不在用户提供的内存快照内）、调用者 PC 不可恢复
   （返回地址列无规则或为 undefined），都在首个原始偏移处整体拒绝，
   绝不返回部分寄存器结果。

> 由于 `.eh_frame` 的 CIE 标记字也是 `0`，而本系统又接受指向节偏移 0
> 处 CIE 的绝对指针 `0`，解析器通过**结构性探测**消歧：节中第一条记录
> 必须是 CIE；其后 id 为 0 的记录，仅当字节能构成合法 CIE 头
> （version=1、增强字符串正常结束、code/data align 合法）时才判定为 CIE，
> 否则视为指向偏移 0 的 FDE。

## 运行（Docker Compose）

```bash
# 默认宿主端口 8080
docker compose up -d --build
# 自定义宿主端口
EHF_HOST_PORT=9090 docker compose up -d --build

# 页面
open http://localhost:8080/
# 健康响应
curl -s http://localhost:8080/healthz
```

## 验收 verify（Compose 内对真实接口执行）

`verify` 在 Compose 内：构建检查（字节码编译）、对有效嵌套规则 /
恢复回退 / 截断 FDE 执行代码测试，并以有效及失败输入完成 API/HTTP
冒烟后退出，**用退出码报告验收结果**（0 全部通过，1 存在失败）：

```bash
docker compose up -d --build web
docker compose run --rm verify
echo "exit=$?"
```

`verify` 会等待 `web` 健康后，通过 `EHF_SMOKE_URL=http://web:8080`
对真实 HTTP 接口做冒烟。也可不依赖容器本地直接运行（自行拉起进程内
HTTP 服务）：

```bash
python3 -m app.verify
```

## HTTP API

### `GET /healthz`

```json
{"status": "ok", "service": "eh-frame-analyzer"}
```

### `POST /api/analyze`

请求字段：

```json
{
  "section_base64": "....",
  "pc": "0x401003",
  "registers_text": "rsp=0x1000\nrbp=0x2000",
  "memory_text": "0x1008=0x50000"
}
```

也接受对象形式 `registers` / `memory`（键为寄存器名或编号）。
寄存器名兼容 `rax rdx rcx rbx rsi rdi rbp rsp r8..r15 rip`（DWARF
x86-64 编号 0..16）。

成功命中时返回 200，包含 `fde / cie / hit_range / matched_row /
cfa / caller_pc / caller_pc_rule / registers / memory_reads /
timeline`；未命中返回 200 且仅 `hit=false + miss_reason`；
任何解析/归约错误返回 **422**：

```json
{"error": "悬空 CIE 引用：FDE@0x12 的绝对指针 0xdead 不指向任何 CIE",
 "offset": 22}
```

`offset` 即检测到的首个原始节字节偏移，且错误响应不含寄存器结果。

## 目录

```
app/
  eh_frame.py    严格解析器 + CFI 抽象机 + 逐地址规则归约与状态恢复
  server.py      标准库 HTTP 服务（页面 / healthz / api/analyze）
  static/index.html  值班页面
  samplegen.py   确定性合成 .eh_frame（含 remember/restore 与各类畸形样例）
  verify.py      构建检查 + 引擎代码测试 + API/HTTP 冒烟，退出码报告
Dockerfile
docker-compose.yml
```

仅依赖 Python 3.11 标准库，镜像内无 pip 安装步骤。
