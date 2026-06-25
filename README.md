# 基于 LSSS 矩阵的 CP-ABE 实验实现

本项目实现了一个基于 LSSS 矩阵的密文策略属性基加密系统。系统以访问控制树作为策略输入，自动生成 LSSS 矩阵，并通过 Setup、KeyGen、Encrypt、Decrypt 四个流程演示“属性集合满足策略才能解密”的 CP-ABE 工作机制。

项目同时提供两条运行路线：默认的 `ExponentSimulation` 路线使用 Windows PowerShell 和 .NET 标准库，以整数指数抽象方式验证 LSSS-CP-ABE 的代数正确性和访问控制语义；真实 pairing 路线通过 Python 后端调用 `py-ecc` 的 BLS12-381 群运算和双线性配对，并使用 `pycryptodome` 处理 AES-CBC-HMAC 载荷。当前实现适用于课程实验和算法验证，不声明已经满足完整论文级安全证明或真实部署要求。

## 项目做了什么

本项目围绕“访问控制树到 LSSS 矩阵，再到 CP-ABE 加解密”这一主线完成了以下内容：

- 定义访问控制树 JSON 格式，支持属性叶子、AND、OR 和一般 `k-of-n` 阈值门。
- 实现访问控制树到 LSSS 矩阵 `(M, rho)` 的自动转换。
- 实现模素数域上的向量运算、高斯消元和 LSSS 重构系数求解。
- 实现 CP-ABE 的 `Setup`、`KeyGen`、`Encrypt`、`Decrypt` 四个核心流程。
- 使用 AES-CBC-HMAC 对实际明文载荷进行混合加密和完整性保护。
- 提供命令行接口，支持独立运行密钥生成、加密、解密等步骤。
- 编写烟雾测试，覆盖成功解密、拒绝解密、阈值门、重复属性、非法策略和密文篡改等场景。
- 抽象出 `GroupAdapter` 边界，默认适配器为 `ExponentSimulation`，同时提供 `PyEccBls12381Pairing` 真实 pairing 路线。

## 目录结构

```text
LSSS-ABE/
├── Project/                         # 可运行的软件系统
│   ├── bin/
│   │   └── lsss-abe.ps1             # 命令行入口
│   ├── src/
│   │   └── LsssAbe/
│   │       ├── LsssAbe.psm1         # 核心 PowerShell 模块
│   │       └── pairing_backend.py   # BLS12-381 真实 pairing 后端
│   ├── examples/
│   │   ├── message.txt              # 示例明文
│   │   └── policy.json              # 示例访问控制树
│   ├── tests/
│   │   ├── smoke.ps1                # 指数抽象版自动化烟雾测试
│   │   ├── smoke_pairing.ps1        # 真实 pairing 路线自动化烟雾测试
│   │   ├── artifacts/               # 指数抽象版测试产物
│   │   └── artifacts_pairing/        # 真实 pairing 路线测试产物
│   ├── artifacts/                   # 手动运行时的示例输出目录
│   ├── requirements-pairing.txt      # 真实 pairing 路线 Python 依赖
│   └── README.md                    # Project 子目录的简要运行说明
├── Report/                          # 结课论文与相关图表材料
│   ├── LaTeX/
│   │   ├── main.tex                 # 论文 LaTeX 入口
│   │   ├── main.pdf                 # 已编译论文
│   │   ├── pages/                   # 各章节源码
│   │   └── figures/                 # 报告中使用的图表资源
│   └── 公钥密码学期末作业模板.*       # 课程模板文件
├── References_Article/              # 课程材料和参考论文
├── LICENSE
└── README.md                        # 本文件
```

## 核心文件说明

| 文件 | 作用 |
| --- | --- |
| `Project/bin/lsss-abe.ps1` | CLI 入口，解析 `setup`、`keygen`、`encrypt`、`decrypt` 四类命令。 |
| `Project/src/LsssAbe/LsssAbe.psm1` | 核心实现，包含策略校验、LSSS 构造、线性重构、群适配器、混合加密和 CP-ABE 主流程。 |
| `Project/src/LsssAbe/pairing_backend.py` | 真实 pairing 后端，使用 BLS12-381 群元素和配对运算执行真实 pairing 路线的四算法流程。 |
| `Project/examples/policy.json` | 示例访问策略，默认表示 `(A AND B) OR C`。 |
| `Project/examples/message.txt` | 示例明文，用于加密和解密验证。 |
| `Project/tests/smoke.ps1` | 指数抽象版自动化测试脚本，覆盖 9 个成功、失败和边界场景。 |
| `Project/tests/smoke_pairing.ps1` | 真实 pairing 路线自动化测试脚本，覆盖 8 类 pairing 场景。 |
| `Project/tests/artifacts/` | 指数抽象版烟雾测试生成的公钥、主密钥、用户私钥、密文和解密输出。 |
| `Project/tests/artifacts_pairing/` | 真实 pairing 路线烟雾测试生成的密钥、密文和解密输出。 |
| `Report/LaTeX/main.pdf` | 项目配套实验报告。 |

## 快速运行

建议在 Windows PowerShell 中运行。进入 `Project` 目录：

```powershell
Set-Location E:\WHU\Kinding_Plan\LSSS-ABE\Project
```

运行默认指数抽象版完整烟雾测试：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\smoke.ps1
```

测试通过时会看到类似输出：

```text
Scenario 1 OK: {A,B} decrypted successfully.
Scenario 2 OK: {C} decrypted successfully.
Scenario 3 OK: {A} correctly rejected.
Scenario 4 OK: filename-safe attribute key for role:admin decrypted successfully.
Scenario 5 OK: tampered ciphertext correctly rejected.
Scenario 6 OK: {D,F} satisfied 2-of-3 threshold policy.
Scenario 7 OK: {D} correctly rejected by 2-of-3 threshold policy.
Scenario 8 OK: repeated attribute rows decrypted successfully.
Scenario 9 OK: invalid policies correctly rejected.
All smoke tests passed.
```

真实 pairing 路线使用仓库根目录下的 `env` 环境。依赖版本记录在 `Project/requirements-pairing.txt` 中；在本机原路径下可先激活环境：

```powershell
conda activate E:\WHU\Kinding_Plan\LSSS-ABE\env
```

然后在 `Project` 目录运行 pairing 烟雾测试：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\smoke_pairing.ps1
```

测试通过时会看到：

```text
All pairing smoke tests passed.
```

也可以手动运行四个核心阶段：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 setup -OutDir .\artifacts

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 keygen `
  -Pub .\artifacts\public.json `
  -Msk .\artifacts\master.json `
  -OutDir .\artifacts `
  -Attrs "A,B"

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 encrypt `
  -Pub .\artifacts\public.json `
  -Policy .\examples\policy.json `
  -In .\examples\message.txt `
  -Out .\artifacts\ct.json

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 decrypt `
  -Pub .\artifacts\public.json `
  -Sk .\artifacts\sk_A_B.json `
  -In .\artifacts\ct.json `
  -Out .\artifacts\out.txt
```

## 访问策略格式

策略使用 JSON 访问控制树表示。叶子节点使用 `attr` 字段：

```json
{ "attr": "A" }
```

阈值门使用 `k` 和 `children` 字段：

```json
{
  "k": 2,
  "children": [
    { "attr": "A" },
    { "attr": "B" },
    { "attr": "C" }
  ]
}
```

其中：

- `k = 1` 表示 OR 门。
- `k = children.length` 表示 AND 门。
- 其他合法 `k` 值表示一般 `k-of-n` 阈值门。

默认示例策略为：

```text
(A AND B) OR C
```

因此：

- 属性集合 `{A,B}` 可以解密。
- 属性集合 `{C}` 可以解密。
- 属性集合 `{A}` 会被拒绝。

## 测试覆盖

`Project/tests/smoke.ps1` 覆盖以下场景：

| 场景 | 目的 |
| --- | --- |
| `{A,B}` 解密成功 | 验证 AND 分支满足策略。 |
| `{C}` 解密成功 | 验证 OR 分支满足策略。 |
| `{A}` 解密失败 | 验证不满足策略时拒绝解密。 |
| `role:admin` 属性 | 验证特殊属性名能安全生成私钥文件并保持属性语义。 |
| 篡改密文标签 | 验证 AES-CBC-HMAC 的完整性保护。 |
| `{D,F}` 满足 `2-of-3` | 验证一般阈值门成功路径。 |
| `{D}` 不满足 `2-of-3` | 验证一般阈值门失败路径。 |
| 重复属性 `X AND X` | 验证多行映射到同一属性时仍能重构。 |
| 非法策略输入 | 验证空属性、非法阈值、缺失字段等错误会被拒绝。 |

## 实现边界

当前实现用于课程实验和算法演示，主要验证 LSSS-CP-ABE 的结构正确性：

- 默认路线使用 `ExponentSimulation` 保存群元素指数，并用模运算模拟群运算和配对关系。
- 真实 pairing 路线使用 `py-ecc` 的 BLS12-381 群元素、`pairing()` 和 `hash_to_G1`，并将密钥、密文中的群元素保存为 JSON 编码。
- 指数版与 pairing 版的密钥、密文格式不同，不能混用。
- 当前 pairing 路线能够验证真实群运算路径可运行，但不等同于完成与 Waters 2011 安全模型完全一致的形式化安全证明。

如果要进一步扩展为更严格的真实密码实现，还需要继续审查曲线与安全模型选择、哈希到群域分离、随机标量采样、群元素序列化、子群检查和异常密文处理。
