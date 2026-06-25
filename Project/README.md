# Project：基于 LSSS 矩阵的 CP-ABE

该目录是本项目的主要可运行源码目录。系统以访问控制树作为策略输入，自动构造 LSSS 矩阵，并完成 CP-ABE 的 Setup、KeyGen、Encrypt、Decrypt 流程。

当前 `Project` 同时提供两条运行路线：

- `ExponentSimulation`：默认路线，使用指数抽象模型，便于快速验证访问树、LSSS 矩阵和重构逻辑。
- `PyEccBls12381Pairing`：真实 pairing 路线，通过 Python 后端调用 `py-ecc` 的 BLS12-381 群运算和双线性配对，并使用 `pycryptodome` 处理 AES-CBC/HMAC 混合加密载荷。

## 群运算适配器状态

- `ExponentSimulation`：PowerShell 模块内置适配器，用模 `p` 的整数指数表示群元素和配对关系。
- `PyEccBls12381Pairing`：真实配对适配器，源码位于 `src/LsssAbe/pairing_backend.py`，使用 `G1/G2/GT/Zp`、`pairing()`、hash-to-G1、群元素 JSON 序列化、曲线成员检查和子群检查。

真实 pairing 路线保留了访问树到 LSSS 的主线，但密钥和密文中的群元素已经不再是十进制指数，而是 BLS12-381 的 `G1`、`G2` 和 `GT` 编码。因此，指数版生成的密钥/密文不能与 pairing 版混用。

## 目录结构

- bin：命令行入口
- src/LsssAbe：PowerShell 模块源码与 Python pairing 后端
- examples：示例策略与示例明文
- tests：最小可运行验证脚本

## 依赖环境

真实 pairing 路线使用仓库根目录下的 conda 环境。在本机原路径下可执行：

```powershell
conda activate E:\WHU\Kinding_Plan\LSSS-ABE\env
```

如果项目移动到其他目录，只需将上述路径替换为新仓库根目录下的 `env`。依赖版本由 `requirements-pairing.txt` 锁定，在 `Project` 目录执行：

```powershell
python -m pip install -r requirements-pairing.txt
```

本仓库配套的 `E:\WHU\Kinding_Plan\LSSS-ABE\env` 环境已经安装并验证上述依赖。命令行脚本默认会优先使用 `..\env\python.exe`；也可以通过 `-Python` 手动指定解释器。

## 快速开始：默认指数版

进入 `Project` 目录后执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 setup -OutDir .\artifacts

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 keygen -Pub .\artifacts\public.json -Msk .\artifacts\master.json -Attrs "A,B"

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 encrypt -Pub .\artifacts\public.json -Policy .\examples\policy.json -In .\examples\message.txt -Out .\artifacts\ct.json

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 decrypt -Pub .\artifacts\public.json -Sk .\artifacts\sk_A_B.json -In .\artifacts\ct.json -Out .\artifacts\out.txt
```

运行完整验证：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\smoke.ps1
```

## 快速开始：真实 pairing 路线

真实 pairing 路线通过 `-Adapter pairing` 启用：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 setup -Adapter pairing -OutDir .\artifacts_pairing

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 keygen -Adapter pairing -Pub .\artifacts_pairing\public.json -Msk .\artifacts_pairing\master.json -OutDir .\artifacts_pairing -Attrs "A,B"

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 encrypt -Adapter pairing -Pub .\artifacts_pairing\public.json -Policy .\examples\policy.json -In .\examples\message.txt -Out .\artifacts_pairing\ct.json

powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\lsss-abe.ps1 decrypt -Adapter pairing -Pub .\artifacts_pairing\public.json -Sk .\artifacts_pairing\sk_A_B.json -In .\artifacts_pairing\ct.json -Out .\artifacts_pairing\out.txt
```

运行真实 pairing 路线验证：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\smoke_pairing.ps1
```

## 策略格式（访问控制树 JSON）

叶子节点：

```json
{ "attr": "A" }
```

阈值门（k-of-n）：

```json
{ "k": 2, "children": [ { "attr": "A" }, { "attr": "B" }, { "attr": "C" } ] }
```

AND/OR 分别是：

- AND：k = children.length
- OR：k = 1
