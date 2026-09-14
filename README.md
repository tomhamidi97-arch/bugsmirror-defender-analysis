# Bugsmirror Defender (libcachehandler.so) — RASP Environment Detection Analysis

## 0. 概述

- **目标库**：`libcachehandler.so` — 商业 RASP 产品 **Bugsmirror Defender**（Paytm 在用）
  - 特征字符串：`BugsmirrorDefenderValidation`、`com.bugsmirror.samplekeyattestation`
- **分析环境**：AArch64，IDA + Frida Gadget
- **核心发现**：该 RASP 通过 **IST31（KeyStore attestation 链验签 + pin 比对）** 与 **IST34（echo-trap 回声陷阱）** 两套互补机制检测 KeyStore 伪造模块；此外还有应用黑名单、代理 CA 扫描、shell 环境探测等多类环境检测。

## 1. 关键函数与偏移

| 函数 | 作用 |
| --- | --- |
| `sub_14D5E0` | 上报汇聚点 `handle_security_violation(ctx, code, sev, a3, a4, ist)` |
| `sub_DF838(id)` | 结果读取器，读全局结果位表（解密重建版对应 `sub_EA95C`） |
| `sub_143BB4` / `sub_11DEE8` | KeyStore attestation 校验（IST31） |
| `check_android_keystore_integrity_trap`（重建版 `sub_11D478`） | echo-trap 回声陷阱本体（IST34） |
| `check_su_in_system_image`（重建版 `sub_11B9B8`） | IST34 上报判定点，调用 echo-trap |
| `sub_14BDA8` | 运行期字符串解码器（黑名单/命令等敏感串均编码存储） |

> 偏移说明：IST34 部分偏移取自**解密重建版** `libcachehandler_decrypted_rebuild.so`（结果读取器为 `sub_EA95C`），已在 IDA 中逐条验证。

## 2. 检测项汇总

| code | arg5 / 含义 | 检测内容 | 应对 |
| --- | --- | --- | --- |
| **61007** | `61007-IST1` … `IST34` | AndroidKeyStore 密钥认证链真伪（核心，见 §3/§4） | 关闭 StrongBox 特性 |
| **61009** | `61009-IST1/2-<包名>` | 已装应用黑名单（77 项编码列表，如 `bin.mt.plus`） | 卸载/改包名，或 hook 解码器干扰匹配 |
| **10002** | `CA compromised by proxy tool:` | 抓包/中间人代理 CA（Charles / Fiddler / HttpCanary…） | 卸载抓包工具并删除其用户 CA |
| **10004** | `90040-IST5` | `popen` shell 命令环境探测 | 视具体命令隐藏痕迹 |
| **00000** | `Device environment is not correct.` | 兜底：某项检查抛异常未走完（本例为 StrongBox 请求失败） | 消除异常根因 |

### 2.1 应用黑名单（61009）细节

通过 `getInstalledPackages` 枚举已装应用，与 77 项经 `sub_14BDA8` 解码的黑名单包名逐个 `strcmp`，命中即报 `61009-IST2-<包名>`。

### 2.2 上报层归一

所有 `61007-ISTx` 上报路径均为 `if (sub_DF838(1004)) → 上报`，即只读 **category 1004** 的结果位，该位由 KeyStore attestation 校验置位。检测层 IST31 与 IST34 原理不同（见下），但根因在上报层归一。

## 3. IST31 — KeyStore Attestation 链校验

流程：

1. `hasSystemFeature("android.hardware.strongbox_keystore")` — 设备支持 StrongBox 时 `setIsStrongBoxBacked(true)`
2. `KeyPairGenerator` 现场生成带 attestation 的密钥（EC secp256r1 / RSA）
3. `getCertificateChain` 取回证书链
4. **逐级 `cert.verify(上一级公钥)`** — 密码学验签
5. `checkValidity()` — 证书有效期
6. **公钥 / 序列号 / IssuerDN 与内嵌 pin 值比对**（`sub_122BD4` / `sub_122EE8`，内嵌了正版 Google/TEE 认证链参照值）
7. 验签失败或 pin 不符 → 置 category 1004 → 报 **61007**

特点：

- 验的是「链是否由 Google 真实私钥签发」，**不**检查证书内容字段，也**不**解析 RootOfTrust / verifiedBoot / 解锁状态（无 `getExtensionValue`）
- 对伪造 attestation 的 keybox 替换模块（`newChain = leaf + keybox.certificates`）**数学上无解**：伪造链没有 Google 私钥签名，必中；换正版 keybox 也不行，因为 pin 的是 RASP 自带的特定链

### StrongBox 门槛（最干净的绕过点）

**App 只在设备报告支持 StrongBox 时才执行这套强完整性检查。**

- `hasSystemFeature(strongbox) = true` → 走 StrongBox 路径 → 链校验 → 伪造链被逮（61007）；若 StrongBox 请求失败则抛 `StrongBoxUnavailableException` → 兜底报 **00000**
- `hasSystemFeature(strongbox) = false` → 整条强完整性检查（含 IST31/IST34）**直接跳过**

因此 hook `hasSystemFeature` 关掉 StrongBox 特性报告，即可让 IST31/IST34 均不运行。

## 4. IST34 — Echo-Trap 回声陷阱

**原理**：向 AndroidKeyStore 写入一张内容完全已知的自签证书，再原样读回，逐字节比对——以此检测「无差别替换 `getCertificateChain` 返回值」的 keystore hook 副作用。

### 4.1 内嵌常量

| 变量 | 内容 |
| --- | --- |
| 私钥 | PKCS#8 EC 私钥（secp256r1） |
| 证书 | 自签证书，CN = `EchoTrapStatic`，notBefore `2026-05-07` / notAfter `2126-04-13` |

### 4.2 执行流程

1. `sub_147EF0`（WolfSSL）将两段 base64 解为 DER，记录证书 DER 及长度作为参照锚点
2. 私钥经 `PKCS8EncodedKeySpec` + `KeyFactory("EC")` 还原，证书经 `CertificateFactory("X.509")` 还原
3. 前置诱饵：`KeyPairGenerator` + `setAttestationChallenge("trap_bait")` 生成一个真 attestation key，让 hook 误以为是常规 attestation 调用
4. `keyStore.setKeyEntry("echo_trap_key", privKey, pwd, [cert])` — 塞入已知证书
5. `chain = keyStore.getCertificateChain("echo_trap_key")` — 原样读回
6. `keyStore.deleteEntry("echo_trap_key")` — 删除不留痕
7. **核心判定**（逐字节比对）：

```c
if ( !GetArrayLength(chain)                          // 链为空
  || chain[0].getEncoded().length != 内嵌证书长度 )   // 长度不符
{
    return true;                                     // 判定被篡改
}
return memcmp(内嵌证书DER, chain[0].getEncoded(), 长度) != 0;  // 任一字节不同 → 篡改
```

### 4.3 触发条件（IST34 门控代码）

```c
v2 = sub_EA95C(1004);                        // 读 category 1004 结果位
if (__system_property_get("ro.build.version.sdk", nptr) <= 0) return;
v3 = (v2 & 1) != 0 ? 29 : 33;                // SDK 阈值：1004 已置位→29，否则→33
v4 = atoi(nptr);
if (v4 < 1 || v4 < v3 || (byte_15FCDB & 1)) return;   // SDK 太低 / 已跑过一次 → 跳过

if ((sub_EA95C(1004) & 1) != 0 && check_android_keystore_integrity_trap(a1))
    handle_security_violation(a1, "61007", 0, 0, 0, "61007-IST34");
```

三个门槛：

1. **`byte_15FCDB` 单次守卫** — 全程只执行一次
2. **SDK 门槛** — 低版本 Android 不跑
3. **`sub_EA95C(1004) & 1` 必须已为真** — IST34 是 IST31 的「二次确认」：只有链校验已判定环境可疑（1004 已置位）才拉起 echo-trap，命中则补报 `IST34`

### 4.4 IST31 与 IST34 的互补关系

| | IST31 | IST34 |
| --- | --- | --- |
| 原理 | 硬件认证链**验签 + pin 比对** | **echo-trap 回声陷阱** |
| 打击点 | 伪造链没有 Google 真签名 | hook 太贪——连 RASP 自己塞入 KeyStore 的已知证书都被乱改 |
| 视角 | 密码学正确性 | keystore hook 的副作用 |

任何粗暴全局替换 `getCertificateChain` 返回值的伪造模块，两条检测至少中一条。

## 5. 绕过思路汇总（研究向）

1. **关闭 StrongBox 特性报告**（最干净）：hook `hasSystemFeature` 对 `android.hardware.strongbox_keystore` 返回 false → IST31/IST34 整条不跑，且根除 00000 兜底异常
2. **Hook 结果读取器**：`sub_EA95C` / `sub_DF838` 对 `id == 1004` 返回 0，同时压掉 IST31 与 IST34 的前置
3. **针对 echo-trap 的白名单**：keystore hook 对 alias `echo_trap_key` 放行、不替换其返回链——成熟伪造模块应具备的白名单逻辑
4. 其他路径（原文提及可自行测试）：改机 / 魔改 ROM / 近期新出的免解锁 root 提权漏洞机等

## 参考

- 原文：看雪安全社区《paytm 商业 RASP Bugsmirror Defender 环境检测分析》
  https://bbs.kanxue.com/thread-292873.htm
- 分析对象版本：设备版 `libcachehandler.so_fixed`、解密重建版 `libcachehandler_decrypted_rebuild.so`

## 免责声明

本文仅供安全研究与学习交流。请遵守当地法律法规，未经授权不得对他人系统进行测试。
