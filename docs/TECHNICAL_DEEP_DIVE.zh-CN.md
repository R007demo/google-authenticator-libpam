# Google Authenticator (libpam) 源码级技术深析

> 本文是对 `google-authenticator-libpam`（版本 **1.11**，commit 基于 2026 年主线）的**源码级**技术分析。
> - **逐函数拆解算法实现**（含字节布局、常量、位运算、端序处理）；
> - **精确推导 6 位验证码的产生过程**（HMAC-SHA1 → 动态截断 → 模运算）；
> - **剖析状态文件的全部状态机**（RATE_LIMIT / DISALLOW_REUSE / TIME_SKEW / HOTP_COUNTER / scratch）；
> - **枚举安全机制**（降权、TOCTOU 防护、时序常量化的反证、内存清零、SELinux 标签）；
> - **给出关键代码的 `file:line` 引用**，便于对照阅读。

---

## 目录

1. [项目本质与代码地图](#1-项目本质与代码地图)
2. [OTP 算法核心：从 RFC 到 `compute_code()`](#2-otp-算法核心从-rfc-到-compute_code)
3. [密码学栈逐层拆解](#3-密码学栈逐层拆解)
4. [状态文件：格式、语义与状态机](#4-状态文件格式语义与状态机)
5. [PAM 认证主流程逐行精读](#5-pam-认证主流程逐行精读)
6. [三种验证码的校验算法](#6-三种验证码的校验算法)
7. [速率限制 / 防重放 / 时间漂移自愈](#7-速率限制--防重放--时间漂移自愈)
8. [权限模型与安全加固](#8-权限模型与安全加固)
9. [CLI（provisioning）实现细节](#9-cliprovisioning实现细节)
10. [构建系统、测试与可观测性](#10-构建系统测试与可观测性)
11. [已知边界、攻击面与设计权衡](#11-已知边界攻击面与设计权衡)

---

## 1. 项目本质与代码地图

### 1.1 它到底实现了什么

| 标准 | 实现内容 | 代码位置 |
|------|----------|----------|
| **RFC 4648** Base32 | 编解码，字母表 `A-Z2-7` | `src/base32.c` |
| **FIPS 180-4** SHA-1 | 自带实现（无 OpenSSL 依赖） | `src/sha1.c` |
| **RFC 2104** HMAC-SHA1 | 嵌套哈希结构 | `src/hmac.c` |
| **RFC 4226** HOTP | 动态截断 + 模 10^6 | `pam_google_authenticator.c:1390` `compute_code()` |
| **RFC 6238** TOTP | `T = floor(unixtime / step)`，默认 step=30 | `pam_google_authenticator.c:974` `get_timestamp()` |

**关键点：** 这是一个**完全自包含**的实现——没有链接 libcrypto/libssl。SHA-1、HMAC、Base32 都是手写。
这意味着：
- 部署零密码学库依赖（降低供应链风险）；
- 但 SHA-1 实现的正确性、端序处理、抗侧信道能力完全由本项目代码负责，无法依赖系统库的审计。

### 1.2 产物清单（`Makefile.am`）

```
bin_PROGRAMS     = google-authenticator            # 用户态 CLI：生成密钥
pam_LTLIBRARIES  = pam_google_authenticator.la     # PAM 共享库（auth 栈）
noinst_PROGRAMS  = base32                          # 调试用 base32 工具
check_PROGRAMS   = examples/demo                   # 直接调用 pam_sm_authenticate 的演示
check_LTLIBRARIES= libpam_google_authenticator_testing.la  # 带 TESTING 宏的副本
```

三个核心 C 文件职责清晰：

| 文件 | 行数 | 角色 | 导出符号 |
|------|------|------|----------|
| `src/pam_google_authenticator.c` | 2286 | PAM 模块（验证侧） | `pam_sm_authenticate` / `pam_sm_setcred` |
| `src/google-authenticator.c` | 977 | CLI（provisioning 侧） | `main` |
| `src/{sha1,hmac,base32,util}.c` | 552 | 共享密码学/工具 | 全部 `visibility("hidden")` |

> **架构精髓：** CLI 与 PAM **不共享任何 API**。它们之间唯一的契约是磁盘上的一个 ASCII 文件 `~/.google_authenticator`。这是典型的"文件即协议"设计——简单、可调试、无 IPC，但代价是无集群同步、无集中吊销。

### 1.3 符号可见性工程

所有内部函数都被刻意限制可见性：

```c
// src/base32.h
int base32_decode(...) __attribute__((visibility("hidden")));

// src/hmac.h
void hmac_sha1(...) __attribute__((visibility("hidden")));
```

PAM 模块本身只导出真正必要的 PAM 钩子（`Makefile.am:35`）：

```makefile
pam_google_authenticator_la_LDFLAGS = ... -export-symbols-regex "pam_sm_(setcred|open_session|authenticate)"
```

这样即便被加载进 `sshd` 等进程地址空间，也不会与宿主的同名符号冲突（`MODULE_NAME` 也特意缩短为 `pam_google_auth`，见 `pam_google_authenticator.c:67` 的注释——避免 rsyslog 截断问题）。

测试构建（`libpam_google_authenticator_testing.la`）通过 `-DTESTING=1` 解除隐藏：

```c
#ifdef TESTING
int compute_code(...) __attribute__((visibility("default")));
void set_time(time_t t) __attribute__((visibility("default")));
```

允许单元测试注入时间、直接调用 OTP 计算（见第 10 节）。

---

## 2. OTP 算法核心：从 RFC 到 `compute_code()`

整个项目的密码学核心就是 **一个函数**：`compute_code(secret, secretLen, value)`（`pam_google_authenticator.c:1390-1408`）。它在 PAM 和 CLI 两边几乎完全一致地出现（CLI 里叫 `generateCode`，`google-authenticator.c:50`）。

### 2.1 算法的三个阶段（RFC 4226 §5.3）

```
┌─────────────────────────────────────────────────────────────┐
│ 阶段 1：构造 8 字节大端计数器                                 │
│   value (uint64) → val[8]  （大端字节序）                     │
├─────────────────────────────────────────────────────────────┤
│ 阶段 2：HMAC-SHA1                                            │
│   hash = HMAC-SHA1(key=secret, msg=val)  → 20 字节           │
├─────────────────────────────────────────────────────────────┤
│ 阶段 3：动态截断（Dynamic Truncation）+ 模运算                │
│   offset = hash[19] & 0x0F          // 低 4 位，范围 [0,15]   │
│   truncated = hash[offset..offset+3] // 4 字节，大端         │
│   truncated &= 0x7FFFFFFF           // 清除符号位            │
│   code = truncated % 1000000        // 6 位十进制            │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 代码逐行精读

```c
// pam_google_authenticator.c:1390
int compute_code(const uint8_t *secret, int secretLen, unsigned long value) {
  uint8_t val[8];
  for (int i = 8; i--; value >>= 8) {   // ① 大端拆字节
    val[i] = value;
  }
  uint8_t hash[SHA1_DIGEST_LENGTH];      // 20 字节
  hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);  // ② HMAC
  explicit_bzero(val, sizeof(val));      // 立即清零计数器（含明文 value）
  const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;  // ③ 动态偏移
  unsigned int truncatedHash = 0;
  for (int i = 0; i < 4; ++i) {          // ④ 取 4 字节拼回整数（大端）
    truncatedHash <<= 8;
    truncatedHash  |= hash[offset + i];
  }
  explicit_bzero(hash, sizeof(hash));    // 清零 HMAC 输出
  truncatedHash &= 0x7FFFFFFF;           // ⑤ 去符号位 → 31 位
  truncatedHash %= 1000000;              // ⑥ 映射到 [0, 999999]
  return truncatedHash;
}
```

**关键细节解读：**

1. **循环 `for (int i = 8; i--; ...)` 的反序**：`i` 从 7 递减到 0，每次 `value >>= 8` 先取最低字节放入 `val[7]`，最终 `val[0]` 是最高字节——这正是**大端序**编码。RFC 4226 要求 counter 作为大端 64 位整数参与运算，此实现完全合规。

2. **`offset = hash[19] & 0xF`**：用 HMAC 结果**最后一字节**（不是第一字节）的低 4 位作为偏移。这符合 RFC 4226 §5.3 的标准做法，偏移量 ∈ [0, 15]，保证 `hash[offset..offset+3]` 永不越界（最远到 hash[18]，安全）。

3. **`&= 0x7FFFFFFF`**：把 32 位整数限制到 31 位正整数（[0, 2³¹−1]），保证 `% 1000000` 后结果唯一确定、与符号位无关。

4. **`explicit_bzero` 的两处使用**：①清零 `val[]`（可能泄露当前时间步）；②清零 `hash[]`（HMAC 输出本身是敏感中间值）。这是防内存残留取证的标准做法（见 §8.4）。

### 2.3 TOTP vs HOTP：唯一区别在 `value`

```c
// TOTP：value = unix_timestamp / step_size    （pam_google_authenticator.c:974）
static int get_timestamp(...) {
  const int step = step_size(...);  // 默认 30
  return get_time()/step;           // 整数除法 = floor
}

// HOTP：value = HOTP_COUNTER（单调递增计数器，存储在状态文件）
const long hotp_counter = get_hotp_counter(pamh, buf);  // :1968
```

两者在 `compute_code` 内部**完全相同**——这是 RFC 6238 的设计精髓：TOTP 就是把"时间"当作计数器。数学上：

```
TOTP(K, T) = HOTP(K, floor(T_current / T_step))
```

### 2.4 一个端到端数值示例

用单元测试里的已知向量（`tests/pam_google_authenticator_unittest.c:246`）验证：

- 密钥（Base32）：`2SH3V3GDW7ZNMGYE`
- 二进制密钥（base32 解码后）：16 字节
- 时间步：`set_time(10000 * 30)` → `tm = 10000`
- 期望响应：`response = "050548"` → 即 `compute_code(...)` 在 `value=10000` 时应得 `50548`

测试断言 `pam_sm_authenticate(...) == PAM_SUCCESS`（第 389 行），证明 `compute_code(secret, 16, 10000) == 50548`。**任何人**用同样的密钥和时间都能复现这个数字——这正是 TOTP 的可复现性基础。

---

## 3. 密码学栈逐层拆解

### 3.1 Base32（`src/base32.c`）—— RFC 4648 的"宽容"变体

字母表：`ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`（`base32.c:88`）。

**编码**（`base32.c:64`）：标准实现，每 5 位映射一个字符，不足补零位（无 `=` 填充，与 RFC 4648 的 padding 不同——Google Authenticator 不用 `=`）。

**解码**的"人性化"特性（`base32.c:33-49`）：

```c
// 处理常见手误输入
if (ch == '0')      ch = 'O';   // 数字 0 → 字母 O
else if (ch == '1') ch = 'L';   // 数字 1 → 字母 L
else if (ch == '8') ch = 'B';   // 数字 8 → 字母 B

// 容忍空白与分隔符
if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-')
  continue;
```

这是面向"用户手动抄写密钥"场景的工程取舍：严格 RFC 解码会因一个小错让整个密钥作废。代价是密钥空间理论上的歧义（`0` 和 `O` 无法区分），但由于二者在字母表中本就不存在歧义映射（`0` 不在字母表，`O` 是第 14 个字符），实际无安全影响。

**位运算核心**（`base32.c:51-56`）：

```c
buffer |= ch;
bitsLeft += 5;
if (bitsLeft >= 8) {
  result[count++] = buffer >> (bitsLeft - 8);  // 取高 8 位
  bitsLeft -= 8;
}
```

每凑齐 8 位输出一字节，剩余位留在 `buffer` 高位。160 位密钥（20 字节）需要 ⌈160/5⌉ = 32 个 Base32 字符——这与 CLI 生成的密钥长度一致（`SECRET_BITS = 160`，`google-authenticator.c:40`）。

### 3.2 SHA-1（`src/sha1.c`）—— 公共领域移植版

这是一个**自带、跨端序**的 SHA-1 实现，源自 Bruce Schneier《应用密码学》中 Peter Gutmann 的版本，由 Uwe Hollerbach 改造。

**初始哈希值**（FIPS 180 标准，`sha1.c:224-228`）：

```c
sha1_info->digest[0] = 0x67452301L;  // 这些是 fractional bits of sqrt(2,3,5,8)
sha1_info->digest[1] = 0xefcdab89L;
sha1_info->digest[2] = 0x98badcfeL;
sha1_info->digest[3] = 0x10325476L;
sha1_info->digest[4] = 0xc3d2e1f0L;
```

**端序处理**（`sha1.c:118-169`）：通过 `BYTE_ORDER` 宏（来自 `<sys/types.h>`）区分四种字节序（1234 小端、4321 大端、12345678 中字小端、87654321 中字大端），分别用不同的字加载代码。这是该实现能在 SPARC、x86、ARM 上都正确工作的关键。

**消息扩展**（`sha1.c:171-174`）：

```c
for (i = 16; i < 80; ++i) {
  W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];  // 标准 SHA-1 扩展
  W[i] = R32(W[i], 1);                          // 循环左移 1
}
```

**四种轮函数**（`sha1.c:65-68`）对应 80 轮的四个 20 轮阶段：

```c
#define f1(x,y,z) ((x & y) | (~x & z))           // Ch (选择)
#define f2(x,y,z) (x ^ y ^ z)                    // Parity
#define f3(x,y,z) ((x & y) | (x & z) | (y & z))  // Maj (多数)
#define f4(x,y,z) (x ^ y ^ z)                    // Parity
```

**性能优化开关**：`UNRAVEL` 和 `UNROLL_LOOPS` 宏（`sha1.c:181,196`）展开 80 轮循环以减少分支预测开销。默认走通用 `for` 循环（`sha1.c:206-209`），保证可读性与可移植性。

> **安全注记：** SHA-1 已被证明不具备抗碰撞安全性（SHAttered 攻击，2017）。但 HOTP/TOTP 的安全模型依赖的是 HMAC-SHA1 的 **PRF（伪随机函数）** 性质，而非 SHA-1 的抗碰撞性。HMAC-SHA1 至今仍被 NIST 认为安全（SP 800-107, SP 800-131A）。所以本项目**在 OTP 场景下并非"过时"**——这是常见的误解。

### 3.3 HMAC-SHA1（`src/hmac.c`）—— RFC 2104 教科书实现

```c
void hmac_sha1(key, keyLength, data, dataLength, result, resultLength) {
  // ① 密钥规范化：>64 字节则先 SHA-1 压缩到 20 字节
  if (keyLength > 64) {
    sha1(key) → hashed_key;  // hmac.c:32-37
    key = hashed_key; keyLength = 20;
  }

  // ② 内层密钥：key XOR 0x36，补零到 64 字节
  uint8_t tmp_key[64];
  for (i=0; i<keyLength; ++i) tmp_key[i] = key[i] ^ 0x36;  // ipad
  memset(tmp_key + keyLength, 0x36, 64 - keyLength);

  // ③ 内层哈希：H(ipad || data)
  inner = SHA1(tmp_key(64) || data);

  // ④ 外层密钥：key XOR 0x5C
  for (i=0; i<keyLength; ++i) tmp_key[i] = key[i] ^ 0x5C;  // opad
  memset(tmp_key + keyLength, 0x5C, 64 - keyLength);

  // ⑤ 外层哈希：H(opad || inner)
  result = SHA1(tmp_key(64) || inner(20));

  // ⑥ 清零所有敏感中间值
  explicit_bzero(hashed_key, ...);
  explicit_bzero(sha, ...);
  explicit_bzero(tmp_key, ...);
}
```

**为什么是 0x36 和 0x5C？** RFC 2104 规定 ipad=0x36（二进制 `00110110`）、opad=0x5C（`01011100`）。两者汉明距离足够大，保证内/外层哈希的密钥差异显著，防止长度扩展攻击。

> OTP 密钥通常是 20 字节（160 位），不超过 64 字节阈值，所以**规范化分支 ① 实际很少触发**——但代码必须处理，否则长密钥会出错。

---

## 4. 状态文件：格式、语义与状态机

`~/.google_authenticator` 是整个系统的**唯一持久化状态**，也是 CLI 与 PAM 之间唯一的"接口"。`FILEFORMAT` 是其规范文档。文件结构严格固定：

```
<base32 密钥>\n                          ← 第 1 行：共享密钥
" TOTP_AUTH\n   或   " HOTP_COUNTER N\n  ← 模式标记（二选一）
" DISALLOW_REUSE [ts1 ts2 ...]\n         ← 可选：TOTP 防重放列表
" RATE_LIMIT N M [ts...] \n              ← 可选：速率限制 + 时间戳历史
" WINDOW_SIZE W\n                        ← 可选：窗口大小（默认 3）
" STEP_SIZE S\n                          ← 可选：步长（默认 30，范围 1..60）
" TIME_SKEW <skew>\n                     ← 可选：已知时钟偏移（自动学习）
" RESETTING_TIME_SKEW <ts±skew ...>\n    ← 可选：正在进行的偏移学习
" LAST0 .. LAST9 <rhost timestamp>\n     ← 可选：grace_period 最近登录
<8位数字>\n                              ← scratch 码（应急一次性码）
<8位数字>\n
...
```

### 4.1 格式约束（`open_secret_file` + `read_file_contents`）

- **必须 NUL-free**：`memchr(buf, 0, filesize)` 检测（`pam_google_authenticator.c:530`）。因为整个解析器基于 `strstr`/`strcspn` 等 C 字符串函数。
- **大小限制**：1B ≤ size ≤ 64KB（`pam_google_authenticator.c:493`）；读取后再防御性加 1MB 上限（`read_file_contents:509`）。
- **必须常规文件**：`S_ISREG(st_mode)`（`pam_google_authenticator.c:467`）——拒绝符号链接、设备文件、管道。
- **权限检查**：`(st_mode & 03777 & ~allowed_perm)` 必须为 0（`pam_google_authenticator.c:472`）。默认 `allowed_perm = 0600`，即只允许 owner 读写。
- **属主检查**：`st_uid` 必须等于登录用户的 uid（除非 `no_strict_owner`）。

### 4.2 选项行的解析规则

所有选项行以 `" `（双引号+空格）开头，这一约定（`FILEFORMAT`）**数学上保证**了选项名不会与 Base32 密钥或 scratch 码冲突：

- Base32 字母表只有 `A-Z2-7`，不含 `"`；
- scratch 码是纯数字 8 位。

解析函数 `get_cfg_value()` / `set_cfg_value()`（`pam_google_authenticator.c:834, 861`）用 `" KEY` 前缀匹配，KEY 必须以下划线或行尾结束，避免前缀歧义（如 `RATE_LIMIT` 不误匹配 `RATE_LIMITER`）。

### 4.3 三种状态机的语义

| 状态字段 | 触发 | 读取逻辑 | 写入逻辑 |
|----------|------|----------|----------|
| `HOTP_COUNTER N` | CLI `-c` | `N` 为下一个期望的计数器 | 验证成功后 `N += matched_offset + 1`；失败时若未设 `no_increment_hotp` 则 `N += 1` |
| `DISALLOW_REUSE ts...` | CLI `-d` | 列表中存在当前 `tm` 则拒绝 | 成功登录后追加当前 `tm`；过期项（超出 window）自动清理 |
| `RATE_LIMIT N M ts...` | CLI `-r/-R` | 窗口 [now-M, now] 内尝试次数 > N 则拒绝 | 每次都追加当前时间戳，剪枝过期项 |
| `TIME_SKEW s` | 自动学习 | `tm += s` 作为有效时间步 | 连续 3 次 ±25min 内的偏移一致时写入平均值 |
| `RESETTING_TIME_SKEW` | 自动学习中间态 | 维护最近 3 个 `(tm, skew)` 对 | 学习未完成时记录进度，完成后清空 |

---

## 5. PAM 认证主流程逐行精读

入口 `pam_sm_authenticate`（`pam_google_authenticator.c:2257`）只是个壳，真正的逻辑在 `google_authenticator()`（`:1905`）。这是整个项目最复杂、最值得精读的函数。

### 5.1 完整流程图

```
google_authenticator(pamh, argc, argv)
  │
  ├─ ① parse_args()                           :1838  解析 PAM 配置参数
  │
  ├─ ② get_user_name()                        :163   pam_get_user()
  ├─ ② get_secret_filename()                  :212   展开 ~/${USER}/${HOME}
  │
  ├─ ③ drop_privileges()                      :373   setfsuid/setfsgid 降权
  │
  ├─ ④ open_secret_file()                     :436   权限/属主/大小检查
  ├─ ④ read_file_contents()                   :504   读入 + NUL 检测
  │
  ├─ ⑤ rate_limit()                           :1002  【状态修改 early_updated】
  ├─ ⑤ get_shared_secret()                    :775   base32 解码首行
  ├─ ⑤ get_hotp_counter()                     :983   读 HOTP 模式
  │
  ├─ ⑥ within_grace_period()?                 :1975  → 直接 PAM_SUCCESS（不问 OTP）
  │
  ├─ ⑦ 是否要问 OTP？                           :1984
  │     条件: !stopped_by_rate_limit && (secret || nullok != SECRETNOTFOUND)
  │
  ├─ ⑧ 4-mode 密码获取循环                     :1994  (见 §5.3)
  │     ├─ check_scratch_codes()              :1186
  │     ├─ check_counterbased_code()          :1767  (HOTP)
  │     └─ check_timebased_code()             :1547  (TOTP)
  │
  ├─ ⑨ forward_pass 处理                       :2137  回写 PAM_AUTHTOK
  │
  ├─ ⑩ HOTP 失败递增计数器                      :2155
  │
  ├─ ⑪ grace_period 记录登录                   :2167  update_logindetails()
  │
  ├─ ⑫ nullok + 文件不存在 → PAM_IGNORE         :2185
  │
  ├─ ⑬ 持久化状态                              :2190  write_file_contents()（原子写）
  │
  └─ ⑭ 恢复权限 + 清零所有敏感缓冲              :2215  explicit_bzero × 多处
```

### 5.2 降权读文件——为什么用 `setfsuid` 而不是 `seteuid`

`drop_privileges()` → `setuser()` → `setfsuid()`（`pam_google_authenticator.c:332-351`）：

```c
#ifdef HAVE_SETFSUID
  int old_uid = setfsuid(uid);
  if (uid != setfsuid(uid)) {  // 二次设置验证
    setfsuid(old_uid);
    return -1;
  }
#else
  int old_uid = geteuid();
  if (old_uid != uid && seteuid(uid)) {
    return -1;
  }
#endif
```

**`setfsuid` 的优势：** 它**只影响文件系统访问的 UID 判定**，不改进程的真实/有效 UID。这对 PAM 模块至关重要——模块可能需要在降权读用户文件的同时，保留 root 权限去访问其他系统资源（如 syslog）。

**二次设置验证**（`if (uid != setfsuid(uid))`）：`setfsuid` 的返回值是**之前的** fsuid。调用两次后，第二次的返回值应该等于目标 uid；若不等说明设置失败，恢复原值。这是 Linux man page 推荐的用法（man 2 setfsuid）。

**`#ifdef linux #error`**（`:343`）：在 Linux 上若没有 `setfsuid`，编译直接失败——因为 Linux 一定有此系统调用，缺失说明配置错误。

**fallback 链**（`:414-428`）：先尝试"先改 gid 再改 uid"（典型 root 场景），失败则"先改 uid 再改 gid"（非 root 调用方）。注释解释：PAM 模块的调用上下文多种多样，必须覆盖所有情况。

### 5.3 4-mode 密码获取循环（最巧妙的设计）

这是整个模块最 tricky 的部分（`pam_google_authenticator.c:1994-2132`）。为什么需要 4 次循环？因为存在**密码与 OTP 拼接**的场景（`forward_pass`），而拼接串无法区分是"密码+6位OTP"还是"2位密码+8位scratch"。

```
mode=0: 从 PAM_AUTHTOK 取密码，尾部按 6 位 OTP 解析
mode=1: 从 PAM_AUTHTOK 取密码，尾部按 8 位 scratch 解析
mode=2: 主动 prompt 用户，尾部按 6 位 OTP 解析
mode=3: 主动 prompt 用户，尾部按 8 位 scratch 解析
```

**mode 与 `pass_mode` 的交互矩阵：**

| `pass_mode` | mode 0/1（用 first_pass） | mode 2/3（prompt） |
|-------------|---------------------------|---------------------|
| `PROMPT`（默认） | 跳过 | 执行（prompt 一次） |
| `TRY_FIRST_PASS` | 尝试 | 失败则 fallback prompt |
| `USE_FIRST_PASS` | 尝试 | 跳过（绝不 prompt） |

**关键不变量**（`:2000-2011`）：循环开始前，`updated` 必须为 0、`pw` 必须为 NULL。否则说明内部逻辑错误，立即 `PAM_AUTH_ERR` 终止。这条防御性断言也被单元测试覆盖。

**`saved_pw` 的作用**（`:2034`）：在 TRY_FIRST_PASS + forward_pass 场景，mode 2 和 mode 3 都需要 prompt，但**只 prompt 一次**——`saved_pw` 缓存第一次 prompt 的结果，第二次复用。否则会问用户两遍密码。

### 5.4 密码/OTP 切分逻辑（`:2046-2089`）

```c
const int pw_len = strlen(pw);
const int expected_len = mode & 1 ? 8 : 6;   // scratch=8, OTP=6
char ch;
// 验证尾部 expected_len 个字符是否合法：
//   OTP: 6 位 0-9
//   scratch: 8 位，首位 1-9
if (pw_len < expected_len ||
    (ch = pw[pw_len - expected_len]) > '9' ||
    ch < (expected_len == 8 ? '1' : '0')) {
  goto invalid;
}
// strtol 解析尾部数字
const long l = strtol(pw + pw_len - expected_len, &endptr, 10);
...
const int code = (int)l;
memset(pw + pw_len - expected_len, 0, expected_len);  // 从密码中抹掉 OTP
```

**注意 `memset` 抹除**：切出 OTP 后，`pw` 尾部的数字被立即清零——这样 `pw` 就只剩"密码部分"，可以安全地通过 `pam_set_item(PAM_AUTHTOK)` 转发给下一个 PAM 模块（forward_pass 场景）。

**OpenSSH "假密码" 检测**（`:2054-2059`）：

```c
if (pw_len > 0 && pw[0] == '\b') {
  log_message(LOG_INFO, pamh,
              "Dummy password supplied by PAM."
              " Did OpenSSH 'PermitRootLogin <anything but yes>' ...");
}
```

OpenSSH 在某些配置下（如 `PermitRootLogin prohibit-password`）会向 PAM 栈塞一个固定假密码 `"\b\n\r\177INCORRECT"`，以避免密码被转发到不安全的栈。本模块检测到后记录日志——这是一个非常隐蔽的兼容性 hack。

---

## 6. 三种验证码的校验算法

### 6.1 Scratch 码（应急一次性码）—— `check_scratch_codes()`

最简单的一种（`:1186-1248`）：

```c
// 跳过首行（密钥）
char *ptr = buf + strcspn(buf, "\n");

for (;;) {
  while (*ptr == '\r' || *ptr == '\n') ptr++;   // 跳空行
  if (*ptr == '"') { ptr += strcspn(ptr, "\n"); continue; }  // 跳选项行

  const int scratchcode = strtoul(ptr, &endptr, 10);
  // 合法性：必须是 8 位数字（10,000,000 ≤ x < 100,000,000）
  if (scratchcode < 10*1000*1000 || scratchcode >= 100*1000*1000) break;

  if (scratchcode == code) {
    // ★ 使用即删除：memmove 覆盖该行
    memmove(ptr, endptr, strlen(endptr) + 1);
    memset(strrchr(ptr, '\000'), 0, endptr - ptr + 1);  // 清除残留
    *updated = 1;
    return 0;  // 成功
  }
  ptr = endptr;
}
return 1;  // 未匹配，继续尝试其他码型
```

**"使用即删除"** 是 scratch 码的核心语义。删除用 `memmove` 移动后续内容覆盖，再 `memset` 清零尾部残留——防止密钥信息在堆上残留。

### 6.2 HOTP（计数器）—— `check_counterbased_code()`

```c
// :1791
for (int i = 0; i < window; ++i) {
  const unsigned int hash = compute_code(secret, secretLen, hotp_counter + i);
  if (hash == (unsigned int)code) {
    // ★ 推进计数器到匹配位置 + 1
    snprintf(counter_str, ..., "%ld", hotp_counter + i + 1);
    set_cfg_value(pamh, "HOTP_COUNTER", counter_str, buf);
    *updated = 1;
    return 0;
  }
}
*must_advance_counter = 1;  // 窗口内无匹配，外层会 +1
return 1;
```

**窗口方向：** HOTP 只向后看（`i = 0..window-1`，即 counter 和未来的 window-1 个），不像 TOTP 有"过去"的概念——因为计数器单调递增。

**"未来码"的工程意义：** 用户可能用 App 生成了码但没登录（比如网络断了），下次登录时 App 的计数器已经超前。window 允许接受超前 ≤ window-1 的码，避免永久失步。

**失败也要推进**（`:2155-2162`）：若 HOTP 验证失败且未设 `no_increment_hotp`，计数器仍 +1。这是防暴力：攻击者每次试错都会推进计数器，让真正的用户更难追上——所以 README 强烈建议 HOTP 模式配 `no_increment_hotp`。

### 6.3 TOTP（时间）—— `check_timebased_code()`

最复杂，包含窗口扫描和时钟漂移自愈（`:1547-1617`）：

```c
// ① 计算当前时间步
const int tm = get_timestamp(...);   // floor(now / step_size)

// ② 读已知时钟偏移
int skew = 0;
const char *skew_str = get_cfg_value(pamh, "TIME_SKEW", *buf);
if (skew_str) skew = strtol(skew_str, NULL, 10);

// ③ 窗口扫描（window 默认 3）
const int window = window_size(...);  // [1, 100]
for (int i = -((window-1)/2); i <= window/2; ++i) {
  const unsigned int hash = compute_code(secret, secretLen, tm + skew + i);
  if (hash == (unsigned int)code) {
    return invalidate_timebased_code(tm + skew + i, ...);  // ④ 防重放
  }
}

// ⑤ 窗口内未命中 → 尝试时钟漂移自愈（除非 noskewadj）
if (!params->noskewadj) {
  skew = 1000000;  // 哨兵值
  for (int i = 0; i < 25*60; ++i) {  // 扫描 ±25 分钟
    unsigned int hash = compute_code(secret, secretLen, tm - i);
    if (hash == code && skew == 1000000) skew = -i;
    hash = compute_code(secret, secretLen, tm + i);
    if (hash == code && skew == 1000000) skew = i;
  }
  if (skew != 1000000) {
    return check_time_skew(...);  // ⑥ 记录/学习偏移
  }
}
```

**窗口扫描的非对称区间** `[-((window-1)/2), window/2]`（`:1583`）：

| window | 区间 | 含义 |
|--------|------|------|
| 3（默认） | [-1, +1] | 前 1 步 + 当前 + 后 1 步 |
| 17（大窗口） | [-8, +8] | ±4 分钟（step=30s） |
| 2 | [0, +1] | 当前 + 后 1 步 |
| 1 | [0, 0] | 仅当前 |

这是 `(window-1)/2` 向下取整、`window/2` 向下取整的结果——故意让"未来"方向比"过去"多覆盖一些（当 window 为偶数时），因为时钟稍快比稍慢更常见。

**漂移扫描的 ±25 分钟**（`25*60`，但单位是**时间步**而非秒——`:1596`）：实际是 ±25 分钟 = ±50 个 step（step=30s）。注释指出这是个**时序常量化**的反制：

> "Don't short-circuit out of the loop as the obvious difference in computation time could be a signal that is valuable to an attacker."

即使找到匹配也继续扫完整个范围，让所有失败/成功的响应时间一致——防止通过响应延迟推断偏移量。

---

## 7. 速率限制 / 防重放 / 时间漂移自愈

### 7.1 RATE_LIMIT（`:1002-1125`）

语法：`" RATE_LIMIT N M ts1 ts2 ...`，含义"每 M 秒最多 N 次尝试"，后跟历史时间戳。

**算法：**

```
1. 解析 N、M、历史时间戳列表
2. 排序时间戳（qsort）
3. 剪枝：保留 [now-M, now] 区间内的
4. 若区间内数量 > N → 拒绝（exceeded=1）
5. 追加 now 到列表
6. 写回文件（set_cfg_value），标记 updated
```

**注意时序：** `rate_limit` 在读取密钥**之前**执行（`:1960`），且它的状态修改用单独的 `early_updated` 标记（`:1927`）。这是因为：即使后续 OTP 验证失败，速率限制的时间戳记录也必须持久化——否则攻击者可以无限重试。

**状态写入的原子性** 见 §8.3。

### 7.2 DISALLOW_REUSE（`:1283-1379`）

防重放：TOTP 码用过后记入黑名单，同一码 30 秒内不可再用。

```c
// 遍历黑名单
for (char *ptr = disallow; *ptr; ) {
  const int blocked = strtoul(ptr, &endptr, 10);
  if (tm == blocked) {
    // ★ 命中黑名单 → 拒绝，并警告可能 MITM
    log_message(LOG_ERR, ..., "Warning! This might mean, you are currently "
                "subject to a man-in-the-middle attack.");
    return -1;
  }
  // 过期项清理：超出 window 范围的 blocked 移除
  if (blocked - tm >= window || tm - blocked >= window) {
    memmove(ptr, endptr, ...);  // 删除
  } else {
    ptr = endptr;
  }
}
// 追加当前 tm
snprintf(..., " %d", tm);
set_cfg_value("DISALLOW_REUSE", disallow, buf);
```

**MITM 警告的逻辑：** 同一个 30 秒窗口内出现两次相同 OTP，最可能的解释是中间人截获了第一次登录的码并重放——所以日志特别警告。这是从"防重放"延伸到"入侵检测"的设计。

### 7.3 TIME_SKEW 自动学习（`check_time_skew`，`:1413-1541`）

这是一个**用户友好但略降安全性**的特性：用户连续 3 次以同样的时钟偏移登录，系统就记住这个偏移，后续不再需要漂移扫描。

**学习算法：**

```
1. 维护一个 3 元组队列 [(tm1,skew1), (tm2,skew2), (tm3,skew3)]
2. 每次漂移匹配成功，追加 (当前tm, 当前skew)
3. 检查 3 元组是否满足：
   a. 时间戳连续（tms[i] <= tms[i-1]+2，即每两次间隔 ≤ 2 个 step）
   b. 偏移稳定（|skew[i] - skew[i-1]| ≤ 1）
4. 满足 → 写入 TIME_SKEW = avg(skew)，清空 RESETTING_TIME_SKEW
5. 不满足 → 更新 RESETTING_TIME_SKEW 继续学习
```

**"3"的选择**（`:1428` 注释）：故意选 3，使其**不会触发默认 RATE_LIMIT**（默认 3 次/30 秒）。这是个精心设计的协同——用户重试 3 次校时刚好不被限流。

---

## 8. 权限模型与安全加固

### 8.1 文件权限的三重检查

```
① S_ISREG(st_mode)                         → 必须常规文件（防 symlink/设备）
② (st_mode & 03777 & ~allowed_perm) == 0   → 权限位严格（防 group/other 读写）
③ st_uid == uid                             → 属主必须是登录用户（防偷梁换柱）
④ 1 ≤ st_size ≤ 64KB                       → 大小合理（防恶意构造）
⑤ 无 NUL 字节                              → 内容合法（防字符串解析器崩溃）
```

任一失败即拒绝。这些检查在 `open_secret_file` 和 `read_file_contents` 中完成。

### 8.2 `nobody` 兜底降权

```c
// :1936-1945
const char* drop_username = username;
if (uid == -1) {  // 用户不存在
  drop_username = nobody;  // "nobody"
  if (parse_user(pamh, drop_username, &uid)) {
    goto out;  // 连 nobody 都没有 → 拒绝
  }
}
```

如果登录用户名在系统中不存在（如某些 PAM 集成场景），降权到 `nobody` 而非以 root 身份操作文件——最小权限原则。

### 8.3 原子写入与 TOCTOU 防护（`write_file_contents`，`:639-769`）

这是整个模块最精密的安全函数之一：

```c
// ① 创建临时文件（mkstemp，umask 077）
char *tmp_filename = "...~XXXXXX";
umask(077);
fd = mkstemp(tmp_filename);
fchmod(fd, 0400);

// ② TOCTOU 检查：确认原文件未被篡改
struct stat sb;
stat(secret_filename, &sb);
if (sb.st_ino != orig_stat->st_ino ||
    sb.st_size != orig_stat->st_size ||
    sb.st_mtime != orig_stat->st_mtime) {
  err = EAGAIN;  // 文件变了 → 拒绝写
  goto cleanup;
}

// ③ 写入 + fsync（强制落盘）
full_write(fd, buf, ...);
set_selinux_context(fd);
fsync(fd);
close(fd);

// ④ 二次校验临时文件大小
stat(tmp_filename, &st);
if (st.st_size != strlen(buf)) { err = EAGAIN; goto cleanup; }

// ⑤ 原子替换
rename(tmp_filename, secret_filename);
```

**为什么需要 TOCTOU 检查（步骤②）？** 注释解释（`:678-679`）：

> "Make sure the secret file is still the same. This prevents attackers from opening a lot of pending sessions and then reusing the same scratch code multiple times."

攻击场景：攻击者打开多个并发 SSH 会话，每个会话读到相同的 scratch 码列表，然后在不同会话里用同一个 scratch 码——若无 TOCTOU 检查，可能多个会话都成功（因为它们各自基于读入时的快照判断）。通过比较 `inode/size/mtime`，确保"读"和"写"之间文件未被其他会话改过。

**残留的微小竞态：** 注释诚实承认（`:681-682`）：

> "except for the brief race condition between this stat and the `rename` below"

`stat` 和 `rename` 之间仍有极小窗口，但 `rename` 是原子的，且文件已锁，实际可利用性极低。

**SELinux 标签**（`:587-635`）：写入后通过 `fsetfilecon` 设置 `auth_home_t` 类型，确保 SELinux 策略允许 PAM 模块后续读取（否则 enforcing 模式会拒绝）。仅在 `HAVE_SELINUX` 编译时启用。

### 8.4 内存清零的系统性应用

`explicit_bzero`（`util.c:42-47`）在所有敏感缓冲的生命周期终点被调用：

| 位置 | 清零对象 |
|------|----------|
| `compute_code` 末尾 | `val[8]`（计数器）、`hash[20]`（HMAC 输出） |
| `hmac_sha1` 末尾 | `hashed_key`、`sha`、`tmp_key` |
| `read_file_contents` 错误路径 | `buf`（含密钥的明文文件内容） |
| `get_shared_secret` 失败 | `secret`（base32 解码后的二进制密钥） |
| `google_authenticator` 清理段 | `buf`、`secret`、`pw`、`saved_pw` |
| `check_scratch_codes` 删除后 | 尾部残留 |

**为什么用 `explicit_bzero` 而非 `memset`？** 普通 `memset` 会被编译器当作"死代码"优化掉（因为缓冲随后不再被读）。`explicit_bzero` 内部有 `asm volatile ("":::"memory")` 内存屏障（`util.c:46`），阻止优化。现代 glibc 已原生提供此函数（`configure.ac:26` 检测）。

### 8.5 日志的安全级别

```c
static void log_message(int priority, pam_handle_t *pamh, ...) {
  ...
  if (priority == LOG_EMERG) {
    _exit(1);  // EMERG 级别直接退出进程
  }
}
```

`LOG_EMERG`（如无法恢复权限，`:2231`）会立即 `_exit(1)`——因为继续运行可能导致以错误权限暴露敏感数据。这是"fail-closed"原则。

**日志脱敏：** 所有日志只记录用户名、文件名、错误码，**从不记录 OTP、密码、密钥**。即便 `debug` 模式也只输出"shared secret processed"，不输出密钥本身。

---

## 9. CLI（provisioning）实现细节

`google-authenticator.c` 是用户态 CLI，负责生成密钥和初始状态文件。

### 9.1 密钥生成的熵源

```c
// :766-775
int fd = open("/dev/urandom", O_RDONLY);
uint8_t buf[SECRET_BITS/8 + MAX_SCRATCHCODES*BYTES_PER_SCRATCHCODE];  // 20 + 40 = 60 字节
if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
  goto urandom_failure;
}
```

一次性读 60 字节：20 字节做密钥，40 字节做 10 个 scratch 码的种子（每个 4 字节）。

> **为什么 `/dev/urandom` 而非 `/dev/random`？** Linux 的 `/dev/urandom` 在熵池初始化后是密码学安全的（即使熵估计低），且不会阻塞。`/dev/random` 会阻塞，导致 CLI 在启动早期或虚拟机中卡死。这是 Linux 内核邮件列表和 `getrandom(2)` man page 反复澄清的常见误解。

### 9.2 scratch 码的生成与"前导零"处理

```c
// :820-845
for (int i = 0; i < emergency_codes; ++i) {
  int scratch = 0;
  for (int j = 0; j < BYTES_PER_SCRATCHCODE; ++j) {  // 4 字节 → 32 位
    scratch = 256*scratch + buf[...];
  }
  scratch = (scratch & 0x7FFFFFFF) % modulus;  // 模 10^8
  if (scratch < modulus/10) {  // ★ 首位为 0（即 < 10^7）
    // 重新读 4 字节重生成——scratch 码必须恰好 8 位
    if (read(fd, ...) != BYTES_PER_SCRATCHCODE) goto urandom_failure;
    goto new_scratch_code;
  }
  printf("  %08d\n", scratch);
  snprintf(..., "%08d\n", scratch);
}
```

**"前导零"问题：** scratch 码必须是恰好 8 位数字。若随机数模 10^8 后 < 10^7（即首位是 0），`%08d` 会输出前导零（如 `09123456`），但 PAM 端用 `strtoul` 解析会丢掉前导零，导致"用户抄的是 09123456，文件里存的是 9123456"的歧义。所以 CLI 直接重生成。

> 注意：`PAM` 端校验 scratch 时要求 `scratchcode >= 10*1000*1000`（`:1217`），即首位 1-9。CLI 和 PAM 两端约定一致——这是"文件契约"的又一体现。

### 9.3 otpauth:// URL 与 QR 码

```c
// :159-184
asprintf(&url, "otpauth://%cotp/%s?secret=%s", totp, encodedLabel, secret);
if (issuer) {
  asprintf(&newUrl, "%s&issuer=%s", url, encodedIssuer);
}
```

格式遵循 [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)：`otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER`。

**QR 码的运行时 dlopen**（`:195-318`）：

```c
void *qrencode = dlopen("libqrencode.so.2", RTLD_NOW | RTLD_LOCAL);
if (!qrencode) qrencode = dlopen("libqrencode.so.3", ...);
if (!qrencode) qrencode = dlopen("libqrencode.so.4", ...);
if (!qrencode) qrencode = dlopen("libqrencode.3.dylib", ...);  // macOS
if (!qrencode) qrencode = dlopen("libqrencode.4.dylib", ...);
if (!qrencode) return 0;  // 优雅降级：只打印 URL
```

不硬链接 libqrencode，而是运行时按版本号逐一尝试 dlopen——这让二进制可在有无 libqrencode 的系统上都运行。ANSI 反色、Unicode 半块字符（▀▄█）等多种渲染模式适配不同终端。

### 9.4 临时文件 + rename 的原子写

```c
// :869-856
char* tmp_fn = malloc(strlen(secret_fn) + 3);
snprintf(tmp_fn, size, "%s~", secret_fn);
fd = open(tmp_fn, O_WRONLY|O_EXCL|O_CREAT|O_NOFOLLOW|O_TRUNC, 0400);
write(fd, secret, strlen(secret));
rename(tmp_fn, secret_fn);  // 原子替换
```

`O_EXCL`（文件已存在则失败）+ `O_NOFOLLOW`（不跟随符号链接）+ `O_CREAT` 的组合，加上 `rename` 的原子性，确保：
- 不会覆盖已存在文件（防止符号链接攻击）；
- 写入过程对读者不可见（要么旧文件、要么新文件，无中间态）；
- 失败时旧文件完好。

注意 CLI 这里权限是 `0400`（只读）——但 PAM 端 `write_file_contents` 用 `mkstemp` + `umask(077)` + `fchmod(0400)`，更严格。

---

## 10. 构建系统、测试与可观测性

### 10.1 构建系统的三个变体

`Makefile.am` 为同一个 `pam_google_authenticator.c` 构建了三个变体：

```makefile
# ① 生产 PAM 模块（导出 pam_sm_* ）
pam_google_authenticator_la_CFLAGS = $(AM_CFLAGS) $(SELINUX_CFLAGS)
pam_google_authenticator_la_LDFLAGS = ... -export-symbols-regex "pam_sm_(...)"

# ② 测试用副本（额外 -DTESTING=1，解除隐藏）
libpam_google_authenticator_testing_la_CFLAGS = $(AM_CFLAGS) -DTESTING=1 ...

# ③ Demo（额外 -DDEMO=1，重定义 log_message）
examples_demo_CFLAGS = $(AM_CFLAGS) -DDEMO=1
```

`-DTESTING=1` 和 `-DDEMO=1` 通过条件编译改变行为：

```c
// pam_google_authenticator.c:96-106
#if defined(DEMO) || defined(TESTING)
static char* error_msg = NULL;  // 内存里存日志，供测试断言
const char *get_error_msg(void) { ... }
#endif

// :1384-1389
#ifdef TESTING
int compute_code(...) __attribute__((visibility("default")));  // 导出供测试
#else
static  // 生产环境隐藏
#endif
int compute_code(...) { ... }
```

`TESTING` 还把 `get_time()` 替换为可注入的 `current_time`（`:814-823`）：

```c
#ifdef TESTING
static time_t current_time;
void set_time(time_t t) { current_time = t; }  // 测试注入
static time_t get_time(void) { return current_time; }
#else
static time_t get_time(void) { return time(NULL); }  // 生产：真实时间
#endif
```

这让单元测试可以精确控制时间步，验证窗口边界、防重放、漂移学习等时间相关逻辑。

### 10.2 单元测试覆盖的场景

`tests/pam_google_authenticator_unittest.c`（630 行）通过 `dlopen` 加载测试用 .so，跑了 **8 种 OTP 传递模式 × 十余个功能点**：

**8 种 OTP 模式**（`:263-336`）覆盖 PAM 配置矩阵：

| mode | 配置 | conv 行为 | 期望 prompt 次数 |
|------|------|-----------|------------------|
| 0 | 默认（PROMPT） | TWO_PROMPTS | 1 |
| 1 | forward_pass | COMBINED_PROMPT | 1 |
| 2 | use_first_pass | COMBINED_PASSWORD | 0 |
| 3 | use_first_pass + forward_pass | COMBINED_PASSWORD | 0 |
| 4 | try_first_pass | COMBINED_PASSWORD | 2（first_pass 失败 + prompt） |
| 5 | try_first_pass + forward_pass | COMBINED_PASSWORD | 2 |
| 6 | try_first_pass | TWO_PROMPTS | 1 |
| 7 | try_first_pass + forward_pass | COMBINED_PROMPT | 1 |

每个 mode 内测试：失败登录、位数校验、空响应、缺文件、nullok、成功登录、STEP_SIZE、WINDOW_SIZE、DISALLOW_REUSE（含过期清理）、RATE_LIMIT（含状态验证）、TIME_SKEW、noskewadj、scratch 码、HOTP 成功/失败/未来码。

**已知测试向量**（`:172-213`）：HMAC-SHA1 用 RFC 4646 测试向量验证正确性。Base32 用 `"Hello world..."` ↔ `"JBSWY3DPEB3W64TMMQXC4LQA"` 验证。

### 10.3 可观测性

- **syslog**：所有日志走 `openlog(LOG_AUTHPRIV)`（`:122`），`LOG_AUTHPRIV` 让日志在多数系统上受限访问（只 root 可见）。
- **debug 选项**：`PAM` 配置加 `debug` 后，输出详细诊断（用户名、文件权限、scratch 删除、时间漂移调整等），但**绝不输出密钥**。
- **conv_error**（`:1137`）：写入失败时通过 PAM 对话向用户显示系统错误（如 `EROFS`、`ENOSPC`），而非静默失败——帮助用户理解"为什么登不进去"。

### 10.4 utc-time 服务（时间校准辅助）

`utc-time/main.py` 是一个 Google App Engine 的 Flask 微服务（35 行），返回当前 UTC 时间戳，供 `totp.html`（浏览器端 TOTP 调试器）计算本地时钟漂移。它与 PAM 模块无直接关系，是**开发调试辅助工具**。

---

## 11. 已知边界、攻击面与设计权衡

### 11.1 明确的安全边界

| 场景 | 是否支持 | 说明 |
|------|----------|------|
| 集群/多机同步 | ❌ | 状态文件在用户家目录，无同步机制 |
| 集中吊销 | ❌ | 删除 `~/.google_authenticator` 即吊销，但无 API |
| 离线 App seed 备份 | ❌ | 密钥只在生成时显示一次 |
| WebAuthn/PUSH/SMS | ❌ | 仅 TOTP/HOTP/scratch |
| 多设备（同密钥） | ✅ | 多设备扫描同一 QR 即可 |
| 加密家目录 | ⚠️ | 需配 `secret=` 指向未加密路径 |
| NFS 家目录 | ✅ | `drop_privileges` 降权后访问 |

### 11.2 攻击面与缓解

**1. 状态文件被读** → 文件权限 0600 + 属主检查（§8.1）。
**2. 状态文件被改** → TOCTOU 检查 + 原子 rename（§8.3）。
**3. OTP 暴力** → RATE_LIMIT（默认可配）+ 窗口限制（默认 3）。
**4. OTP 重放** → DISALLOW_REUSE（可选）+ scratch 一次性。
**5. 时序侧信道** → 漂移扫描全程执行不短路（§6.3）；HMAC-SHA1 实现无数据相关分支。
**6. 内存残留取证** → 系统 `explicit_bzero`（§8.4）。
**7. 符号链接/设备文件攻击** → `S_ISREG` + `O_NOFOLLOW`（CLI）。
**8. 临时文件竞争** → `mkstemp` + `O_EXCL`（§8.3, §9.4）。
**9. core dump 泄露密钥** → demo.c 设置 `RLIMIT_CORE=0`（`:166`）；生产 PAM 依赖宿主进程。

### 11.3 已知的"非漏洞但需注意"点

**a. `allow_readonly` 的危险**（README 明确警告）：若启用，攻击者填满磁盘后，状态文件无法写回 → DISALLOW_REUSE / RATE_LIMIT / scratch 删除全部失效 → OTP 可重放。仅在确实需要"宁可降级也要能登录"的场景启用。

**b. `no_strict_owner` 的危险**：允许任何属主的文件被当作密钥文件。仅用于非 root 守护进程读取非自身属主文件的场景。

**c. `noskewadj` 的取舍**：禁用漂移自愈可提升安全性（不接受 ±25 分钟的偏移码），但牺牲用户友好性。严格安全环境建议开启。

**d. 状态文件的"软"大小限制**：`FILEFORMAT` 说"currently limited to 1kB"，但代码实际检查 `64KB`（`:493`）。文档与代码不一致——若依赖 1KB 限制做容量规划需注意。

**e. grace_period 的 IP 信任**：grace_period 基于 `PAM_RHOST`，若应用层伪造 RHOST，可绕过二次验证。仅在可信应用（如 sshd 正确设置 RHOST）下使用。

### 11.4 设计权衡总结

| 决策 | 收益 | 代价 |
|------|------|------|
| 自带 SHA-1/HMAC/Base32 | 零依赖、部署简单 | 无法享受系统库的安全审计与 CVE 修复 |
| 文件即协议（CLI↔PAM） | 极简、可调试、无 IPC | 无集群同步、无集中管理 |
| 单用户单文件 | 隔离清晰、权限模型简单 | 无组织级密钥管理 |
| 时序常量化的漂移扫描 | 抗侧信道 | 失败时 CPU 开销大（5000 次 HMAC） |
| `setfsuid` 而非 `seteuid` | 降权时保留 syslog 等能力 | 代码更复杂、Linux 专属 |
| 运行时 dlopen libqrencode | 二进制可移植 | 启动时有微小开销 |

---

## 附录 A：关键代码索引（按阅读顺序）

| 主题 | 文件:行 | 函数/符号 |
|------|---------|-----------|
| OTP 计算（核心） | `pam_google_authenticator.c:1390` | `compute_code()` |
| HMAC-SHA1 | `hmac.c:24` | `hmac_sha1()` |
| SHA-1 主变换 | `sha1.c:107` | `sha1_transform()` |
| Base32 解码 | `base32.c:22` | `base32_decode()` |
| TOTP 时间步 | `pam_google_authenticator.c:974` | `get_timestamp()` |
| 主认证流程 | `pam_google_authenticator.c:1905` | `google_authenticator()` |
| 4-mode 密码循环 | `pam_google_authenticator.c:1994` | （内联于 `google_authenticator`） |
| 降权 | `pam_google_authenticator.c:332,373` | `setuser()`/`drop_privileges()` |
| 文件权限检查 | `pam_google_authenticator.c:436` | `open_secret_file()` |
| 原子写 | `pam_google_authenticator.c:639` | `write_file_contents()` |
| Scratch 校验 | `pam_google_authenticator.c:1186` | `check_scratch_codes()` |
| TOTP 校验 | `pam_google_authenticator.c:1547` | `check_timebased_code()` |
| HOTP 校验 | `pam_google_authenticator.c:1767` | `check_counterbased_code()` |
| RATE_LIMIT | `pam_google_authenticator.c:1002` | `rate_limit()` |
| DISALLOW_REUSE | `pam_google_authenticator.c:1283` | `invalidate_timebased_code()` |
| TIME_SKEW 学习 | `pam_google_authenticator.c:1413` | `check_time_skew()` |
| CLI 密钥生成 | `google-authenticator.c:766` | （`main` 内联） |
| CLI OTP 生成 | `google-authenticator.c:50` | `generateCode()` |

## 附录 B：RFC 合规性核对

| RFC 要求 | 实现位置 | 合规 |
|----------|----------|------|
| RFC 4226 §5.1 HMAC-SHA1 | `hmac.c` | ✅ |
| RFC 4226 §5.2 计数器大端 8 字节 | `compute_code` `val[8]` 循环 | ✅ |
| RFC 4226 §5.3 动态截断 `offset = hs[19] & 0xf` | `compute_code:1398` | ✅ |
| RFC 4226 §5.3 `& 0x7FFFFFFF` | `compute_code:1405` | ✅ |
| RFC 4226 §5.3 模 10^digit | `compute_code:1406`（digit=6） | ✅ |
| RFC 4226 §7.2 建议 digit=6-8 | scratch=8, OTP=6 | ✅ |
| RFC 6238 §4.2 `T = floor((Tnow - T0)/X)`，X=30, T0=0 | `get_timestamp` | ✅ |
| RFC 6238 §5.2 步长建议 30s | `STEP_SIZE` 默认 30 | ✅ |

---

*本文基于 `google-authenticator-libpam` 1.11 源码生成。所有 `file:line` 引用可在对应文件中直接定位。如需验证算法正确性，运行 `make check` 即可执行 630 行单元测试覆盖的全部场景。*
