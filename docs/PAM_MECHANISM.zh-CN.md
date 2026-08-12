# Google Authenticator PAM 模块技术详解

> 版本：基于 google-authenticator-libpam **1.11** 源码  
> 目标读者：需要理解 PAM 二因子认证实现原理、阅读源码或进行生产集成的工程师

---

## 目录

1. [项目定位与总体架构](#1-项目定位与总体架构)
2. [PAM 框架与本模块的接入方式](#2-pam-框架与本模块的接入方式)
3. [构建产物与代码模块划分](#3-构建产物与代码模块划分)
4. [状态文件：CLI 与 PAM 之间的唯一契约](#4-状态文件cli-与-pam-之间的唯一契约)
5. [密码学栈：从 Base32 到 6 位 OTP](#5-密码学栈从-base32-到-6-位-otp)
6. [Provisioning 阶段：google-authenticator CLI](#6-provisioning-阶段google-authenticator-cli)
7. [认证阶段：pam_sm_authenticate 完整流程](#7-认证阶段pam_sm_authenticate-完整流程)
8. [PAM 对话机制与密码传递模式](#8-pam-对话机制与密码传递模式)
9. [验证码校验：Scratch / HOTP / TOTP](#9-验证码校验scratch--hotp--totp)
10. [安全机制深度剖析](#10-安全机制深度剖析)
11. [状态持久化与并发控制](#11-状态持久化与并发控制)
12. [PAM 模块配置选项全解](#12-pam-模块配置选项全解)

---

## 1. 项目定位与总体架构

### 1.1 这是什么、不是什么

**这是：**

- 一个 **Linux PAM（Pluggable Authentication Modules）认证插件**，在用户名/密码之外增加第二因子（TOTP 或 HOTP 动态码，或一次性应急码）。
- 一套 **RFC 4226（HOTP）/ RFC 6238（TOTP）** 的服务端参考实现，算法与 Google Authenticator 等主流 App 兼容。
- 一个 **「文件契约驱动」** 的双组件系统：CLI 负责写密钥文件，PAM 模块负责读文件并验证。

**这不是：**

- 登录 Google/Facebook 等 OAuth/OIDC 的 SDK。
- 中心化 MFA 平台（无用户目录、无推送、无在线吊销 API）。
- WebAuthn/FIDO2、U2F 或基于 SMS 的 2FA。

README 将其描述为 *"Example PAM module demonstrating two-factor authentication"*，应理解为：**模块本身成熟可靠，但 PAM/SSH 集成、密钥分发、应急恢复需运维自行完成**。

### 1.2 双组件架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Provisioning（一次性/轮换）                    │
│  用户或管理员执行: google-authenticator                             │
│    ├─ /dev/urandom → 160-bit 密钥                                   │
│    ├─ Base32 编码 → 写入 ~/.google_authenticator 首行               │
│    ├─ 写入选项行 (TOTP_AUTH / HOTP_COUNTER / RATE_LIMIT / ...)     │
│    ├─ 生成 8 位 scratch codes                                       │
│    └─ 可选 QR 码 (运行时 dlopen libqrencode)                        │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ~/.google_authenticator  (ASCII, ≤1KB 文档约定)
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Authentication（每次登录）                        │
│  sshd / login / sudo → PAM stack → pam_google_authenticator.so      │
│    ├─ 降权读取密钥文件                                               │
│    ├─ rate_limit / grace_period 检查                                │
│    ├─ PAM conversation 获取 OTP                                     │
│    ├─ scratch → HOTP → TOTP 依次验证                                │
│    └─ 原子写回状态（计数器、防重放列表、scratch 删除等）               │
└─────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
                          手机 App 生成 6 位 TOTP/HOTP
```

**关键设计决策：** CLI 与 PAM 之间 **没有 IPC、没有共享库 API、没有数据库**。所有共享状态落在用户家目录下的一个 ASCII 文件中。这使得实现极简、部署简单，但也意味着无集群同步、无集中吊销。

---

## 2. PAM 框架与本模块的接入方式

### 2.1 PAM 是什么

PAM 是 Linux/Unix 上可插拔的认证框架。应用程序（如 `sshd`、`login`、`sudo`）不直接验证密码，而是调用 `libpam`，由配置文件 `/etc/pam.d/<service>` 定义的 **模块栈（stack）** 依次执行。

每个 PAM 模块可实现四类管理组（management group）：

| 类型 | 典型用途 |
|------|----------|
| `auth` | 验证用户身份（本模块唯一实现的功能） |
| `account` | 账户是否允许登录（过期、时间限制等） |
| `session` | 登录会话建立/销毁（环境变量、审计） |
| `password` | 修改密码 |

本模块 **仅导出 `auth` 相关符号**：

```35:35:Makefile.am
pam_google_authenticator_la_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) -export-symbols-regex "pam_sm_(setcred|open_session|authenticate)"
```

- `pam_sm_authenticate`：真正的认证逻辑。
- `pam_sm_setcred`：桩函数，直接返回 `PAM_SUCCESS`，不设置凭证。

```2257:2268:src/pam_google_authenticator.c
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR,
                                   int argc, const char **argv) {
  return google_authenticator(pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED_ATTR,
                int flags UNUSED_ATTR,
                int argc UNUSED_ATTR,
                const char **argv UNUSED_ATTR) {
  return PAM_SUCCESS;
}
```

### 2.2 PAM 控制标志（与生产安全密切相关）

PAM 配置行格式：`type  control  module  [options]`

常用 control 值：

| 标志 | 行为 |
|------|------|
| `required` | 失败记一次失败，**继续执行后续模块** |
| `requisite` | 失败记一次失败，**立即返回**，不执行后续模块 |
| `sufficient` | 成功则可能直接通过整个栈 |
| `optional` | 成败影响不大 |

**官方强烈建议：** `pam_unix.so` 与 `pam_google_authenticator.so` 至少有一个设为 `required`，**不要用 `requisite`**。这样即使密码错误或 OTP 错误，用户仍会被要求输入另一因子，避免攻击者通过「只出现一个提示」推断哪一因子错误。

### 2.3 典型双因子 PAM 栈

```
# /etc/pam.d/sshd 示例
auth required pam_unix.so
auth required pam_google_authenticator.so no_increment_hotp
```

执行顺序：先 `pam_unix` 验证密码，再 `pam_google_authenticator` 验证 OTP。两者都需成功，整个 `auth` 栈才算通过。

---

## 3. 构建产物与代码模块划分

### 3.1 Makefile 定义的产物

| 产物 | 安装路径 | 说明 |
|------|----------|------|
| `pam_google_authenticator.so` | `$(libdir)/security/` | PAM 共享库 |
| `google-authenticator` | `$(bindir)/` | 用户注册 CLI |
| `base32` | 不安装（`noinst_PROGRAMS`） | 测试用小工具 |
| man 页 | `man/` | pandoc 从 `.md` 生成 |

### 3.2 共享核心源码（CORE_SRC）

```
src/util.c      — explicit_bzero 等工具
src/base32.c    — Base32 编解码
src/hmac.c      — HMAC-SHA1
src/sha1.c      — SHA-1 摘要
```

CLI 与 PAM 模块 **各自编译一份 CORE_SRC**，保证 OTP 计算逻辑一致，但无运行时共享库依赖。

### 3.3 源码体量（约）

| 文件 | 行数 | 职责 |
|------|------|------|
| `pam_google_authenticator.c` | ~2287 | PAM 认证全部逻辑 |
| `google-authenticator.c` | ~977 | 密钥生成与文件初始化 |
| `hmac.c` | ~81 | HMAC-SHA1 |
| `base32.c` | ~96 | Base32 |
| `sha1.c` | ~330 | SHA-1 |

PAM 单文件设计意味着：状态文件解析、限流、防重放、PAM 对话、原子写入全部内聚在一个翻译单元中，便于审计，但不利于复用。

---

## 4. 状态文件：CLI 与 PAM 之间的唯一契约

规范文档：`FILEFORMAT`（仓库根目录）。

### 4.1 物理位置与约束

- 默认路径：`~/.google_authenticator`
- PAM 可通过 `secret=` 覆盖（支持 `~`、`${HOME}`、`${USER}`）
- 文档约定大小上限 **1KB**；代码中 `open_secret_file` 允许 **1 字节 ~ 64KB**
- 权限：默认 **0600**，属主必须为登录用户
- 编码：纯 ASCII，**不得含 NUL 字节**

### 4.2 逻辑结构

```
第 1 行          Base32 编码的共享密钥（20 字节原始密钥 → 32 字符 Base32）
" 开头的行        配置选项（见下表）
纯 8 位数字行     一次性 scratch code（首位 1-9）
```

### 4.3 配置选项语义

| 选项 | 设置方 | 读取/更新方 | 含义 |
|------|--------|-------------|------|
| `" TOTP_AUTH` | CLI | PAM `is_totp()` | 启用时间型 OTP |
| `" HOTP_COUNTER n` | CLI | PAM `get_hotp_counter()` | 启用计数型 OTP，下一有效 counter |
| `" STEP_SIZE n` | CLI | PAM `step_size()` | TOTP 步长秒数，默认 30 |
| `" WINDOW_SIZE n` | CLI | PAM `window_size()` | 有效码窗口，默认 3 |
| `" DISALLOW_REUSE` + 时间戳 | CLI/PAM | PAM `invalidate_timebased_code()` | TOTP 防重放 |
| `" RATE_LIMIT n m` + 时间戳 | CLI/PAM | PAM `rate_limit()` | m 秒内最多 n 次尝试 |
| `" TIME_SKEW n` | PAM | PAM `check_timebased_code()` | 持久化时钟偏差 |
| `" RESETTING_TIME_SKEW ...` | PAM | PAM `check_time_skew()` | 偏差学习中间状态 |
| `" LAST0`..`" LAST9` | PAM | PAM `grace_period` | 最近登录 IP 与时间 |

**模式互斥规则（FILEFORMAT）：**

- 存在 `" HOTP_COUNTER` → HOTP 模式
- 存在 `" TOTP_AUTH` 且 **无** `HOTP_COUNTER` → TOTP 模式

### 4.4 配置行解析：`get_cfg_value` / `set_cfg_value`

配置行格式严格：`" KEY value\n`（双引号 + 空格 + 大写键名 + 空格 + 值）。

```834:858:src/pam_google_authenticator.c
static char *get_cfg_value(pam_handle_t *pamh, const char *key,
                           const char *buf) {
  const size_t key_len = strlen(key);
  for (const char *line = buf; *line; ) {
    const char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !strncmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      // ... 提取 value ...
    }
    // ... 下一行 ...
  }
  return NULL;
}
```

`set_cfg_value` 支持就地更新或扩容缓冲区，更新后清除旧缓冲区（`memset` + `free`），并删除重复键行。这是整个「状态机」能在单文件中原子演进的基础。

---

## 5. 密码学栈：从 Base32 到 6 位 OTP

### 5.1 Base32 编解码

密钥以 Base32（RFC 4648 字母表 `A-Z2-7`）存储在文件首行。`base32_decode` 将首行转为二进制密钥；`google-authenticator` 用 `base32_encode` 写入。

容错：`0→O`、`1→L`、`8→B` 的常见误输入纠正。

### 5.2 HMAC-SHA1

```24:80:src/hmac.c
void hmac_sha1(const uint8_t *key, int keyLength,
               const uint8_t *data, int dataLength,
               uint8_t *result, int resultLength) {
  // 密钥 > 64 字节时先 SHA1 哈希
  // inner: (key XOR 0x36) || data → SHA1
  // outer: (key XOR 0x5C) || inner_hash → SHA1
  // ...
  explicit_bzero(hashed_key, sizeof(hashed_key));
  explicit_bzero(sha, sizeof(sha));
  explicit_bzero(tmp_key, sizeof(tmp_key));
}
```

标准 HMAC-SHA1，计算后清零临时缓冲区。

### 5.3 `compute_code`：OTP 核心（RFC 4226 动态截断）

PAM 与 CLI 使用相同算法：

```1390:1408:src/pam_google_authenticator.c
int compute_code(const uint8_t *secret, int secretLen, unsigned long value) {
  uint8_t val[8];
  for (int i = 8; i--; value >>= 8) {
    val[i] = value;
  }
  uint8_t hash[SHA1_DIGEST_LENGTH];
  hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);
  explicit_bzero(val, sizeof(val));
  const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
  unsigned int truncatedHash = 0;
  for (int i = 0; i < 4; ++i) {
    truncatedHash <<= 8;
    truncatedHash  |= hash[offset + i];
  }
  explicit_bzero(hash, sizeof(hash));
  truncatedHash &= 0x7FFFFFFF;
  truncatedHash %= 1000000;
  return truncatedHash;
}
```

**步骤说明：**

1. 将 counter（HOTP 的计数器或 TOTP 的时间步 `floor(time/step)`）编码为 **8 字节大端**整数 `val[8]`。
2. `HMAC-SHA1(secret, val)` → 20 字节 `hash`。
3. **动态截断**：`offset = hash[19] & 0x0F`，从 `hash[offset]` 起取 4 字节组成 31 位整数。
4. `& 0x7FFFFFFF` 去掉符号位，`% 1000000` 得到 **6 位十进制 OTP**（可带前导零）。

CLI 侧 `generateCode()`（`google-authenticator.c:50-94`）逻辑完全对称。

### 5.4 TOTP 时间步

```974:981:src/pam_google_authenticator.c
static int get_timestamp(pam_handle_t *pamh, const char *secret_filename,
                         const char **buf) {
  const int step = step_size(pamh, secret_filename, *buf);
  if (!step) {
    return 0;
  }
  return get_time()/step;
}
```

默认 `step_size = 30`，即每 30 秒一个时间片，与主流 Authenticator App 一致。

---

## 6. Provisioning 阶段：google-authenticator CLI

### 6.1 主流程概览

`main()` 大致步骤：

1. 解析命令行（`-t` TOTP、`-c` HOTP、`-d` 防重放、`-r/-R` 限流等）
2. 打开 `/dev/urandom`，读取 `SECRET_BITS/8 + scratch` 随机字节
3. `base32_encode` → 密钥字符串
4. 交互或静默模式下展示 QR / URL / 明文密钥
5. TOTP 模式下可选验证用户输入的测试码
6. 拼接配置行与 scratch codes
7. `mkstemp` + `write` + `rename` 原子写入 `~/.google_authenticator`（权限 0400）

### 6.2 密钥生成参数

```39:46:src/google-authenticator.c
#define SECRET                    "/.google_authenticator"
#define SECRET_BITS               160         // Must be divisible by eight
#define VERIFICATION_CODE_MODULUS (1000*1000) // Six digits
#define SCRATCHCODES              5           // Default number of initial scratchcodes
#define MAX_SCRATCHCODES          10
#define SCRATCHCODE_LENGTH        8
#define BYTES_PER_SCRATCHCODE     4
```

- 密钥：**160 位**（20 字节），Base32 后约 32 字符。
- 应急码：默认 **5 个**，每个 **8 位**数字，首位非 0。

### 6.3 otpauth URL 与 QR 码

```159:184:src/google-authenticator.c
static const char *getURL(const char *secret, const char *label,
                          const int use_totp, const char *issuer) {
  // otpauth://totp/ 或 otpauth://hotp/
  // 参数: secret=, issuer=
}
```

`displayQRCode()` 运行时 `dlopen("libqrencode.so.*")`，**非编译依赖**。无 libqrencode 时用户需手动输入密钥或访问 URL。

### 6.4 非交互批量注册

```bash
google-authenticator -t -d -r 3 -R 30 -f -q -C \
  -l "user@hostname" -s /path/to/.google_authenticator
```

| 参数 | 作用 |
|------|------|
| `-t` | TOTP |
| `-d` | DISALLOW_REUSE |
| `-r 3 -R 30` | 30 秒内最多 3 次 |
| `-f` | 不询问直接写入 |
| `-q` | 静默 |
| `-C` | 跳过 App 码确认 |

---

## 7. 认证阶段：pam_sm_authenticate 完整流程

`google_authenticator()` 是认证主控函数（约 1905–2247 行）。以下按执行顺序拆解。

### 7.1 阶段 0：解析模块参数

```1838:1903:src/pam_google_authenticator.c
static int parse_args(pam_handle_t *pamh, int argc, const char **argv,
                      Params *params) {
  params->allowed_perm = 0600;  // 默认
  // 解析 secret=, user=, nullok, forward_pass, grace_period=, ...
}
```

`Params` 结构体（74–90 行）保存本次认证的全部模块级配置。

### 7.2 阶段 1：身份与密钥路径

```1929:1931:src/pam_google_authenticator.c
  const char* const username = get_user_name(pamh, &params);
  char* const secret_filename = get_secret_filename(pamh, &params,
                                                    username, &uid);
```

- `get_user_name`：`pam_get_user()` 获取 PAM 用户名。
- `get_secret_filename`：展开 `secret=` 中的 `~`、`${HOME}`、`${USER}`；`user=` 模式下禁止 home 占位符。

### 7.3 阶段 2：降权（drop_privileges）

```373:433:src/pam_google_authenticator.c
static int drop_privileges(pam_handle_t *pamh, const char *username, int uid,
                           int *old_uid, int *old_gid) {
  // getpwuid_r → 用户 gid
  // setfsgid(gid) + setfsuid(uid)  或 setegid/seteuid
}
```

**为何降权：** PAM 模块常以 root 调用。在读取用户密钥文件前切换到目标 UID/GID，避免 root 读取用户文件带来的权限侧信道，并兼容 NFS 挂载的 home 目录。

函数结束或 `out` 标签处 **恢复** 原始 uid/gid；恢复失败会 `LOG_EMERG` 并 `_exit(1)`。

### 7.4 阶段 3：打开并读取密钥文件

```435:500:src/pam_google_authenticator.c
static int open_secret_file(...) {
  // open(O_RDONLY) + fstat
  // 检查: 普通文件、权限 ≤ allowed_perm、属主、大小
  // ENOENT + nullok → params->nullok = SECRETNOTFOUND
}
```

```775:812:src/pam_google_authenticator.c
static uint8_t *get_shared_secret(...) {
  // 首行 strcspn("\n") → base32_decode → 二进制 secret
}
```

### 7.5 阶段 4：rate_limit（在提示用户之前）

```1002:1125:src/pam_google_authenticator.c
static int rate_limit(...) {
  // 解析 "RATE_LIMIT attempts interval [timestamps...]"
  // 追加当前时间，排序，剔除窗口外记录
  // 超限 → 返回 -1，用户甚至看不到 OTP 提示
  // 无论是否超限，都写回修剪后的时间戳列表
}
```

被限流时 `stopped_by_rate_limit=1`，后续跳过 OTP 提示循环。

### 7.6 阶段 5：grace_period 检查

```1712:1761:src/pam_google_authenticator.c
int within_grace_period(...) {
  // 遍历 LAST0..LAST9，匹配 PAM_RHOST
  // 若 when + grace_period > now → 直接 PAM_SUCCESS，免 OTP
}
```

需在 PAM 配置中设置 `grace_period=N`（秒）。适合减少同 IP 频繁 sudo/SSH 的重复输入，但会降低会话内 2FA 强度。

### 7.7 阶段 6：获取并解析用户输入（核心循环）

四层 `mode` 循环（1994–2132 行）处理不同密码来源与码类型歧义：

| mode | 含义 |
|------|------|
| 0 | `try_first_pass`/`use_first_pass`：从 `PAM_AUTHTOK` 提取 **6 位** OTP |
| 1 | 同上，尝试 **8 位** scratch |
| 2 | `request_pass` 交互提示，提取 **6 位** |
| 3 | 交互提示，提取 **8 位** |

**从合并字符串末尾提取验证码：**

```2048:2079:src/pam_google_authenticator.c
      const int pw_len = strlen(pw);
      const int expected_len = mode & 1 ? 8 : 6;
      // 6 位 OTP: 末位可为 '0'-'9'
      // 8 位 scratch: 末 8 位首位必须为 '1'-'9'
      const long l = strtol(pw + pw_len - expected_len, &endptr, 10);
      const int code = (int)l;
      memset(pw + pw_len - expected_len, 0, expected_len);  // 剥离 OTP，保留密码
```

**OpenSSH 特殊处理：** 若密码以 `\b` 开头，记录日志提示检查 `PermitRootLogin` 等配置（2054–2058 行）。

### 7.8 阶段 7：验证码校验链

```2093:2128:src/pam_google_authenticator.c
        switch (check_scratch_codes(...)) {
        case 1:  // 非 scratch，继续
          if (hotp_counter > 0) {
            check_counterbased_code(...);
          } else {
            check_timebased_code(...);
          }
        case 0:  // scratch 成功
          rc = PAM_SUCCESS;
        }
```

### 7.9 阶段 8：forward_pass 转发密码

```2137:2141:src/pam_google_authenticator.c
    if (rc == PAM_SUCCESS && params.forward_pass) {
      if (!pw || pam_set_item(pamh, PAM_AUTHTOK, pw) != PAM_SUCCESS) {
        rc = PAM_AUTH_ERR;
      }
    }
```

验证成功后，将 **已剥离 OTP 的纯密码** 写入 `PAM_AUTHTOK`，供下游 `pam_unix.so use_first_pass` 使用。

### 7.10 阶段 9：HOTP 失败计数器推进

```2153:2162:src/pam_google_authenticator.c
    if (!params.no_increment_hotp && must_advance_counter) {
      // HOTP_COUNTER → hotp_counter + 1
    }
```

防止攻击者暴力枚举 counter；生产环境 README 建议 `no_increment_hotp` 在「失败也提示 OTP」的场景下保护合法用户——注意这与 HOTP 防暴力语义需结合栈设计理解。

### 7.11 阶段 10：nullok 语义

```2185:2187:src/pam_google_authenticator.c
  if (params.nullok == SECRETNOTFOUND) {
    rc = PAM_IGNORE;
  }
```

用户无密钥文件时返回 **`PAM_IGNORE`**（非 SUCCESS 非 FAILURE），PAM 栈需另有模块返回 SUCCESS 才能登录。这是灰度上线的关键语义。

### 7.12 阶段 11：持久化状态

```2189:2213:src/pam_google_authenticator.c
  if (early_updated || updated) {
    if (write_file_contents(...) != 0) {
      if (!params.allow_readonly) {
        rc = PAM_AUTH_ERR;  // 写失败默认拒登
      }
    }
  }
```

---

## 8. PAM 对话机制与密码传递模式

### 8.1 converse 调用链

```152:161:src/pam_google_authenticator.c
static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}
```

PAM 应用（sshd）注册 `pam_conv` 回调；模块通过 `PAM_PROMPT_ECHO_OFF/ON` 控制是否回显。

### 8.2 四种 pass_mode

| 模式 | 配置 | 行为 |
|------|------|------|
| `PROMPT` | 默认 | 模块自己 `request_pass` 提示 OTP |
| `TRY_FIRST_PASS` | `try_first_pass` | 先读 `PAM_AUTHTOK`，失败再提示 |
| `USE_FIRST_PASS` | `use_first_pass` | 只读 `PAM_AUTHTOK`，永不提示 |
| `forward_pass` | `forward_pass` | 单提示「密码+OTP」，成功后转发密码 |

### 8.3 SSH 典型栈（单提示）

```
auth required pam_google_authenticator.so forward_pass
auth required pam_unix.so use_first_pass
```

用户一次输入：`MyPassword123456`（密码 + 6 位 OTP）。模块剥离后 6 位验证 OTP，将 `MyPassword` 交给 pam_unix。

### 8.4 分离式双提示（控制台）

```
auth required pam_unix.so
auth required pam_google_authenticator.so
```

先密码，后 `Verification code:`。

---

## 9. 验证码校验：Scratch / HOTP / TOTP

### 9.1 Scratch Code（应急码）

**校验**（`check_scratch_codes`）：

- 跳过首行 secret 和所有 `"` 配置行
- 匹配 8 位纯数字行，`10000000 ≤ code < 100000000`
- 命中后 `memmove` 删除该行，`updated=1`
- 返回：`0`=成功，`1`=非 scratch 继续 OTP，`-1`=错误

**一次性保证：** 用后从文件删除 + `write_file_contents` 前 `stat` 比对防 TOCTOU。

### 9.2 HOTP（计数器模式）

```1767:1807:src/pam_google_authenticator.c
static int check_counterbased_code(...) {
  const int window = window_size(...);  // 默认 3
  for (int i = 0; i < window; ++i) {
    if (compute_code(secret, secretLen, hotp_counter + i) == code) {
      // HOTP_COUNTER → hotp_counter + i + 1
      return 0;
    }
  }
  *must_advance_counter = 1;
  return 1;
}
```

- 在 `[counter, counter+window-1]` 内搜索匹配
- 成功：counter 设为 `matched + 1`
- 失败：`must_advance_counter`，主流程可能 `counter+1`（除非 `no_increment_hotp`）

### 9.3 TOTP（时间模式）

```1547:1617:src/pam_google_authenticator.c
static int check_timebased_code(...) {
  const int tm = get_timestamp(...);
  int skew = TIME_SKEW 或 0;
  const int window = window_size(...);

  // 1. 窗口内搜索
  for (int i = -((window-1)/2); i <= window/2; ++i) {
    if (compute_code(secret, secretLen, tm + skew + i) == code) {
      return invalidate_timebased_code(tm + skew + i, ...);
    }
  }

  // 2. 时钟偏差暴力搜索（除非 noskewadj）
  if (!params->noskewadj) {
    for (int i = 0; i < 25*60; ++i) {
      // 搜索 tm-i 和 tm+i，找到后不提前 break（防时序侧信道）
    }
    if (skew != 1000000) {
      return check_time_skew(...);  // 学习偏差
    }
  }
  return 1;
}
```

**防重放**（`invalidate_timebased_code`）：

- 若配置 `DISALLOW_REUSE`，检查时间步 `tm` 是否在已用列表
- 已用 → 拒绝并提示等待 `step_size` 秒
- 未用 → 将 `tm` 追加到列表并写回

**时钟偏差自学习**（`check_time_skew`）：

- 维护 `RESETTING_TIME_SKEW` 中最近 3 次 `(tm, skew)` 对
- 连续 3 次、时间步递增、skew 稳定 → 写入 `TIME_SKEW`
- 需连续成功输入，与 rate_limit 默认 3 次/30s 设计协调

---

## 10. 安全机制深度剖析

### 10.1 密钥文件访问控制

| 检查项 | 默认 | 可绕过选项 |
|--------|------|------------|
| 文件类型 | 必须 regular file | — |
| 权限 | ≤ 0600 | `allowed_perm=` |
| 属主 | 登录用户 UID | `no_strict_owner` |
| 读取身份 | setfsuid 到目标用户 | — |

### 10.2 内存安全

- `explicit_bzero` 清除 secret、密码、hash、旧 buf（`util.c` 在无 glibc 时提供 polyfill）
- `set_cfg_value` 重分配前 `memset` 旧缓冲区

### 10.3 防暴力与防重放

| 机制 | 层级 |
|------|------|
| `RATE_LIMIT` | 登录频率 |
| `DISALLOW_REUSE` | TOTP 时间片重用 |
| scratch 删除 | 应急码一次性 |
| HOTP counter 推进 | 计数器空间不可回退枚举 |
| `write_file_contents` stat 检查 | 多会话 scratch 竞态 |

### 10.4 时序侧信道意识

`check_timebased_code` 在暴力搜索 skew 时，**找到匹配后不立即 break**，继续循环以保持大致恒定时间（1599–1606 行注释）。

### 10.5 危险选项（生产禁用）

| 选项 | 风险 |
|------|------|
| `allow_readonly` | 状态写失败仍登录 → OTP/防重放可失效 |
| `no_strict_owner` | 任意属主文件可被读取 |
| `allowed_perm` 放宽 | 组/其他用户可读密钥 |
| `nullok`（上线后） | 未配置 2FA 的用户仅靠密码 |

### 10.6 SELinux

可选编译：`fsetfilecon` 将密钥文件标为 `auth_home_t`（`SECRET_SELINUX_TYPE`）。

---

## 11. 状态持久化与并发控制

### 11.1 `write_file_contents` 原子写入流程

```
1. mkstemp("secret~XXXXXX")  umask(077)
2. fchmod(0400)
3. stat(原文件) 比对 st_ino, st_size, st_mtime  → 不一致则 EAGAIN
4. full_write(新内容)
5. set_selinux_context (可选)
6. fsync + close
7. stat(临时文件) 校验大小
8. rename(临时, 正式路径)
```

这保证了：

- 读者不会看到半写文件
- 两个并发会话不能同时使用同一 scratch code（写前 stat 检测文件变化）

### 11.2 写失败策略

默认：**拒绝登录**（`PAM_AUTH_ERR`），并向用户显示 `EPERM`/`ENOSPC`/`EROFS`/`EIO`/`EDQUOT` 错误。

`allow_readonly`：忽略写错误仍放行——**破坏 OTP 一次性**，仅极端只读文件系统场景可考虑，且文档标为 DANGEROUS。

---

## 12. PAM 模块配置选项全解

| 选项 | 类型 | 说明 |
|------|------|------|
| `secret=/path` | 路径 | 支持 `~` `${HOME}` `${USER}` |
| `user=name` | 字符串/UID | 文件操作前切换身份；与 `~` 互斥 |
| `authtok_prompt=text` | 字符串 | 自定义 OTP 提示；含空格用 `[...]` |
| `nullok` | 标志 | 无密钥文件 → `PAM_IGNORE` |
| `no_increment_hotp` | 标志 | HOTP 失败不递增 counter |
| `noskewadj` | 标志 | 禁用 TOTP 时钟偏差自动学习 |
| `forward_pass` | 标志 | 合并提示并转发密码 |
| `try_first_pass` | 标志 | 先尝试 `PAM_AUTHTOK` |
| `use_first_pass` | 标志 | 仅用 `PAM_AUTHTOK` |
| `grace_period=N` | 整数 | 同 IP N 秒内免 OTP |
| `debug` | 标志 | 详细 syslog |
| `echo_verification_code` | 标志 | OTP 输入回显 |
| `no_strict_owner` | 标志 | **危险** |
| `allowed_perm=0nnn` | 八进制 | **危险** |
| `allow_readonly` | 标志 | **危险** |

---


## 附录 A：返回值速查

| 返回值 | 含义 |
|--------|------|
| `PAM_SUCCESS` | OTP/scratch 验证通过 |
| `PAM_AUTH_ERR` | 验证失败、限流、写状态失败等 |
| `PAM_IGNORE` | `nullok` 且无密钥文件 |

## 附录 B：关键常量

| 常量 | 值 | 位置 |
|------|-----|------|
| `SECRET` | `~/.google_authenticator` | pam 第 69 行 |
| `CODE_PROMPT` | `Verification code: ` | pam 第 71 行 |
| `PWCODE_PROMPT` | `Password & verification code: ` | pam 第 72 行 |
| `SECRET_BITS` | 160 | CLI 第 40 行 |
| 默认 `STEP_SIZE` | 30 | FILEFORMAT / `step_size()` |
| 默认 `WINDOW_SIZE` | 3 | FILEFORMAT / `window_size()` |

## 附录 C：相关文件索引

```
src/pam_google_authenticator.c   # PAM 认证全部逻辑
src/google-authenticator.c       # CLI provisioning
src/hmac.c / src/sha1.c          # 密码学
src/base32.c                     # 编解码
src/util.c                       # explicit_bzero
FILEFORMAT                       # 状态文件规范
Makefile.am                      # 构建定义
tests/pam_google_authenticator_unittest.c
examples/demo.c
man/pam_google_authenticator.8.md
man/google-authenticator.1.md
```

---

*文档结束。如需针对特定环境（Kali SSH、加密 home、批量用户）的落地配置清单，可在此基础上单独编写运维附录。*
