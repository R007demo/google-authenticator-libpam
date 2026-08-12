# 二次认证实现逻辑与实战部署指南

> 本文回答两个核心问题：  
> **① 它到底用什么逻辑实现「二次认证」？**  
> **② 如何在 SSH、sudo、特定程序等场景实际用起来？**

---

## 第一部分：二次认证的具体逻辑（从一次登录说起）

### 1.1 先纠正一个常见误解

**`pam_google_authenticator.so` 本身不验证你的 Linux 登录密码。**

它只做一件事：**验证 OTP（6 位动态码）或 scratch 应急码（8 位）**。

真正的「二次认证」= **两个 PAM 模块串联**：

| 因子 | 验证内容 | 典型模块 | 「你拥有什么」 |
|------|----------|----------|----------------|
| 第一因子 | Unix 系统密码 | `pam_unix.so` | 你知道的密码 |
| 第二因子 | TOTP/HOTP/scratch | `pam_google_authenticator.so` | 手机 App 里的动态码 |

两个模块都在 PAM 配置的 `auth` 栈里，**都返回 SUCCESS**，整个登录才算成功。缺任何一个 → 登录失败。

---

### 1.2 PAM 在登录时扮演什么角色

以 SSH 为例，流程不是 `sshd` 自己读 `/etc/shadow`，而是：

```
用户 ssh user@host
    │
    ▼
sshd 收到连接，调用 libpam
    │
    ▼
libpam 读取 /etc/pam.d/sshd
    │
    ▼
按顺序执行 auth 栈里的每个模块
    │
    ├─ pam_unix.so        → 问密码，对照 /etc/shadow
    ├─ pam_google_auth.so → 问 OTP，对照 ~/.google_authenticator
    └─ ...
    │
    ▼
全部 required 模块成功 → 登录成功
```

**关键点：** 应用程序（sshd）只负责「发起认证」和「展示 PAM 要求的提示」；具体验什么、怎么验，全由 PAM 配置文件决定。

---

### 1.3 一次 SSH 登录的完整时序（双提示模式，最直观）

假设 PAM 配置为：

```
# /etc/pam.d/sshd 或 common-auth
auth required pam_unix.so
auth required pam_google_authenticator.so
```

用户执行：`ssh alice@192.168.1.10`

```
时间线 ──────────────────────────────────────────────────────────────►

[1] ssh 客户端连接，sshd 接受连接

[2] sshd 调用 pam_start("sshd", "alice", ...)
    pam 加载 /etc/pam.d/sshd → 包含 common-auth

[3] sshd 调用 pam_authenticate()
    │
    ├─► [模块 1] pam_unix.so
    │       pam_conv 回调 → sshd 向用户显示:
    │         "alice@192.168.1.10's password:"
    │       用户输入: MySecretPassword
    │       pam_unix 用 crypt() 对比 /etc/shadow
    │       → PAM_SUCCESS 或 PAM_AUTH_ERR
    │
    │   若失败: 整个 auth 栈失败，连接拒绝（但 required 会继续问 OTP，见下）
    │
    └─► [模块 2] pam_google_authenticator.so
            │
            ├─ parse_args()           解析模块参数
            ├─ get_user_name()       得到 "alice"
            ├─ get_secret_filename()  → /home/alice/.google_authenticator
            ├─ drop_privileges()      降权为 alice 的 uid
            ├─ open_secret_file()     打开密钥文件，检查 0600 权限
            ├─ read_file_contents()   读入整个文件到内存
            ├─ rate_limit()           检查是否登录太频繁
            ├─ get_shared_secret()    Base32 解码首行密钥
            ├─ within_grace_period()  若配置了 grace_period 且同 IP 刚登过 → 跳过 OTP
            │
            ├─ request_pass()         pam_conv → 显示:
            │     "Verification code:"
            │   用户输入: 847293
            │
            ├─ check_scratch_codes()  不是 8 位应急码 → 继续
            ├─ check_timebased_code()
            │     tm = time()/30
            │     在窗口内 compute_code(secret, tm±skew) == 847293 ?
            │     若 DISALLOW_REUSE → 检查该时间片是否用过
            │
            ├─ write_file_contents()  更新防重放/限流状态到文件
            │
            └─ 返回 PAM_SUCCESS 或 PAM_AUTH_ERR

[4] 两个模块都 SUCCESS → pam_authenticate 成功

[5] sshd 继续 account 栈、session 栈（与 2FA 无关）

[6] 用户获得 shell
```

**用户主观感受：** 先输密码，再输 6 位数字——这就是「二次」。

---

### 1.4 `pam_google_authenticator` 内部到底验什么

模块 **从不读取 `/etc/shadow`**，也 **不调用 `crypt()`**。

验证链（源码 `google_authenticator()` 2093–2128 行）：

```
用户输入的数字 code
    │
    ▼
┌─ 是 8 位且首位 1-9？ ──► check_scratch_codes
│                              在文件中找匹配行 → 用后删除 → SUCCESS
│                              找不到 → 继续
▼
┌─ 文件含 HOTP_COUNTER？ ──► check_counterbased_code
│                              HMAC-SHA1(secret, counter..counter+window)
│                              匹配 → counter+1 写回 → SUCCESS
▼
┌─ 文件含 TOTP_AUTH？ ──► check_timebased_code
│                          HMAC-SHA1(secret, floor(time/30)±窗口)
│                          匹配 → 可选 DISALLOW_REUSE → SUCCESS
│                          不匹配 → 可选自动学 TIME_SKEW（连续 3 次）
▼
PAM_AUTH_ERR
```

**OTP 计算（与手机 App 必须一致）：**

```
counter = floor(当前Unix时间 / 30)     # TOTP
HMAC-SHA1(二进制密钥, counter的8字节大端)
→ 动态截断 → % 1000000 → 6位数字如 0847293
```

手机 App 和服务器用 **同一密钥**（存在 `~/.google_authenticator` 首行），同一算法，同一时刻算出相同 6 位数。

---

### 1.5 为什么必须两个模块，一个不够

| 若只有 pam_unix | 若只有 pam_google_auth |
|-----------------|------------------------|
| 仅密码，单因子 | 仅 OTP，无密码 |
| 密码泄露即沦陷 | 密钥文件泄露即沦陷 |
| | 且无法对接现有 Unix 账号体系 |

**标准双因子 = 密码模块 + OTP 模块**，两者 `auth required`。

---

### 1.6 `required` 与失败时的行为（安全细节）

```
auth required pam_unix.so          # 密码错 → 记失败，继续
auth required pam_google_auth.so   # 仍提示 OTP；OTP 也错 → 最终失败
```

若改成 `requisite`：密码一错 **立刻返回**，不再问 OTP。攻击者可据此判断「密码是否正确」，**不推荐**。

---

### 1.7 单提示模式 `forward_pass` 的逻辑

部分 SSH 客户端/配置下只能弹 **一次** 密码框。配置：

```
auth required pam_google_authenticator.so forward_pass
auth required pam_unix.so use_first_pass
```

**执行顺序变了：OTP 模块在前，密码模块在后。**

```
[1] pam_google_authenticator 显示:
      "Password & verification code:"
    用户一次输入: MySecretPassword847293
                              ^^^^^^ 末尾6位是OTP

[2] 模块从末尾剥离 6 位 → code=847293，剩余 "MySecretPassword"
    验证 OTP → SUCCESS

[3] pam_set_item(PAM_AUTHTOK, "MySecretPassword")  # 把纯密码塞回 PAM

[4] pam_unix use_first_pass 不再提示，直接读 PAM_AUTHTOK 验密码
```

**用户感受：** 像只输了一次「超长密码」，实际是密码+OTP 拼在一起。

---

## 第二部分：实际运用——按场景配置

### 2.0 任何场景的共同前置步骤

#### 步骤 A：安装模块

```bash
# 方式1：发行版包（Kali/Debian/Ubuntu 推荐）
sudo apt install libpam-google-authenticator qrencode

# 方式2：本仓库源码
cd /workspace/development/google-authenticator-libpam
./bootstrap.sh && ./configure && make
sudo make install
```

确认文件存在：

```bash
ls /lib/x86_64-linux-gnu/security/pam_google_authenticator.so
# 或 /usr/lib/security/pam_google_authenticator.so
which google-authenticator
```

#### 步骤 B：每个需要 2FA 的用户注册密钥

```bash
# 以用户 alice 身份执行（不要用 sudo 代跑写 root 的 home）
su - alice
google-authenticator -t -d -r 3 -R 30
# -t 时间型  -d 禁止OTP重用  -r/-R 限流
```

会生成 `~/.google_authenticator`，用手机 App 扫 QR 或输入密钥。  
**把 5 个 8 位应急码抄到安全处。**

```bash
chmod 600 ~/.google_authenticator
ls -la ~/.google_authenticator   # 必须是 -rw------- alice alice
```

#### 步骤 C：改 PAM 前留后路

```bash
# 开一个 root 控制台或已有 SSH 会话，不要关
sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak
```

---

### 2.1 场景一：SSH 远程登录需要二次认证

#### 方案 A：两次提示（推荐新手、最清晰）

**Debian/Kali** 的 `sshd` 通过 `@include common-auth` 引入认证。改 `common-auth` 会影响 **所有** 引用它的服务（sudo、su 等也会要 OTP）。

**若只想 SSH 要 2FA**，只改 `/etc/pam.d/sshd`，**不要** `@include common-auth`，改为显式写：

```bash
sudo nano /etc/pam.d/sshd
```

在文件 **最上方 auth 部分** 替换 `@include common-auth` 为：

```
# ---- 仅 sshd 启用双因子 ----
auth required pam_unix.so
auth required pam_google_authenticator.so nullok
# nullok：还没注册 OTP 的用户仍能登录（灰度期用，上线后删掉 nullok）
```

保留文件其余 session/account 等行不动。

**OpenSSH 配置**（一般默认即可）：

```bash
sudo nano /etc/ssh/sshd_config
```

确认：

```
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
```

```bash
sudo systemctl reload ssh
# 或 sudo systemctl reload sshd
```

**测试（新开终端，勿关旧会话）：**

```bash
ssh alice@localhost
# 提示1: password:  → 输入系统密码
# 提示2: Verification code: → 输入 App 上 6 位数
```

#### 方案 B：SSH 一次提示（password+OTP 连在一起）

`/etc/pam.d/sshd` 中 auth 部分：

```
auth required pam_google_authenticator.so forward_pass nullok
auth required pam_unix.so use_first_pass
```

用户输入示例：假设密码是 `hello`，OTP 是 `123456`，则输入 `hello123456`（中间无空格）。

#### 方案 C：强制全员 2FA（灰度完成后）

去掉 `nullok`：

```
auth required pam_unix.so
auth required pam_google_authenticator.so
```

未运行 `google-authenticator` 的用户 **无法登录**。

#### sshd 专用 vs 改 common-auth

| 改哪里 | 影响范围 |
|--------|----------|
| 只改 `/etc/pam.d/sshd` | 仅 SSH |
| 改 `/etc/pam.d/common-auth` | SSH、sudo、su、login 等所有 `@include common-auth` 的服务 |

---

### 2.2 场景二：sudo 提权时需要二次认证

`/etc/pam.d/sudo` 当前（Kali）：

```
@include common-auth
```

**做法 1：** 若已在 `common-auth` 加了 google-authenticator → **sudo 自动也要 OTP**。

**做法 2：** 仅 sudo 要 OTP，SSH 不要——在 `common-auth` 不加，单独改 sudo：

```bash
sudo nano /etc/pam.d/sudo
```

将 `@include common-auth` 替换为：

```
auth required pam_unix.so
auth required pam_google_authenticator.so
```

效果：普通 SSH 登录只要密码；每次 `sudo command` 再要一次 OTP。

**注意：** 自动化脚本里非交互 `sudo` 会卡住或失败，需为特定用户/命令配置 NOPASSWD 或使用 SSH 密钥 + 受限命令。

---

### 2.3 场景三：本地控制台 login / 图形登录

| 服务 | PAM 文件 | 说明 |
|------|----------|------|
| 文本 login | `/etc/pam.d/login` | getty 登录 |
| GDM | `/etc/pam.d/gdm-password` | GNOME 登录 |
| LightDM | `/etc/pam.d/lightdm` | 其他桌面 |

在对应文件的 `auth` 段加入（或在 `common-auth` 统一加）：

```
auth required pam_google_authenticator.so
```

图形登录通常 **两次提示**（先密码窗口，再 OTP），比 SSH 的 `forward_pass` 更少用。

---

### 2.4 场景四：「打开某个程序」时需要二次认证

**核心原则：只有调用 PAM 的程序才能用本模块。**

#### 能直接配 PAM 的（改 `/etc/pam.d/<服务名>`）

| 程序/场景 | PAM 服务名 | 配置文件 |
|-----------|------------|----------|
| SSH | sshd | `/etc/pam.d/sshd` |
| sudo | sudo | `/etc/pam.d/sudo` |
| su | su | `/etc/pam.d/su` |
| 本地登录 | login | `/etc/pam.d/login` |
| 屏幕锁定 | 因 DE 而异 | `xfce4-screensaver`、`gdm-password` 等 |
| pkexec | polkit 通常 **不走** 这套 PAM | 需 polkit 规则，不是本模块 |

#### 自定义程序若支持 PAM

若你自己写的 C 服务调用了 `pam_authenticate()`，且服务名为 `myapp`：

1. 创建 `/etc/pam.d/myapp`：

```
auth required pam_unix.so
auth required pam_google_authenticator.so
account required pam_permit.so
session required pam_permit.so
```

2. 程序里 `pam_start("myapp", user, &conv, &pamh)`。

#### 普通 GUI 程序（firefox、自定义脚本）—— 默认 **不能**

Firefox、VS Code 等 **不会** 调用 PAM。无法通过 `pam_google_authenticator` 在「双击图标」时弹 OTP。

**可行替代：**

1. **先 SSH/sudo 进高权限环境**，再在里边开程序  
2. **用 sudo 包装启动脚本**：

```bash
# /usr/local/bin/secure-start-myapp
#!/bin/bash
exec sudo -u "$USER" /path/to/myapp
```

`/etc/pam.d/sudo` 已配 OTP → 每次 sudo 启动都要 OTP。

3. **polkit / 桌面策略**（图形授权，不是 TOTP PAM）  
4. **应用层自己集成 TOTP**（调用同一密钥 API，与本 PAM 模块无关）

---

### 2.5 场景五：仅部分用户需要 2FA

本模块 **没有** 内置「用户组白名单」。常见做法：

**做法 A：** 未配置密钥的用户用 `nullok` 跳过（配了密钥的必须 OTP）

**做法 B：** 不同用户密钥路径 + PAM 的 `secret=`（运维复杂）

**做法 C：** 只对 sshd 强制，管理员用控制台 + 未配 OTP 的 break-glass 账号

**做法 D：** 两个 sshd 实例/端口，不同 PAM 配置（高级）

---

### 2.6 场景六：加密家目录（ecryptfs/fscrypt）

登录时 home 尚未挂载，读不到 `~/.google_authenticator`。

```
auth required pam_google_authenticator.so \
  secret=/var/local/otp/${USER}/.google_authenticator
```

管理员预先：

```bash
sudo mkdir -p /var/local/otp/alice
sudo google-authenticator -t -f -s /var/local/otp/alice/.google_authenticator
sudo chown alice:alice /var/local/otp/alice/.google_authenticator
sudo chmod 600 /var/local/otp/alice/.google_authenticator
```

PAM 解密 home **之前** 必须能读到该路径（有时需调整 ecryptfs 的 PAM 顺序）。

---

## 第三部分：配置模板速查

### 模板 1：仅 SSH，双提示，灰度

```
# /etc/pam.d/sshd — 替换 @include common-auth
auth required pam_unix.so
auth required pam_google_authenticator.so nullok
```

### 模板 2：仅 SSH，双提示，强制 2FA

```
auth required pam_unix.so
auth required pam_google_authenticator.so
```

### 模板 3：SSH，单提示

```
auth required pam_google_authenticator.so forward_pass
auth required pam_unix.so use_first_pass
```

### 模板 4：全局（common-auth），所有服务都要 2FA

```
# /etc/pam.d/common-auth — 在 pam-auth-update 管理的块之外添加
auth required pam_unix.so
auth required pam_google_authenticator.so
auth required pam_permit.so
```

（注意与 `pam-auth-update` 自动生成的行不要冲突，建议用 `dpkg-reconfigure pam-auth-update` 前先备份。）

### 模板 5：仅 sudo 要 2FA

```
# /etc/pam.d/sudo
auth required pam_unix.so
auth required pam_google_authenticator.so
@include common-account
@include common-session-noninteractive
```

---

## 第四部分：运维与排错

### 4.1 日志

```bash
sudo tail -f /var/log/auth.log
# 模块 debug 模式：
# auth required pam_google_authenticator.so debug
```

成功：`Accepted google_authenticator for alice`  
失败：`Invalid verification code for alice`

### 4.2 常见问题

| 现象 | 原因 | 处理 |
|------|------|------|
| 只问密码不问 OTP | PAM 未配或未 reload sshd | 检查 pam.d，reload |
| OTP 总错 | 时间不同步 | `timedatectl`，或连续 3 次正确码学 skew |
| 配了 OTP 仍只问密码 | 改错文件 / 未 include | 确认 sshd 用的哪份配置 |
| 锁死无法登录 | PAM 语法错误 | 控制台改回 `.bak` |
| sudo 脚本失败 | 非交互无法输 OTP | NOPASSWD 或 expect/密钥 |

### 4.3 应急恢复

1. 控制台登录 root  
2. `sudo cp /etc/pam.d/common-auth.bak /etc/pam.d/common-auth`  
3. 或用 scratch code 登录一次  
4. `systemctl reload ssh`

---

## 第五部分：逻辑总结一图流

```
                    ┌─────────────────────────────────┐
                    │  用户要证明的两件事              │
                    │  ① 知道 Unix 密码 (pam_unix)    │
                    │  ② 持有手机 OTP   (pam_google)  │
                    └─────────────────────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          ▼                           ▼                           ▼
    /etc/pam.d/sshd            /etc/pam.d/sudo            /etc/pam.d/login
    (仅远程 SSH)               (仅提权)                   (本地控制台)
          │                           │                           │
          └───────────────────────────┴───────────────────────────┘
                                      │
                                      ▼
                         pam_google_authenticator.so
                                      │
                    读 ~/.google_authenticator
                    验 6位TOTP / 8位scratch
                    更新防重放/限流状态
                                      │
                                      ▼
                              PAM_SUCCESS → 允许
                              PAM_AUTH_ERR → 拒绝
```

---


```
sequenceDiagram
    participant User as 用户
    participant SSH as sshd
    participant PAM as libpam
    participant Unix as pam_unix
    participant GA as pam_google_auth
    participant File as .google_authenticator

    User->>SSH: 连接
    SSH->>PAM: pam_authenticate()
    PAM->>Unix: 验第一因子
    Unix->>User: password:
    User->>Unix: MyPassword
    Unix->>Unix: crypt 对比 shadow
    Unix-->>PAM: SUCCESS

    PAM->>GA: 验第二因子
    GA->>File: 读密钥+配置
    GA->>User: Verification code:
    User->>GA: 847293
    GA->>GA: HMAC-SHA1 算 OTP 比对
    GA->>File: 写回防重放/限流
    GA-->>PAM: SUCCESS

    PAM-->>SSH: 认证通过
    SSH->>User: 进入 shell

```





*配合阅读：[PAM_MECHANISM.zh-CN.md](./PAM_MECHANISM.zh-CN.md) 源码级细节。*
