# Google Authenticator (libpam) 集成

> 本文是 `google-authenticator-libpam` 项目的**集成实战文档**。所有命令、路径、配置语法均在一次真实部署中得到验证：
> - 目标机：**Ubuntu 24.04.3 LTS**（x86_64，kernel 6.8）
> - 部署目标：单用户（abc）的 SSH 双因子认证
> - 版本：`google-authenticator 1.11`

---

## 目录

- [第一部分：PAM 与 CLI 的本质区别](#第一部分pam-与-cli-的本质区别)
- [第二部分：构建编译（含本次踩坑实录）](#第二部分构建编译含本次踩坑实录)
- [第三部分：两种安装方式（make install vs DEB 包）](#第三部分两种安装方式make-install-vs-deb-包)
- [第四部分：用户开通 OTP（CLI）](#第四部分用户开通-otpcli)
- [第五部分：配置 SSH 启用 2FA（含 key 绕过漏洞修复）](#第五部分配置-ssh-启用-2fa含-key-绕过漏洞修复)
- [第六部分：验证、回滚与运维](#第六部分验证回滚与运维)

---

# 第一部分：PAM 与 CLI 的本质区别

| 维度 | CLI（`google-authenticator`） | PAM 模块（`pam_google_authenticator.so`） |
|------|--------------------------------|---------------------------------------------|
| **源文件** | `src/google-authenticator.c` (977 行) | `src/pam_google_authenticator.c` (2286 行) |
| **产物类型** | ELF 可执行文件（`bin_PROGRAMS`） | 共享对象 `.so`（`pam_LTLIBRARIES`） |
| **入口符号** | `main()` | `pam_sm_authenticate()` / `pam_sm_setcred()` |
| **谁加载它** | shell / 用户直接执行 | libpam（在服务进程内 `dlopen`） |
| **运行时机** | **一次性**：用户开通 2FA 时跑一次 | **每次登录**：每次认证都被调用 |
| **运行身份** | 用户自己 | 先以服务进程身份（常 root），内部 `setfsuid` 降权到目标用户 |
| **对密钥文件的操作** | **创建/覆盖**（一次性写入） | **读取 + 部分改写**（每次登录更新状态） |
| **典型安装路径** | `/usr/bin/google-authenticator` | `/lib/x86_64-linux-gnu/security/pam_google_authenticator.so` |
| **失败影响** | 仅用户无法开通，可重跑 | 用户无法登录（fail-closed） |

**核心论断：CLI 写文件，PAM 读文件。两者之间只有一个 `~/.google_authenticator`。**

---

# 第二部分：构建编译（含本次踩坑实录）

## 2.1 依赖清单（Ubuntu 24.04 实测）

```bash
sudo apt update
sudo apt install -y build-essential autoconf automake libtool \
                     pkg-config libpam0g-dev
```

**每个包的作用与缺失后果（本次实测）**：

| 包 | 作用 | 缺失时的报错 |
|----|------|--------------|
| `build-essential` | gcc / make | `./configure` 找不到编译器 |
| `autoconf` `automake` `libtool` | 生成 `configure` 与 Makefile | `./bootstrap.sh` 直接失败 |
| **`pkg-config`** | 提供 `pkg.m4` 宏（被 `configure.ac:89` 的 `PKG_CHECK_MODULES` 用到） | **`bootstrap.sh` 报 `possibly undefined macro: AC_MSG_ERROR/AC_DEFINE`，autoreconf 退出码 1** |
| `libpam0g-dev` | `<security/pam_modules.h>` | `configure: error: Unable to find the PAM library` |

> **本次最隐蔽的坑：`pkg-config`**。Ubuntu 24.04 默认装的 `build-essential` 不带它。报错信息（`AC_MSG_ERROR` 未定义）看似指向 autoconf，**实则是 pkg.m4 缺失导致 `PKG_CHECK_MODULES` 宏展开失败**，连带后面的 `AC_MSG_ERROR`/`AC_DEFINE` 被当成未定义。诊断方法：`ls /usr/share/aclocal/pkg.m4` —— 文件存在即说明 pkg-config 装好了。

**可选包**：

| 包 | 作用 |
|----|------|
| `libqrencode-dev` | CLI 显示 QR 码（**运行时** dlopen，不装也能手动输密钥） |

> 注意：libqrencode 是**运行时依赖**而非编译期依赖。CLI 通过 `dlopen("libqrencode.so.4")` 加载（`google-authenticator.c:196`）。所以装在运行环境即可，构建环境不需要。缺失时 CLI 打印 `Failed to use libqrencode to show QR code visually for scanning.` 但功能正常（密钥照常显示）。

## 2.2 三步构建

```bash
git clone https://github.com/google/google-authenticator-libpam.git
cd google-authenticator-libpam

# ① 生成 configure（bootstrap.sh 内部执行 autoreconf -i）
./bootstrap.sh

# ② 配置（Ubuntu x86_64 必须显式指定 --libdir，见下文）
./configure --prefix=/usr --libdir=/lib/x86_64-linux-gnu

# ③ 编译 + 跑测试
make
make check
```

### `bootstrap.sh` 成功的标志

只剩两条**无害**的 warning（上游代码用了过时的 autoconf 宏）：

```
configure.ac:18: warning: The macro `AC_PROG_CC_STDC' is obsolete.
configure.ac:107: warning: The macro `AC_CONFIG_HEADER' is obsolete.
```

**不应有任何 `error`**。末尾应看到 `installing 'build/config.guess'`、`installing 'build/install-sh'` 等行——这些辅助文件由 automake 补齐。

> **本次踩坑**：第一次跑 `bootstrap.sh` 失败后，目录里残留了不完整的 `configure`。后续重试即使依赖装好了，仍可能因为 `aclocal.m4` 残留而继续报错。**修复方法**：清理后再跑：
> ```bash
> rm -rf autom4te.cache configure config.h.in Makefile.in aclocal.m4 build/*.m4
> ./bootstrap.sh
> ```

### `--libdir` 为何重要（Ubuntu 上的关键）

不同发行版 libpam 硬编码了 PAM 模块搜索路径：

| 发行版 | PAM 模块默认搜索路径 | 对应 `--libdir` |
|--------|---------------------|-----------------|
| **Ubuntu/Debian x86_64** | `/lib/x86_64-linux-gnu/security/` | `--libdir=/lib/x86_64-linux-gnu` |
| RHEL/CentOS/Fedora x86_64 | `/lib64/security/` | `--libdir=/lib64` |
| 通用 32 位 | `/lib/security/` | `--libdir=/lib` |

> 配错 `--libdir` 的后果：`make install` 后 PAM 配置里写 `pam_google_authenticator.so`，登录时报 `module not found`。本次部署在 Ubuntu 24.04 上**必须**用 `/lib/x86_64-linux-gnu`。

### `make check` 成功的标志

```
PASS: tests/pam_google_authenticator_unittest
PASS: tests/base32_test.sh
============================================================================
# TOTAL: 2
# PASS:  2
============================================================================
```

`pam_google_authenticator_unittest` 是一个 630 行的单元测试，覆盖 8 种 OTP 传递模式 × 十余个功能点（窗口扫描、防重放、时间漂移、HOTP 推进等）。跑通它意味着算法实现在你机器上被验证正确。

---

# 第三部分：两种安装方式（make install vs DEB 包）

构建产物有两个：

| 产物 | 路径（仓库内） | 安装目标 |
|------|----------------|----------|
| CLI | `google-authenticator` | `/usr/bin/` |
| PAM 模块 | `.libs/pam_google_authenticator.so` | `/lib/x86_64-linux-gnu/security/` |

> libtool 注意：顶层目录的 `pam_google_authenticator.so` 是个文本 wrapper，真正的二进制在 `.libs/` 下。`make install` / 打包时会自动处理。

## 3.1 方式 A：`make install`（直装，简单）

```bash
sudo make install
```

**验证**：

```bash
which google-authenticator
ls -l /lib/x86_64-linux-gnu/security/pam_google_authenticator.so
google-authenticator --version
```

**特点**：dpkg 完全不知道这个安装的存在（`dpkg -l | grep google-authenticator` 返回空）。卸载需要源码目录还在：`sudo make uninstall`。适合开发/测试，不适合生产。

## 3.2 方式 B：DEB 包（生产推荐）

Ubuntu 用 DEB（**不是 RPM**）。RPM 是 Red Hat 系格式，Ubuntu 上无法直接用。下面给出实测可用的打包脚本。

### 3.2.1 打包脚本

把以下脚本保存为仓库根目录下的 `build-deb.sh`（**必须放在仓库根目录**，否则 `make install` 找不到 Makefile）：

```bash
cat > build-deb.sh <<'EOF'
#!/bin/bash
# google-authenticator-libpam DEB 打包脚本
# 前提: 已在仓库目录跑过 ./bootstrap.sh && ./configure --prefix=/usr --libdir=/lib/x86_64-linux-gnu && make
# 用法: ./build-deb.sh

set -e

PKG_NAME="google-authenticator"
PKG_VERSION="1.11"
PKG_ARCH=$(dpkg --print-architecture)
PKG_FULL="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"
BUILD_ROOT=$(mktemp -d)
PKG_DIR="${BUILD_ROOT}/${PKG_FULL}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> 打包目录: ${PKG_DIR}"

# 1. 安装到临时目录（DESTDIR 是 autotools 标准）
make -C "${SRC_DIR}" install DESTDIR="${PKG_DIR}"

# 2. 补 DEB 元数据
mkdir -p "${PKG_DIR}/DEBIAN"
cat > "${PKG_DIR}/DEBIAN/control" <<CTRL
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Section: admin
Priority: optional
Architecture: ${PKG_ARCH}
Depends: libpam0g (>= 1.1.0), libc6 (>= 2.34)
Recommends: libqrencode4
Maintainer: ${USER} <${USER}@localhost>
Description: Google Authenticator PAM module (two-factor auth)
 PAM module and CLI tool for TOTP/HOTP two-factor authentication.
 Built from source on $(date -Iseconds).
CTRL

# 3. 打包（fakeroot 保证文件 owner 是 root）
DEB_OUT="${SRC_DIR}/${PKG_FULL}.deb"
fakeroot dpkg-deb --build "${PKG_DIR}" "${DEB_OUT}"

echo
echo "==> 打包成功:"
ls -lh "${DEB_OUT}"

# 4. 清理
rm -rf "${BUILD_ROOT}"
EOF

chmod +x build-deb.sh
```

### 3.2.2 打包与验证

```bash
sudo apt install -y fakeroot dpkg-dev

./build-deb.sh
# 产物: google-authenticator_1.11_amd64.deb（约 100KB）

# 安装这个 DEB
sudo dpkg -i google-authenticator_1.11_amd64.deb

# 验证 dpkg 已登记
dpkg -l google-authenticator

# 验证 dpkg 能列出全部文件（这是包管理的核心价值）
dpkg -L google-authenticator
```

### 3.2.3 两种方式的对比（本次实测）

```bash
# make install 装的 —— dpkg 不知道它存在
dpkg -l | grep google-authenticator     # 空

# dpkg -i 装的 —— dpkg 完全追踪
dpkg -L google-authenticator            # 列出全部 13 个文件
```

| 维度 | `make install` | `dpkg -i xxx.deb` |
|------|----------------|---------------------|
| dpkg 数据库登记 | ❌ | ✅ |
| 卸载 | `make uninstall`（需源码） | `dpkg -r 包名`（一行） |
| 文件清单追溯 | ❌ | ✅ `dpkg -L` |
| 依赖声明 | ❌ | ✅ `Depends:` 字段 |
| 升级 | 重编译 | `dpkg -i 新版.deb` |
| 适合场景 | 开发/单机测试 | 生产/多机部署 |

**结论**：本次单机学习场景，DEB 打包的价值在于**让你直观看到包管理的本质**——同样 13 个文件，DEB 多了一层"元数据 + 数据库登记"，于是可追溯、可干净卸载。生产部署应该用 DEB（或发行版官方包）。

---

# 第四部分：用户开通 OTP（CLI）

**此步骤必须由每个用户自己执行**（或管理员代执行后安全分发密钥）。本节针对本次部署的 abc 用户。

## 4.1 标准交互式开通

```bash
# 以 abc 身份
google-authenticator -t -d -W -Q UTF8 -r 3 -R 30 -e 5
```

参数解释：
- `-t` TOTP 时间模式（手机 App 默认）
- `-d` 禁止同一 OTP 30 秒内重用（防 MITM 重放）
- `-W` 最小窗口（更安全，要求时钟较准）
- `-Q UTF8` Unicode 字符渲染 QR 码（比 ANSI 小一半）
- `-r 3 -R 30` 30 秒内最多 3 次尝试（防暴力）
- `-e 5` 生成 5 个 8 位应急码

**会发生什么**：
1. 终端打印 QR 码（需 `libqrencode` 运行时库；缺失时打印 `Failed to use libqrencode...`，密钥照常显示）
2. 手机 App 扫码，或手动输入 Base32 密钥
3. 提示 `Enter code from app (-1 to skip):` → 输入 App 上的 6 位码确认
4. 显示 5 个应急码（**立即存到密码管理器，只显示一次**）
5. 询问是否更新 `~/.google_authenticator`（默认 y）

## 4.2 验证文件就位

```bash
ls -la ~/.google_authenticator
```

**必须**满足：

```
-r-------- 1 abc abc <100~300字节> ... .google_authenticator
```

- 权限 `-r--------`（400）
- 属主是本人
- 大小通常 100~300 字节

任一不符 PAM 模块都会拒绝（详见 `TECHNICAL_DEEP_DIVE.md` §8.1）。本次实测大小 141 字节（含密钥 + TOTP_AUTH + DISALLOW_REUSE + WINDOW_SIZE + RATE_LIMIT + 5 个 scratch 码）。

## 4.3 非交互式批量开通（管理员场景）

加 `-f`（不确认覆盖）和 `-C`（不要求确认码）：

```bash
sudo -u alice -H google-authenticator -t -d -W -f -C -Q NONE
```

注意 `-Q NONE` 关闭 QR 显示后，密钥只显示一次，需安全渠道发给用户。管理员代开通时密钥经过管理员之手，**生产环境更安全的做法**是给每个用户一个 `otpauth://totp/...?secret=...` URL 让他们自己扫码。

---

# 第五部分：配置 SSH 启用 2FA（含 key 绕过漏洞修复）

> ⚠️ **本节是部署中风险最高的环节**，配置错误会锁死所有用户。开始前**必须另开一个 SSH 会话作为后门**——sshd 只对**新连接**应用新配置，后门不会断。

## 5.1 第一步：让 sshd 支持键盘交互

OpenSSH 默认 `KbdInteractiveAuthentication no`，OTP 提示传不过来。先看现状：

```bash
grep -E '^(KbdInteractiveAuthentication|UsePAM)' /etc/ssh/sshd_config
```

Ubuntu 24.04 默认 `KbdInteractiveAuthentication no`，需改成 `yes`：

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F-%H%M)
sudo sed -i 's/^KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
grep '^KbdInteractiveAuthentication' /etc/ssh/sshd_config
```

## 5.2 第二步：在 PAM 配置里挂载 OTP 模块

```bash
sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak.$(date +%F-%H%M)
sudo sed -i '/^@include common-auth/a auth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
head -7 /etc/pam.d/sshd
```

预期看到插入位置正确：

```pam
# Standard Un*x authentication.
@include common-auth
auth required pam_google_authenticator.so nullok       ← 新插入

# Disallow non-root logins when /etc/nologin exists.
```

**关于 `nullok`**：开通阶段必须带它，否则只有 abc 开通了 OTP，**其他所有用户会被锁死**（因为他们没有 `~/.google_authenticator`）。等所有用户都开通后再去掉 `nullok` 变成强制 2FA。

**关于 `required` vs `requisite`**：两个因子（`pam_unix` 和 `pam_google_authenticator`）都用 `required`。`requisite` 会在密码错误时立即返回，泄露"密码对不对"的信息，便于攻击者枚举。

### 分阶段上线

| 阶段 | PAM 配置 | 说明 |
|------|----------|------|
| 灰度 | `... nullok` + `pam_permit.so` | 未注册用户仍可登录 |
| 强制 | 移除 `nullok` | 全员 2FA |
| 加固 | 用户文件启用 `DISALLOW_REUSE` + `RATE_LIMIT` | 防重放与暴力 |


## 5.3 第三步：重启 + 验证基础链路

```bash
sudo sshd -t          # 语法检查，必须无输出
sudo systemctl restart ssh
sudo systemctl status ssh --no-pager | head -5
```

**先用密码登录测试**（在另一台机器上）：

```bash
ssh -o PreferredAuthentications=keyboard-interactive,password abc@<server-ip>
# (abc@...) Password:           ← 系统密码
# (abc@...) Verification code:  ← 手机上的 OTP
```

服务器端验证日志：

```bash
sudo grep google_auth /var/log/auth.log | tail -5
# 应看到: sshd(pam_google_auth)[...]: Accepted google_authenticator for abc
```

## 5.4 第四步（关键）：堵住 SSH key 绕过 2FA 的漏洞

**本次部署发现的最大安全问题**：基础链路通了之后，直接 `ssh abc@<ip>` 会**因为本机已配 SSH key 而直接拿到 shell，完全跳过 OTP**。

**根因**：OpenSSH 默认 `AuthenticationMethods any`，用户通过**任何一种**认证（publickey 或 password 或 kbdint）就成功。SSH key 认证**不走 PAM auth 栈**，直接在 sshd 内部完成，所以绕过了 google 模块。

**修复**：用 `AuthenticationMethods` 强制多因子（逗号表示"且"）：

```bash
sudo tee -a /etc/ssh/sshd_config >/dev/null <<'EOF'

# 强制双因子：publickey（SSH key）+ keyboard-interactive（PAM 中的 OTP）
AuthenticationMethods publickey,keyboard-interactive
EOF

sudo sshd -t          # 必须无输出
sudo systemctl restart ssh
sudo sshd -T | grep -i authenticationmethods   # 验证生效
```

**预期**：`authenticationmethods publickey,keyboard-interactive`

修复后再用 key 登录，会被要求 `Verification code:`。至此 key + OTP 双因子闭环。

## 5.5 关于"修复后仍问密码"的说明

`publickey,keyboard-interactive` 的实际行为是：

```
publickey 检查  →  静默通过（key 被接受）
keyboard-interactive 触发 PAM auth 栈（common-auth + google_auth）
                ↓
PAM 栈依次问：Password → Verification code
```

即 key 用户实际经历了**三因子**（key + 密码 + OTP）。这是 OpenSSH 的固有行为——`keyboard-interactive` 是整个 PAM auth 栈，而 `common-auth` 默认包含 `pam_unix.so`。

**三种取舍**：

| 目标 | 配置 | 结果 |
|------|------|------|
| 学习/演示，最干净的两因子 | 禁用 key，只用密码+OTP | 见下方"方案 C" |
| 生产，key 用户也要 OTP | `publickey,keyboard-interactive` | 三因子（冗余但最安全） |
| 生产，只用密码+OTP 不要 key | `keyboard-interactive` + `PubkeyAuthentication no` | 方案 C |

**方案 C 配置**（最干净，适合学习/演示）：

```bash
sudo sed -i 's|^AuthenticationMethods publickey,keyboard-interactive|AuthenticationMethods keyboard-interactive|' /etc/ssh/sshd_config
echo "PubkeyAuthentication no" | sudo tee -a /etc/ssh/sshd_config >/dev/null
sudo sshd -t && sudo systemctl restart ssh
```

---

# 第六部分：验证、回滚与运维

## 6.1 端到端验证清单

```bash
# 1. CLI 可用
google-authenticator --version

# 2. PAM 模块就位
ls -l /lib/x86_64-linux-gnu/security/pam_google_authenticator.so

# 3. 用户状态文件权限正确
ls -la ~/.google_authenticator       # 必须 -r--------

# 4. sshd 配置生效
sudo sshd -T | grep -iE 'authenticationmethods|kbdinteractive'

# 5. OTP 真的被检查（登录失败时日志有记录）
sudo grep google_auth /var/log/auth.log | tail -5
```

## 6.2 日志中常见信息

| 日志 | 含义 |
|------|------|
| `Accepted google_authenticator for abc` | OTP 验证成功 |
| `Invalid verification code for abc` | OTP 错误（输错码或时钟漂移） |
| `Secret file ... changed while trying to use scratch code` + `Failed to update ... Resource temporarily unavailable` | **TOCTOU 保护触发**：并发会话改了状态文件，本次拒绝写。这是设计上的安全行为（详见 `TECHNICAL_DEEP_DIVE.md` §8.3），下次重试即可，不影响安全 |
| `Too many concurrent login attempts` | RATE_LIMIT 触发，等 30 秒 |

## 6.3 紧急回滚（用户被锁死时）

**前提**：保留后门会话，或通过其他途径（物理/console/已建立的连接）能登入。

```bash
# 完全关闭 2FA
sudo cp /etc/pam.d/sshd.bak.* /etc/pam.d/sshd
sudo cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config
sudo systemctl restart ssh

# 或只删除用户的状态文件（让他重新开通）
sudo rm /home/abc/.google_authenticator
```

> 备份文件命名规则（本次部署采用）：`<原文件>.bak.<日期-时间>`，例如 `/etc/pam.d/sshd.bak.2026-08-10-1426`。回滚时用通配符 `*.bak.*` 选最新的即可。

## 6.4 卸载

```bash
# DEB 安装的
sudo dpkg -r google-authenticator

# make install 安装的（需源码目录）
sudo make uninstall
```

**卸载不会删除用户的 `~/.google_authenticator`**——这是用户数据。卸载前应清理：

```bash
sudo find /home -name '.google_authenticator' -delete
```

## 6.5 升级

PAM 模块是 `.so`，已加载旧版本的进程（如 sshd）需要重启才能用新代码：

```bash
sudo dpkg -i google-authenticator_新版本_amd64.deb   # 或 make install
sudo systemctl restart ssh                           # 重新加载 PAM 模块
```

> **不要在生产 SSH 上裸升级而不重启 sshd**——旧代码继续跑，新代码逻辑不生效，行为不一致。

## 6.6 常见问题

**Q：OTP 总是错。**
A：90% 是时钟漂移。确认两端时间同步：服务器跑 `timedatectl`（应看到 `System clock synchronized: yes`）。不配 `noskewadj` 时，连续登录 3 次会自动学习偏移（详见 `TECHNICAL_DEEP_DIVE.md` §7.3）。

**Q：QR 码不显示。**
A：装运行时库 `sudo apt install libqrencode-dev`，无需重新编译。或直接手动输入 Base32 密钥到 App。

**Q：加密家目录场景读不到状态文件。**
A：用 `secret=` 参数指向未加密路径：
```pam
auth required pam_google_authenticator.so secret=/var/lib/google-auth/${USER} user=root
```

**Q：cron/systemd 等无 TTY 服务无法弹 OTP。**
A：用 `grace_period=` 让服务在最近成功认证后免 OTP，或配 `nullok` 让无状态文件时跳过。

---

## 附录：本次部署的实际产物清单

| 类别 | 内容 |
|------|------|
| 系统 | Ubuntu 24.04.3 LTS, kernel 6.8, x86_64 |
| 版本 | google-authenticator 1.11 |
| 构建 | `--prefix=/usr --libdir=/lib/x86_64-linux-gnu` |
| CLI 路径 | `/usr/bin/google-authenticator` |
| PAM so 路径 | `/lib/x86_64-linux-gnu/security/pam_google_authenticator.so` |
| 状态文件 | `/home/abc/.google_authenticator`（141 字节，权限 400） |
| PAM 配置 | `/etc/pam.d/sshd` 第 6 行 `auth required pam_google_authenticator.so nullok` |
| sshd 配置 | `KbdInteractiveAuthentication yes` + `AuthenticationMethods publickey,keyboard-interactive` |
| 验证 | `Accepted google_authenticator for abc` 日志出现 |

---

*本文基于一次真实的 Ubuntu 24.04 部署全过程整理。所有命令、路径、报错、日志均来自实操验证。其他发行版（RHEL/CentOS/Fedora）请注意 `--libdir` 与 PAM 模块搜索路径的差异（见 §2.2 表格）。*
