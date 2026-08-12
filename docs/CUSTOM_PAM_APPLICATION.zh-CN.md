# 自定义程序如何接入 PAM（含 Google Authenticator 双因子）

## 1. 两个角色：应用程序 vs PAM 模块

```
┌──────────────────┐         ┌─────────────────────────────┐
│  你的程序         │         │  PAM 模块 (插件)             │
│  (PAM 应用程序)   │  libpam │  pam_unix.so               │
│                  │ ──────► │  pam_google_authenticator  │
│  负责:           │         │  pam_permit.so ...          │
│  - 发起认证      │         │  负责:                       │
│  - 显示提示      │         │  - 验密码 / 验 OTP           │
│  - 收集用户输入  │         │  - 读 ~/.google_authenticator│
└──────────────────┘         └─────────────────────────────┘
         │                                ▲
         │    /etc/pam.d/<服务名> 决定栈顺序 │
         └────────────────────────────────┘
```

- **你要写的是左边**：调用 `libpam` 的 C/Go/Python 等程序。
- **`pam_google_authenticator.so` 是右边**：已写好，不用改，只要在 `/etc/pam.d/` 里配置即可。

本仓库 `examples/demo.c` **不是**标准写法（它直接调 `pam_sm_authenticate` 做单元测试）。  
标准写法见 **`examples/pam_client_example.c`**。

---

## 2. 标准 API 调用流程

```
pam_start(服务名, 用户名, &conv, &pamh)
    │
    ▼
pam_set_item(pamh, PAM_RHOST, ...)   // 可选
    │
    ▼
pam_authenticate(pamh, 0)            // 执行 auth 栈 → 密码 + OTP
    │
    ▼
pam_acct_mgmt(pamh, 0)                 // 执行 account 栈
    │
    ▼
pam_open_session(pamh, 0)             // 可选，session 栈
    │
    ▼
... 你的业务逻辑 ...
    │
    ▼
pam_close_session / pam_end
```

**服务名** 必须与 `/etc/pam.d/<服务名>` 文件名一致，例如 `pam_start("myapp", ...)` → `/etc/pam.d/myapp`。

---

## 3. 核心：实现 `pam_conv` 对话函数

PAM 模块 **不能** 自己读键盘，必须通过应用程序的 **`pam_conv` 回调** 显示提示并获取输入。

```c
static int pam_conv_func(int num_msg,
                         const struct pam_message **msg,
                         struct pam_response **resp,
                         void *appdata_ptr) {
  *resp = calloc(num_msg, sizeof(struct pam_response));

  for (int i = 0; i < num_msg; i++) {
    switch (msg[i]->msg_style) {
    case PAM_PROMPT_ECHO_OFF:   // 密码、OTP（不回显）
    case PAM_PROMPT_ECHO_ON:    // 回显提示
      printf("%s ", msg[i]->msg);
      fgets(buf, ...);
      (*resp)[i].resp = strdup(buf);
      break;
    case PAM_ERROR_MSG:
      fprintf(stderr, "%s\n", msg[i]->msg);
      break;
    case PAM_TEXT_INFO:
      fputs(msg[i]->msg, stdout);
      break;
    }
  }
  return PAM_SUCCESS;
}

struct pam_conv conv = { .conv = pam_conv_func, .appdata_ptr = NULL };
```

**双因子时你会被调用两次（双提示配置）：**

1. `pam_unix` → `"Password: "` → 用户输入系统密码  
2. `pam_google_authenticator` → `"Verification code: "` → 用户输入 6 位 OTP  

你的 `conv` 函数只需 **原样显示 msg 并读一行**，不必区分是哪个模块在问。

---

## 4. 完整最小示例

源码：`examples/pam_client_example.c`

### 4.1 编译

```bash
cd examples
gcc -Wall -o pam_client_example pam_client_example.c -lpam
```

### 4.2 创建 PAM 配置

```bash
sudo tee /etc/pam.d/myapp << 'EOF'
# 双因子：密码 + OTP
auth       required   pam_unix.so
auth       required   pam_google_authenticator.so

# 账户/会话：最小可运行
account    required   pam_unix.so
account    required   pam_permit.so
session    required   pam_permit.so
EOF
```

用户须已运行 `google-authenticator -t` 生成 `~/.google_authenticator`。

### 4.3 运行

```bash
./pam_client_example myapp alice
```

预期交互：

```
Password: ********
Verification code: 123456
认证成功，服务=myapp 用户=alice
```

---

## 5. 与 google-authenticator 模块的配合

### 5.1 双提示（推荐自定义程序）

```
auth required pam_unix.so
auth required pam_google_authenticator.so
```

程序 `pam_conv` 被调用两次，逻辑最简单。

### 5.2 单提示（password+OTP 拼接）

```
auth required pam_google_authenticator.so forward_pass
auth required pam_unix.so use_first_pass
```

`pam_conv` **只调用一次**，提示 `"Password & verification code: "`，用户输入 `password123456`。

### 5.3 模块参数

写在同一行后面，例如：

```
auth required pam_google_authenticator.so nullok debug
auth required pam_google_authenticator.so secret=/var/otp/${USER}/.google_authenticator
```

---

## 6. 必须注意的实现细节

### 6.1 需要 TTY

交互式 `fgets(stdin)` 需要控制终端。若程序从 cron/systemd 无 TTY 启动，**无法弹 OTP**。

做法：

- 像 `demo.c` / `pam_client_example.c` 一样 `open("/dev/tty")` 绑定 stdin  
- 或改用 GUI/网络把 OTP 传给 `pam_set_item(pamh, PAM_AUTHTOK, ...)` + `use_first_pass`（高级）

### 6.2 用户名

```c
pam_start("myapp", "alice", &conv, &pamh);
```

`pam_unix` 和 `pam_google_authenticator` 都会用该用户名找 shadow 和 `~alice/.google_authenticator`。

### 6.3 PAM_RHOST

`grace_period` 功能读 `PAM_RHOST`：

```c
pam_set_item(pamh, PAM_RHOST, client_ip_string);
```

### 6.4 权限

- 程序 **不需要 root** 即可调用 `pam_authenticate`（sshd 也不是 root 验密码）。  
- `pam_google_authenticator` 内部会 **降权** 到目标用户再读密钥文件。

### 6.5 敏感数据

`pam_response` 里存了密码，用完后 `explicit_bzero` + `free`（见示例）。

### 6.6 返回值

| 返回值 | 含义 |
|--------|------|
| `PAM_SUCCESS` | 该模块通过 |
| `PAM_AUTH_ERR` | 认证失败 |
| `PAM_IGNORE` | 模块跳过（如 nullok 且无密钥文件） |

`pam_authenticate` 整体成功要求 auth 栈策略满足（所有 `required` 成功等）。

---

## 7. 守护进程 / 网络服务集成模式

### 模式 A：每个连接在子进程里做 PAM（类似 sshd）

```
accept() → fork()
  子进程: pam_start → pam_authenticate (conv 读写 network/socket 或 tty)
  成功 → 进入业务协议
  失败 → 断开
```

### 模式 B：先 PAM 再发 token（应用层会话）

```
1. 登录接口: pam_authenticate 双因子
2. 成功 → 签发 JWT/session cookie
3. 后续请求带 token，不再走 PAM
```

### 模式 C：仅敏感操作走 PAM

平时用普通会话；执行危险操作前 **再调一次** `pam_authenticate`（或单独 PAM 服务名 `myapp-privileged`）。

---

## 8. 其他语言

### Python（python-pam / pam 包）

```python
import pam

p = pam.pam()
p.authenticate("alice", "password")  # 仅密码，OTP 需扩展 conv
```

标准 Python pam 绑定对 **多轮 conv** 支持有限；生产环境更常见：

- 用 **ctypes 调 libpam** 自写 conv  
- 或 **子进程调用** 已 PAM 化的 C 工具  
- 或 **应用层 TOTP**（读同一密钥文件或数据库，不经过 PAM）

### Go

使用 `github.com/msteinert/pam` 等库，同样需实现 `Conversation` 接口处理多轮提示。

---

## 9. 调试 checklist

```bash
# 1. 模块是否安装
ls /lib/*/security/pam_google_authenticator.so

# 2. 用户是否注册
sudo -u alice test -f ~alice/.google_authenticator && echo OK

# 3. PAM 配置语法
sudo pam-auth-update --package  # Debian 系谨慎，别覆盖手工配置

# 4. 用示例程序隔离测试
./pam_client_example myapp alice

# 5. 开 debug
# /etc/pam.d/myapp 里加: pam_google_authenticator.so debug
sudo tail -f /var/log/auth.log
```

---

## 10. 与「sudo 包装启动」对比

| 方式 | 优点 | 缺点 |
|------|------|------|
| 自研 PAM 客户端 | 完全控制 UX、可嵌入服务 | 需写 C/绑定、处理 TTY |
| `sudo /path/app` | 零代码，改 pam.d/sudo 即可 | 必须是命令行、交互式 |
| 应用内 TOTP 库 | 灵活、可 Web | 不经过 PAM，需自管密钥 |

---

## 11. 相关文件

| 文件 | 说明 |
|------|------|
| `examples/pam_client_example.c` | 标准 libpam 客户端示例 |
| `examples/demo.c` | 测试 harness，非生产模板 |
| `src/pam_google_authenticator.c` | 模块如何调 `converse()` |
| `docs/PRACTICAL_2FA_LOGIC_AND_DEPLOYMENT.zh-CN.md` | SSH/sudo 部署 |

---

*总结：自定义程序接入 PAM = 链接 libpam + 实现 pam_conv + pam_start/pam_authenticate + 编写 /etc/pam.d/服务名；双因子只需在配置里 stacked pam_unix 与 pam_google_authenticator。*
