# Google-AuTHENTICATION-LIBPAM Analyse 

> 最近发现一个比较有意思的一个github项目，趁着有时间分析一下，算法设计很曼妙，理解透算法设计有点难，从分析项目逻辑结构，整个算法的设计逻辑出发，重点在于项目的集成应用。

项目地址：[google-authenticator-libpam](https://github.com/google/google-authenticator-libpam)

这是：

- 一个 Linux PAM（Pluggable Authentication Modules）认证插件，在用户名/密码之外增加第二因子（TOTP 或 HOTP 动态码，或一次性应急码）。
- 一套 RFC 4226（HOTP）/ RFC 6238（TOTP） 的服务端参考实现，算法与 Google Authenticator 等主流 App 兼容。
- 一个 「文件契约驱动」 的双组件系统：CLI 负责写密钥文件，PAM 模块负责读文件并验证。

## PAM 服务
PAM 是 Linux/Unix 上可插拔的认证框架。应用程序（如 `sshd`、`login`、`sudo`）不直接验证密码，而是调用 `libpam`，由配置文件 `/etc/pam.d/<service>` 定义的 **模块栈（stack）** 依次执行。


PAM 配置行格式：type control module [options]

常用 control 值：

| 标志 | 行为 |
|------|------|
| `required` | 失败记一次失败，**继续执行后续模块** |
| `requisite` | 失败记一次失败，**立即返回**，不执行后续模块 |
| `sufficient` | 成功则可能直接通过整个栈 |
| `optional` | 成败影响不大 |

双因子认证架构设计
```
# /etc/pam.d/sshd 示例
auth required pam_unix.so
auth required pam_google_authenticator.so no_increment_hotp
```
执行顺序：先 `pam_unix` 验证密码，再 `pam_google_authenticator` 验证 OTP。两者都需成功，整个 `auth` 栈才算通过。



## 项目架构分析
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

- 对项目架构的深入认识，具体参考
[Google Authenticator PAM 模块技术详解](./PAM_MECHANISM.zh-CN.md)

- 关于源码的深度解读，通过GLM生成了一份技术文档，以便更好的理解算法设计
[Google Authenticator (libpam) 源码级技术深析](./TECHNICAL_DEEP_DIVE.zh-CN.md)

![应用逻辑#以ssh服务为例](./Screenshot%20From%202026-07-11%2004-21-33.png)

## 应用集成

### 系统服务集成
> 工程师开发出google pam 二次认证，具体的运维与集成需要用户完成.
在Ubuntu 24 上将其集成到sshd服务，服务集成详细参考文档[Google Authenticator (libpam) 集成](./Google%20Authenticator%20Service%20Integration.md)


### 自定义程序接入
Custom PAM Applications is a very interesting area of research. There is now a guide available, and we will conduct further research on this extension based on the actual project requirements.

guide：
[CUSTOM_PAM_APPLICATION](./CUSTOM_PAM_APPLICATION.zh-CN.md)


综合的一篇技术文档[PRACTICAL_2FA_LOGIC_AND_DEPLOYMENT](./PRACTICAL_2FA_LOGIC_AND_DEPLOYMENT.zh-CN.md)，针对项目框架，Auth逻辑，以及在不通服务中集成Google-AuTHENTICATION-LIBPAM的检验指导。






