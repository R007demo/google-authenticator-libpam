/*
 * 标准 PAM 客户端示例：演示自定义程序如何接入 libpam，
 * 从而使用 pam_unix + pam_google_authenticator 做双因子认证。
 *
 * 编译:
 *   gcc -Wall -o pam_client_example pam_client_example.c -lpam
 *
 * 配置:
 *   创建 /etc/pam.d/myapp （见 docs/CUSTOM_PAM_APPLICATION.zh-CN.md）
 *
 * 运行:
 *   ./pam_client_example myapp
 *   ./pam_client_example myapp alice
 *
 * 注意: 需在真实终端 (TTY) 下运行，否则无法交互输入密码/OTP。
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/* PAM 模块通过 conv 回调向应用程序「要提示、要输入」 */
static int pam_conv_func(int num_msg,
                         const struct pam_message **msg,
                         struct pam_response **resp,
                         void *appdata_ptr) {
  (void)appdata_ptr;
  if (resp == NULL || msg == NULL) {
    return PAM_CONV_ERR;
  }

  *resp = calloc((size_t)num_msg, sizeof(struct pam_response));
  if (*resp == NULL) {
    return PAM_BUF_ERR;
  }

  for (int i = 0; i < num_msg; ++i) {
    const struct pam_message *m = msg[i];
    switch (m->msg_style) {
    case PAM_PROMPT_ECHO_OFF:
    case PAM_PROMPT_ECHO_ON: {
      /* 模块发来的提示，如 "password:" 或 "Verification code:" */
      printf("%s ", m->msg);
      fflush(stdout);

      char buf[512];
      if (fgets(buf, sizeof buf, stdin) == NULL) {
        return PAM_CONV_ERR;
      }
      size_t len = strlen(buf);
      if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
      }
      (*resp)[i].resp = strdup(buf);
      if ((*resp)[i].resp == NULL) {
        return PAM_BUF_ERR;
      }
      (*resp)[i].resp_retcode = 0;
      break;
    }
    case PAM_TEXT_INFO:
      fputs(m->msg, stdout);
      break;
    case PAM_ERROR_MSG:
      fprintf(stderr, "%s\n", m->msg);
      break;
    default:
      return PAM_CONV_ERR;
    }
  }
  return PAM_SUCCESS;
}

static void free_resp(int num_msg, struct pam_response *resp) {
  if (resp == NULL) {
    return;
  }
  for (int i = 0; i < num_msg; ++i) {
    if (resp[i].resp) {
      /* 密码/OTP 用完后清零 */
      explicit_bzero(resp[i].resp, strlen(resp[i].resp));
      free(resp[i].resp);
    }
  }
  free(resp);
}

static int authenticate_user(const char *service, const char *username) {
  struct pam_conv conv = {
      .conv = pam_conv_func,
      .appdata_ptr = NULL,
  };

  pam_handle_t *pamh = NULL;
  int rc = pam_start(service, username, &conv, &pamh);
  if (rc != PAM_SUCCESS) {
    fprintf(stderr, "pam_start 失败: %s\n", pam_strerror(pamh, rc));
    return rc;
  }

  /* 可选: 设置远程主机名，grace_period 等功能会读 PAM_RHOST */
  if (pam_set_item(pamh, PAM_RHOST, "127.0.0.1") != PAM_SUCCESS) {
    fprintf(stderr, "警告: 无法设置 PAM_RHOST\n");
  }

  /* auth 栈: pam_unix + pam_google_authenticator 在此执行 */
  rc = pam_authenticate(pamh, 0);
  if (rc != PAM_SUCCESS) {
    fprintf(stderr, "认证失败: %s\n", pam_strerror(pamh, rc));
    pam_end(pamh, rc);
    return rc;
  }

  /* account 栈: 账户是否允许登录 (过期、时间限制等) */
  rc = pam_acct_mgmt(pamh, 0);
  if (rc != PAM_SUCCESS) {
    fprintf(stderr, "账户检查失败: %s\n", pam_strerror(pamh, rc));
    pam_end(pamh, rc);
    return rc;
  }

  printf("认证成功，服务=%s 用户=%s\n", service, username ? username : "(默认)");

  pam_end(pamh, PAM_SUCCESS);
  return PAM_SUCCESS;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr,
            "用法: %s <PAM服务名> [用户名]\n"
            "示例: %s myapp\n"
            "      %s myapp alice\n"
            "PAM 服务名对应 /etc/pam.d/<服务名>\n",
            argv[0], argv[0], argv[0]);
    return 1;
  }

  const char *service = argv[1];
  const char *user = (argc >= 3) ? argv[2] : NULL;

  /* 若未指定用户，PAM 可能通过 conv 再询问，本例依赖 pam_unix 的默认行为 */
  if (user == NULL) {
    user = getenv("USER");
  }
  if (user == NULL || user[0] == '\0') {
    fprintf(stderr, "请指定用户名或设置 USER 环境变量\n");
    return 1;
  }

  /* 尽量绑定到控制终端，便于交互 */
  int tty = open("/dev/tty", O_RDWR);
  if (tty >= 0) {
    dup2(tty, STDIN_FILENO);
    dup2(tty, STDOUT_FILENO);
    dup2(tty, STDERR_FILENO);
    close(tty);
  }

  return authenticate_user(service, user) == PAM_SUCCESS ? 0 : 1;
}
