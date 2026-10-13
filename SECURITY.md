# Security Policy / 安全策略

cipherlane is a LAN end-to-end encrypted transfer tool. We take the security of
the tool itself seriously — the crypto is only as trustworthy as the code around it.

## Reporting a Vulnerability / 报告漏洞

**Please do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting instead:

- Go to this repository's **Security** tab → **Report a vulnerability**

或者使用 GitHub 私有漏洞报告：

- 进入本仓库的 **Security** 标签页 → **Report a vulnerability**

You can also start a private security advisory via
`https://github.com/<owner>/cipherlane/security/advisories/new`.

We aim to respond within **72 hours** and will credit reporters in the
advisory unless you prefer to remain anonymous.

目标响应时间 **72 小时**；除非你希望匿名，披露时会在公告中致谢。

## Scope note / 范围说明

Before reporting, please check the documented threat model boundaries in
`README.md` (安全模型). The following are **known and documented limitations**,
not vulnerabilities:

- The web app itself is served over plain HTTP — an active on-path attacker
  can replace the served JavaScript (E2EE protects against passive observers only)
- Device-direct mode: public keys are distributed by the server —
  key substitution is detectable via fingerprints but not automatically prevented
- Room IDs transit in plaintext HTTP — chunk stealing / spoofed ack
  (ack proof makes spoofing detectable) are availability-level issues

报告前请先阅读 `README.md` 的安全模型章节；上述已文档化的设计边界
不属于漏洞。
