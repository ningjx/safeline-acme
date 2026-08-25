# Safeline ACME 证书助手

解决雷池（SafeLine）WAF 内置免费证书只能使用 **Let's Encrypt HTTP-01** 验证、且防火墙屏蔽境外 IP 导致无法申请证书的问题。

本工具使用官方 [acme.sh](https://github.com/acmesh-official/acme.sh)（ACME 客户端）+ **Cloudflare DNS 验证（dns_cf）** 申请/续期证书，然后调用**雷池 OPEN API** 将证书新增 / 更新到雷池，全程自动、可在内网运行（无需公网 80/443 端口）。

- Web 管理界面：查看系统/证书状态、管理托管域名（新增/续期/删除）
- **敏感凭据（雷池 Token、Cloudflare 密钥）只配置在 docker-compose 环境变量中**，Web 不可见、不写入磁盘
- 配置与证书数据挂载到宿主机目录，容器重建不丢失
- 纯 Python（Flask）实现，提供 Dockerfile 与 docker-compose 示例

## 架构

```
┌─────────────────────────────────────────────┐
│            safeline-acme 容器                │
│                                             │
│  Web 界面 (Flask :8080，无登录，局域网只读展示)  │
│      │                                      │
│      ├─ 后台定时任务（Python 调度）            │
│      │      │                               │
│      │      ├─ acme.sh --issue/renew         │──▶ Let's Encrypt / ZeroSSL（DNS-01）
│      │      │     --dns dns_cf               │        │
│      │      │                                │        ▼
│      │      │                                │   Cloudflare API（添加/删除 TXT 记录）
│      │      │                                │        ▲ CF_TOKEN 等来自环境变量
│      │      └─ 读取证书 fullchain.cer + key   │
│      │             │                         │
│      │             ▼                         │
│      │   POST /api/open/cert (X-SLCE-API-TOKEN) ──▶ 雷池 WAF
│      │                          ▲ 凭据来自环境变量（新增/更新证书）
└─────────────────────────────────────────────┘
```

## 环境要求

- Docker 或 Docker Compose
- 一个已接入 Cloudflare DNS 的域名（支持泛域名）
- 雷池 WAF（社区版即可），能访问其管理端口（默认 `9443`）

## 快速开始

### 1. 获取雷池 API Token

登录雷池 Web 控制台 → 右上角 **用户图标 → 个人中心 → OPEN API** → 添加一个 OPEN API TOKEN，权限勾选证书相关（`ssl_cert`）模块。Token 用于请求头 `X-SLCE-API-TOKEN`。

### 2. 获取 Cloudflare 凭据（三种方案任选其一）

Cloudflare 有两代凭据体系：老式 **Global API Key**（一把全权限钥匙）和新式 **API Token**（可精细限权，官方推荐）。acme.sh 官方 dns_cf 插件对两者都支持：

**① 推荐：API Token + Account ID**（适用于 Token 能访问多个 Zone）

1. 打开 [API Token 页面](https://dash.cloudflare.com/profile/api-tokens) →「创建令牌」→ 使用「编辑区域 DNS」模板
2. 权限保持 `Zone.Zone:Read` + `Zone.DNS:Edit`
3. Account ID：登录 dash.cloudflare.com 后点击右上角账户 →「账户主页」，右侧 API 区块可复制；或看地址栏 `https://dash.cloudflare.com/<32位十六进制>` 这一段

**② 免 Account ID：API Token 限制到单个 Zone + Zone ID**

创建 API Token 时把「区域资源」限制为**具体的一个域名**，然后填 `CF_ZONE_ID`（在 Cloudflare 对应域名的「概述」页右侧 API 区块可复制）即可，不需要 Account ID。

**③ 老式 Global API Key + 邮箱**

在 [API Tokens 页面](https://dash.cloudflare.com/profile/api-tokens) 的「API 密钥」区点击「查看」Global API Key，配 Cloudflare 登录邮箱使用。权限过大（等于账号完全控制权），仅建议自有账号使用。

> 这三种写法即 acme.sh 官方文档 [dnsapi#dns_cf](https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf) 定义的 `CF_Token/CF_Account_ID`、`CF_Token/CF_Zone_ID`、`CF_Key/CF_Email` 三组变量，本工具一一对应。

### 3. 配置 docker-compose.yml（敏感凭据只在这里配置）

编辑 `docker-compose.yml` 的 `environment` 段：

```yaml
environment:
  - SAFELINE_BASE_URL=https://192.168.50.100:9443   # 雷池管理地址
  - SAFELINE_API_TOKEN=你的雷池API Token            # 雷池 OPEN API Token
  - CF_TOKEN=你的Cloudflare API Token
  - CF_ACCOUNT_ID=你的Cloudflare Account ID
  # 可选：- CF_ZONE_ID=单Zone时可指定
  # 可选：- SAFELINE_VERIFY_SSL=1（给雷池配了受信任正式证书时才开启）
  # 可选：Web 界面登录（HTTP Basic Auth），默认免登录；置 1 后需填用户名/密码
  #       - WEB_AUTH_ENABLED=1
  #       - WEB_AUTH_USERNAME=admin
  #       - WEB_AUTH_PASSWORD=请设置强密码
```

### 4. 构建并启动

```bash
cd safeline_acme
docker compose up -d --build
```

### 5. 打开管理界面（局域网访问，默认免登录）

访问 `http://<宿主机IP>:8080`（若启用了 `WEB_AUTH_ENABLED=1`，浏览器会弹出登录框）：

1. **配置页**（只展示凭据状态，密钥不可见；可点「测试雷池连接」「测试 Cloudflare 连接」）：
   - ACME 注册邮箱、CA（Let's Encrypt / ZeroSSL）、密钥类型
   - 定时调度：检查间隔、提前续期天数
   - **托管域名**：主域名 + 覆盖域名（逗号分隔，可含泛域名 `*.example.com`）+ 雷池证书 ID
2. 保存后自动在后台申请未签发的证书（「总览」页可看雷池与 Cloudflare 连接状态）；
   也可到「证书管理」页手动点「申请+推送」；以后续期全自动。

> **雷池证书 ID 说明**：填雷池中已存在的证书 ID = **原地更新**（站点继续引用，不中断）；
> 填 `0` = **新建**（站点需选择一次该证书），新建成功后工具会自动把雷池返回的新 ID **回写**到配置，
> 此后每次续签都自动原地更新这张证书，不会重复新建。
> 
> **域名列表变更说明**：修改托管域名的覆盖域名（如新增 `*.example.com`）后，保存即自动按新列表
> **强制重新签发**（工具会比对现有证书的 SAN 与实际配置）。

## Web 权限模型（重要）

- **默认免登录**（适合可信局域网），页面整体为**只读展示**
- 允许的写操作只有三种：
  1. **新增域名**（配置页保存托管域名列表）
  2. **续期**（单个域名「续期+推送」/ 总览页「执行一次续期+推送」）
  3. **删除域名**（移除托管条目 + 删除本地 acme.sh 证书；雷池侧证书请在雷池后台删除）
- 不存在任何能读取文件内容、环境变量或任意路径的接口；所有域名输入均做格式校验，拒绝路径穿越字符（`/`、`\`、`..`、空白等）
- 「证书管理」页底部展示雷池中的全部证书，仅供查看（含被哪些站点引用）
- **可选登录**：设置 `WEB_AUTH_ENABLED=1` 并配置 `WEB_AUTH_USERNAME` / `WEB_AUTH_PASSWORD` 后，
  除健康检查接口（`/health`、`/ready`）外的所有页面与 API 均需 HTTP Basic Auth
  （凭据只存在于容器环境变量，不落盘；用户名密码用常数时间比对）
- **健康检查**：`GET /health` 返回存活状态，`GET /ready` 返回 acme/雷池/Cloudflare 配置状态；
  纯只读、无需鉴权，可直接用于 Docker healthcheck 或 Uptime Kuma 等监控

## 目录结构

```
safeline_acme/
├── app/
│   ├── main.py          # Flask Web 服务与路由（只读 + 三个写操作）
│   ├── config.py        # 非敏感配置/状态管理（/data/config.json、/data/state.json）
│   ├── secrets.py       # 敏感凭据：仅从环境变量读取（雷池 Token、Cloudflare 密钥）
│   ├── acme_client.py   # acme.sh 封装（申请、续期、删除、读取证书，含域名校验）
│   ├── safeline.py      # 雷池 OPEN API 客户端（支持增/删/改/查，Web 仅暴露查+增改）
│   ├── tasks.py         # 核心任务（续期+推送）与后台调度
│   ├── utils.py         # 域名校验（防路径穿越）
│   ├── templates/       # Web 页面
│   └── static/          # 前端资源
├── tests/               # 本地测试（不访问真实雷池）
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh        # 启动时安装 acme.sh（含 dnsapi 插件）
├── requirements.txt
└── README.md
```

宿主机数据目录（`./data`）：

```
data/
├── config.json          # 非敏感 Web 配置（域名/调度/ACME 参数），不含任何密钥
├── state.json           # 运行状态/日志
└── acme.sh/             # acme.sh 脚本、账号、证书（重建容器不丢）
```

## API 说明（依据官方文档）

### 雷池 OPEN API

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/open/cert` | GET | 列出证书 |
| `/api/open/cert` | POST | 新增/更新证书（`type:2` 手动证书，`id` 传 0 新建 / 传已有 ID 原地更新） |
| `/api/open/cert/{id}` | GET | 证书详情 |
| `/api/open/cert/{id}` | DELETE | 删除证书（被站点引用时会被拒绝；本 Web 界面未开放此操作） |
| `/api/open/system` | GET | 系统信息 |

认证：请求头 `X-SLCE-API-TOKEN: <token>`。参考：雷池官方 [OPEN API 使用教程](https://help.waf-ce.chaitin.cn/node/01973fc6-e25e-7eda-8ea8-dae97bdd4213)、[官方仓库讨论 #1148](https://github.com/chaitin/SafeLine/discussions/1148)。

### acme.sh（Cloudflare DNS）

- 环境变量：`CF_Token`、`CF_Account_ID`（可选 `CF_Zone_ID`）
- 签发：`acme.sh --issue --dns dns_cf -d example.com -d '*.example.com' --keylength ec-256`
- 续期：`acme.sh --renew -d example.com --force`（本工具按「距到期不足 N 天」触发）
- 参考：[acme.sh 官方文档](https://github.com/acmesh-official/acme.sh/wiki/说明)、[DNS API dns_cf](https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf)

## 常见问题

**Q: 容器无法访问境外 CA / Cloudflare？**
在「配置」页的 HTTP 代理中填写代理地址（如 `http://代理IP:7890`）。

**Q: 提示 CF Token 权限不足？**
确保 Token 有 `Zone.DNS:Edit` 与 `Zone.Zone:Read` 权限，并覆盖到目标域名所在 Zone。

**Q: 提示 ACME 注册邮箱被拒绝？**
CA（Let's Encrypt）拒绝 `example.com` 等保留域名的联系邮箱，请换成真实邮箱；这也会阻止证书签发。

**Q: 更新雷池证书后站点没生效？**
更新已有 ID 时雷池会自动重载证书；若等待几分钟仍未生效，可在雷池控制台确认证书详情，或重启雷池容器。

**Q: 新建证书（ID=0）后站点无法使用？**
新建的证书需在雷池「站点」配置中重新选择该证书。

**Q: 删除域名后雷池里的证书还在？**
删除域名只清理本工具侧（配置 + acme.sh 本地证书）。雷池侧证书请登录雷池后台解除站点引用后手动删除（防止误删正在使用的证书）。

**Q: Web 不设密码安全吗？**
默认面向受信任的局域网使用。凭据（Token/密钥）完全不会出现在 Web 与磁盘配置中，Web 被探测时最多触发续期/删除域名操作。如需公网暴露或更严格的内网环境，请设置 `WEB_AUTH_ENABLED=1` 启用登录，并搭配反向代理 + TLS。

## 安全提示

- 密钥只存在于容器环境变量与 acme.sh 的 account.conf（acme.sh 原生行为），不要提交 `data/` 目录或 `docker-compose.yml` 中的真实密钥到代码仓库
- 建议限制 `8080` 端口仅监听局域网网卡，或由防火墙限制来源
- `SAFELINE_VERIFY_SSL` 仅在雷池配置了受信任证书后开启（默认雷池自签证书不支持校验）

## License

仅供学习研究使用；请遵循 acme.sh（GPLv3+）与雷池的相关许可。