"""敏感凭据：只从容器环境变量读取（docker-compose 配置），不落盘、不进 Web 配置

- 雷池 API Token、Cloudflare 密钥均在此提供
- 任何模块都不要把这些值写入 config.json / state.json / 日志
"""
import os


def get_safeline():
    """雷池 OPEN API 凭据（X-SLCE-API-TOKEN）"""
    return {
        "base_url": os.environ.get("SAFELINE_BASE_URL", "").strip(),
        "api_token": os.environ.get("SAFELINE_API_TOKEN", "").strip(),
        # 雷池默认自签证书，一般保持 0；给雷池配了受信任证书后可置 1
        "verify_ssl": os.environ.get("SAFELINE_VERIFY_SSL", "0") == "1",
    }


def get_cloudflare():
    """Cloudflare 凭据（acme.sh 官方 dns_cf 插件支持三种方案，任选其一）

    方案一 / 二：新式 API Token（推荐）
      CF_TOKEN + CF_ACCOUNT_ID   （token 允许访问多个 Zone）
      CF_TOKEN + CF_ZONE_ID      （token 限制到单个 Zone，免填 Account ID）
    方案三：老式 Global API Key
      CF_KEY + CF_EMAIL
    参考官方文档: https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf
    """
    return {
        "cf_token": os.environ.get("CF_TOKEN", ""),
        "cf_account_id": os.environ.get("CF_ACCOUNT_ID", ""),
        "cf_zone_id": os.environ.get("CF_ZONE_ID", ""),
        "cf_key": os.environ.get("CF_KEY", ""),
        "cf_email": os.environ.get("CF_EMAIL", ""),
    }


def cloudflare_configured():
    """Cloudflare 凭据满足任一官方方案即视为已配置"""
    cf = get_cloudflare()
    if cf["cf_token"]:
        # 官方文档要求 Token 配合 Account ID（多 Zone）或 Zone ID（单 Zone）
        return bool(cf["cf_account_id"] or cf["cf_zone_id"])
    return bool(cf["cf_key"] and cf["cf_email"])


def secrets_configured():
    """雷池与 Cloudflare 凭据都配置了吗"""
    sl = get_safeline()
    return bool(sl["base_url"] and sl["api_token"]) and cloudflare_configured()