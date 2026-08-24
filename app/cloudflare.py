"""Cloudflare 凭据连通性/权限测试（只读，不参与签发流程）

验证方式（依据 Cloudflare 官方 API v4）：
- API Token：GET /user/tokens/verify（官方令牌校验接口）
- Global API Key：GET /zones（X-Auth-Email + X-Auth-Key）
- 附带检查 Zone 访问权限（配置了 CF_ACCOUNT_ID / CF_ZONE_ID 时）
"""
import requests

from .secrets import get_cloudflare


def _call(method, url, headers, proxy, params=None):
    proxies = {"http": proxy, "https": proxy} if proxy else None
    return requests.request(method, url, headers=headers, proxies=proxies,
                            timeout=10, params=params)


def _check_zone_access(cf, proxy):
    """返回 (ok, info_text)。info_text 为附加说明。"""
    headers = {"Authorization": f"Bearer {cf['cf_token']}"}
    if cf.get("cf_zone_id"):
        try:
            r = _call("GET", f"https://api.cloudflare.com/client/v4/zones/{cf['cf_zone_id']}",
                      headers, proxy)
            data = r.json()
            if data.get("success") and data.get("result"):
                return True, f"可访问 Zone: {data['result']['name']}"
            return False, "Token 有效，但无权限访问指定的 Zone ID（请检查 CF_ZONE_ID 与 Token 的 Zone 限制是否匹配）"
        except requests.RequestException:
            return False, ""
    if cf.get("cf_account_id"):
        try:
            r = _call("GET", "https://api.cloudflare.com/client/v4/zones",
                      headers, proxy,
                      params={"account.id": cf["cf_account_id"], "per_page": 5})
            data = r.json()
            if data.get("success"):
                total = (data.get("result_info") or {}).get("total_count", 0)
                names = ", ".join(z.get("name", "") for z in (data.get("result") or [])[:3])
                if total:
                    extra = f"（如 {names}）" if names else ""
                    return True, f"可访问 {total} 个 Zone{extra}"
                return False, "Token 有效，但该账户下未查到 Zone（请确认 CF_ACCOUNT_ID 正确）"
        except requests.RequestException:
            return False, ""
    return True, ""


def test_connection(proxy=""):
    """测试 Cloudflare 凭据是否可用。

    返回 (ok, message)。绝不回显密钥本身。
    """
    cf = get_cloudflare()
    if not (cf.get("cf_token") or (cf.get("cf_key") and cf.get("cf_email"))):
        return False, "未配置 Cloudflare 凭据（CF_TOKEN 或 CF_KEY+CF_EMAIL）"

    try:
        if cf.get("cf_token"):
            # 官方令牌校验接口
            r = _call("GET", "https://api.cloudflare.com/client/v4/user/tokens/verify",
                      {"Authorization": f"Bearer {cf['cf_token']}"}, proxy)
            data = r.json()
            if not data.get("success"):
                errors = data.get("errors") or [{"message": "未知错误"}]
                return False, "Token 无效: " + errors[0].get("message", "")
            result = data.get("result") or {}
            status = result.get("status", "")
            if status != "active":
                return False, f"Token 状态异常: {status or '未知'}"
            expires = result.get("expires_on")
            ok, zone_info = _check_zone_access(cf, proxy)
            msg = "Token 有效" + (f"（{expires} 到期）" if expires else "")
            if not ok:
                msg += "，" + zone_info
            elif zone_info:
                msg += "，" + zone_info
            return ok, msg

        # Global API Key 方案：列出 Zone 验证邮箱+密钥组合
        r = _call("GET", "https://api.cloudflare.com/client/v4/zones",
                  {"X-Auth-Email": cf["cf_email"], "X-Auth-Key": cf["cf_key"]},
                  proxy, params={"per_page": 1})
        data = r.json()
        if not data.get("success"):
            errors = data.get("errors") or [{"message": "未知错误"}]
            return False, "Global API Key 无效: " + errors[0].get("message", "")
        total = (data.get("result_info") or {}).get("total_count", 0)
        return True, f"Global API Key 有效，账户下有 {total} 个 Zone"
    except requests.RequestException as e:
        return False, f"无法连接 Cloudflare API: {e}"