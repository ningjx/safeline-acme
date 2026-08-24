"""通用校验工具"""
import re

# 合法域名/泛域名：仅允许 字母 数字 连字符 点 与开头单个通配符；
# 明确拒绝路径分隔符、'..'、空白、协议前缀等，防止路径穿越
_DOMAIN_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
DOMAIN_RE = re.compile(rf"^(?:\*\.)?(?:{_DOMAIN_LABEL}\.)*{_DOMAIN_LABEL}\.(?:[a-zA-Z]{{2,}})$")


def is_valid_domain(value):
    """是否为合法域名（含可选 *. 前缀，如 example.com、*.example.com）"""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v or len(v) > 253:
        return False
    if "/" in v or "\\" in v or ".." in v or " " in v:
        return False
    return bool(DOMAIN_RE.fullmatch(v))


def is_valid_cert_name(value):
    """托管证书主域名必须是普通域名（不允许通配符）"""
    if not is_valid_domain(value):
        return False
    return not value.startswith("*")


def sanitize_domains(raw_text):
    """把逗号分隔的域名文本解析为合法域名列表（非法的直接丢弃）"""
    out = []
    for part in (raw_text or "").replace("，", ",").split(","):
        d = part.strip()
        if is_valid_domain(d) and d not in out:
            out.append(d)
    return out