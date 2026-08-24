"""本地安全测试：
- 路径穿越攻击被拒绝（域名校验）
- 已移除的危险接口返回 404（推送到任意证书 ID / 删除雷池证书 / 登录页）
- 通过 Web 提交的敏感字段被白名单丢弃，绝不落盘
- 任何接口都不回显环境变量中的密钥
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["CONFIG_PATH"] = os.path.join(os.path.dirname(__file__), "..", "testdata", "security_test_config.json")
os.environ["STATE_PATH"] = os.path.join(os.path.dirname(__file__), "..", "testdata", "security_test_state.json")
os.environ["ACME_HOME"] = os.path.join(os.path.dirname(__file__), "..", "testdata", "acme.sh")
os.environ["SAFELINE_BASE_URL"] = "https://127.0.0.1:45673"   # 本机未监听端口，连接立即被拒绝（不触网）
os.environ["SAFELINE_API_TOKEN"] = "SECRET-SAFELINE-TOKEN"
os.environ["CF_TOKEN"] = "SECRET-CF-TOKEN"
os.environ["CF_ACCOUNT_ID"] = "SECRET-CF-ACCOUNT"

from app import main as app_module
from app.utils import is_valid_domain, is_valid_cert_name, sanitize_domains

SECRETS = ["SECRET-SAFELINE-TOKEN", "SECRET-CF-TOKEN", "SECRET-CF-ACCOUNT"]


def test_domain_validation():
    # 合法
    for ok in ["example.com", "*.example.com", "auth.ning.host", "a-b.c-d.example.co",
               "x.example.co.uk", "my-domain123.example.net"]:
        assert is_valid_domain(ok), ok
    assert is_valid_cert_name("example.com")
    # 非法（路径穿越/注入）
    for bad in ["../etc/passwd", "..\\..\\etc", "a/b", "a..b", "a b", "example.com/../../x",
                "%2e%2e", "example.com;rm -rf /", "*.", "*.com", "-bad.com", "bad-.com",
                "a..com", "example.com/", "www..com", "http://example.com", "", None,
                "/etc/passwd", "a" * 300, "x com", "com"]:
        assert not is_valid_domain(bad), repr(bad)
    assert not is_valid_cert_name("*.example.com")   # 主域名不允许通配符
    # sanitize_domains 丢弃非法项
    assert sanitize_domains("a.com, ../x, b.com") == ["a.com", "b.com"]
    print("domain validation OK")


def test_pages_render():
    c = app_module.app.test_client()
    for path in ["/", "/config", "/certs", "/logs", "/api/status", "/api/logs"]:
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code)
    print("pages render OK")


def test_path_traversal_blocked():
    c = app_module.app.test_client()
    for name in ["../../etc/passwd", "..%2F..%2Fetc", "a/b", "..", "...", "a..b", "/etc/passwd"]:
        for action in ["renew", "delete"]:
            r = c.post(f"/api/certs/{name}/{action}")
            # 非法域名一律 404，且绝不应触发文件读取或任务执行
            assert r.status_code == 404, (name, action, r.status_code)
    print("path traversal blocked OK")


def test_removed_endpoints_gone():
    c = app_module.app.test_client()
    for path, method in [("/login", "GET"), ("/login", "POST"), ("/logout", "GET"),
                         ("/api/safeline/certs/1/delete", "POST"),
                         ("/api/safeline/certs/1/push", "POST"),
                         ("/api/certs/x/push", "POST")]:
        r = getattr(c, method.lower())(path, data={"password": "x"})
        assert r.status_code == 404, (path, method, r.status_code)
    print("removed endpoints gone OK")


def test_secret_fields_stripped_from_config():
    c = app_module.app.test_client()
    # 尝试通过 Web 提交注入敏感字段
    r = c.post("/config", data={
        "safeline_base_url": "https://evil.example.com",
        "safeline_api_token": "INJECTED-SAFELINE",
        "cf_token": "INJECTED-CF",
        "web_password": "hunter2",
        "acme_email": "test@ning.host",
        "acme_ca_server": "letsencrypt",
        "acme_keylength": "ec-256",
        "schedule_enabled": "on",
        "schedule_interval": "12",
        "schedule_renew_days": "30",
        "cert_name": ["example.com"],
        "cert_domains": ["example.com,*.example.com"],
        "cert_safeline_id": ["0"],
        "cert_enabled": ["on"],
    })
    assert r.status_code == 200, r.status_code
    with open(os.environ["CONFIG_PATH"], encoding="utf-8") as f:
        saved = json.load(f)
    text = json.dumps(saved)
    for injected in ["INJECTED-SAFELINE", "INJECTED-CF", "hunter2", "evil.example.com"]:
        assert injected not in text, injected
    assert "safeline" not in saved and "web_password" not in saved and "cloudflare" not in saved
    assert saved["certs"][0]["name"] == "example.com"
    print("secret fields stripped OK")


def test_invalid_domains_rejected_on_save():
    c = app_module.app.test_client()
    r = c.post("/config", data={
        "acme_email": "test@ning.host", "acme_ca_server": "letsencrypt",
        "acme_keylength": "ec-256",
        "cert_name": ["../../etc/passwd", "good.example.com"],
        "cert_domains": ["../x", "good.example.com"],
        "cert_safeline_id": ["0", "0"],
        "cert_enabled": ["on", "on"],
    })
    assert r.status_code == 200
    with open(os.environ["CONFIG_PATH"], encoding="utf-8") as f:
        saved = json.load(f)
    names = [c["name"] for c in saved["certs"]]
    assert names == ["good.example.com"], names
    print("invalid domains rejected OK")


def test_env_secrets_never_exposed():
    c = app_module.app.test_client()
    for path in ["/", "/config", "/certs", "/logs", "/api/status", "/api/logs"]:
        r = c.get(path)
        body = r.data.decode("utf-8", "ignore")
        for secret in SECRETS:
            assert secret not in body, (path, secret)
    # Cloudflare 测试接口：结果中也不允许出现密钥（会用假 Token 请求真实 CF API）
    r = c.post("/api/cloudflare/test")
    assert r.status_code == 200, r.status_code
    body = r.data.decode("utf-8", "ignore")
    for secret in SECRETS:
        assert secret not in body, secret
    assert not r.get_json().get("ok"), "假 Token 不应测试通过"   # 假 Token 必定无效
    print("env secrets not exposed OK")


def main():
    test_domain_validation()
    test_pages_render()
    test_path_traversal_blocked()
    test_removed_endpoints_gone()
    test_secret_fields_stripped_from_config()
    test_invalid_domains_rejected_on_save()
    test_env_secrets_never_exposed()
    print("ALL SECURITY TESTS PASSED")


if __name__ == "__main__":
    main()