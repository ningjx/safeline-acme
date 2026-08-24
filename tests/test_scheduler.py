"""本地测试：调度器续期决策逻辑（使用 Mock acme，不与真实雷池交互）"""
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 注意：本测试使用独立的配置文件（雷池地址留空），绝不会访问真实雷池
os.environ["CONFIG_PATH"] = os.path.join(os.path.dirname(__file__), "..", "testdata", "scheduler_test_config.json")
os.environ["STATE_PATH"] = os.path.join(os.path.dirname(__file__), "..", "testdata", "scheduler_test_state.json")
os.environ["ACME_HOME"] = os.path.join(os.path.dirname(__file__), "..", "testdata", "acme.sh")
# Cloudflare 凭据来自环境变量（secrets.py）
os.environ.setdefault("CF_TOKEN", "test-cf-token")
os.environ.setdefault("CF_ACCOUNT_ID", "test-acct")
# 雷池凭据也来自环境变量；指向本机未监听端口（连接立即被拒绝，不触网）
os.environ.setdefault("SAFELINE_BASE_URL", "https://127.0.0.1:45673")
os.environ.setdefault("SAFELINE_API_TOKEN", "test-token")

from app.config import ConfigManager, StateManager
from app.tasks import TaskRunner


class MockAcme:
    def __init__(self, expiry, crt_path, key_path, has_cert=True, sans=None):
        self._expiry = expiry
        self.renew_calls = []
        self.issue_calls = []
        self.crt_path = crt_path
        self.key_path = key_path
        self.has_cert = has_cert
        self.sans = sans
    installed = True

    def cert_files(self, name, keylength):
        if not self.has_cert:
            return (None, None)
        return (self.crt_path, self.key_path)

    def cert_expiry(self, path):
        return (self._expiry, self._expiry - timedelta(days=89))

    def cert_sans(self, path):
        return self.sans

    def issue(self, *args, **kwargs):
        self.issue_calls.append((args[0], kwargs.get("force", False)))
        return "ok"

    def renew(self, name, server, cf_cfg, proxy, force=False):
        self.renew_calls.append((name, force))
        return "ok"

    def read_cert(self, name, keylength):
        with open(self.crt_path) as f:
            crt = f.read()
        with open(self.key_path) as f:
            key = f.read()
        return crt, key


class FakeSafeline:
    """伪造雷池客户端：新建证书时返回固定 ID，用于测试 ID 回写"""
    configured = True

    def __init__(self):
        self.created = []

    def upsert_cert(self, cert_id, crt, key):
        if cert_id:
            return cert_id
        return 42


def _seed_config():
    """写入测试专用配置：邮箱齐备；雷池地址留空（凭据走环境变量，本测试不触网）"""
    import json
    cfg = {
        "acme": {"email": "test@example.com", "ca_server": "letsencrypt", "keylength": "ec-256", "proxy": ""},
        "schedule": {"enabled": True, "check_interval_hours": 12, "renew_days_before_expiry": 30},
        "certs": [{
            "name": "example.com",
            "domains": ["example.com", "*.example.com"],
            "safeline_id": 0,
            "enabled": True,
        }],
    }
    with open(os.environ["CONFIG_PATH"], "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def main():
    _seed_config()
    root = os.path.join(os.path.dirname(__file__), "..")
    crt_p = os.path.join(root, "testdata", "fake_fullchain.pem")
    key_p = os.path.join(root, "testdata", "fake_key.pem")
    os.makedirs(os.path.dirname(crt_p), exist_ok=True)
    # 用占位 PEM 内容即可（Mock 测试只读取文件内容，不解析证书）
    dump_crt = "-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----\n"
    dump_key = "-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----\n"
    open(crt_p, "w").write(dump_crt)
    open(key_p, "w").write(dump_key)

    cfg = ConfigManager()
    cert = dict(cfg.get()["certs"][0], safeline_id=0)

    # 场景1：80 天后到期 -> 不应续期（将直接走到推送，Mock 环境读文件即可）
    mock1 = MockAcme(datetime.now(timezone.utc) + timedelta(days=80), crt_p, key_p)
    runner = TaskRunner(cfg, StateManager(), acme=mock1)
    ok, msg, _ = runner.renew_and_push(cert, force=False)
    print("场景1(到期80天):", ok, "|", msg)
    assert mock1.renew_calls == [], mock1.renew_calls

    # 场景2：20 天后到期 -> 自动续期
    mock2 = MockAcme(datetime.now(timezone.utc) + timedelta(days=20), crt_p, key_p)
    runner = TaskRunner(cfg, StateManager(), acme=mock2)
    runner.renew_and_push(cert, force=False)
    print("场景2(到期20天):", mock2.renew_calls)
    assert mock2.renew_calls == [("example.com", False)], mock2.renew_calls

    # 场景3：强制续期
    mock3 = MockAcme(datetime.now(timezone.utc) + timedelta(days=80), crt_p, key_p)
    runner = TaskRunner(cfg, StateManager(), acme=mock3)
    runner.renew_and_push(cert, force=True)
    print("场景3(强制):", mock3.renew_calls)
    assert mock3.renew_calls == [("example.com", True)], mock3.renew_calls

    # 场景4：从未签发过证书 -> 自动走 issue（无需强制）
    mock4 = MockAcme(datetime.now(timezone.utc) + timedelta(days=80), crt_p, key_p, has_cert=False)
    runner = TaskRunner(cfg, StateManager(), acme=mock4)
    runner.renew_and_push(cert, force=False)
    print("场景4(首次申请):", mock4.issue_calls, mock4.renew_calls)
    assert mock4.issue_calls == [("example.com", False)], mock4.issue_calls
    assert mock4.renew_calls == [], mock4.renew_calls

    # 场景4b：证书存在且未到期，但 SAN 与配置不一致 -> 强制按新列表重新签发
    # 模拟：现有证书 SAN=[example.com, old.example.net]，配置改成了 [example.com, *.example.com]
    mock4b = MockAcme(datetime.now(timezone.utc) + timedelta(days=80), crt_p, key_p,
                      sans={"example.com", "old.example.net"})
    runner = TaskRunner(cfg, StateManager(), acme=mock4b)
    runner.renew_and_push(cert, force=False)
    print("场景4b(SAN变更,如新增泛域名):", mock4b.issue_calls)
    assert mock4b.issue_calls == [("example.com", True)], mock4b.issue_calls
    assert mock4b.renew_calls == [], mock4b.renew_calls

    # 场景4c：SAN 与配置完全一致 -> 不重新签发
    mock4c = MockAcme(datetime.now(timezone.utc) + timedelta(days=80), crt_p, key_p,
                      sans={"example.com"})   # 配置 [example.com, *.example.com] 规范化后同为 {example.com}
    runner = TaskRunner(cfg, StateManager(), acme=mock4c)
    runner.renew_and_push(cert, force=False)
    print("场景4c(SAN一致):", mock4c.issue_calls, mock4c.renew_calls)
    assert mock4c.issue_calls == [] and mock4c.renew_calls == [], (mock4c.issue_calls, mock4c.renew_calls)

    # 场景5：定时调度停用 -> 周期检查跳过；wake 保存配置后的 force 检查仍执行
    cfg5 = ConfigManager()
    d5 = cfg5.get()
    d5["schedule"]["enabled"] = False
    cfg5.update(d5)
    mock5 = MockAcme(datetime.now(timezone.utc) + timedelta(days=20), crt_p, key_p)
    runner5 = TaskRunner(cfg5, StateManager(), acme=mock5)
    runner5.check_all(force=False)
    assert mock5.issue_calls == [] and mock5.renew_calls == [], mock5.renew_calls
    runner5.check_all(force=True)
    print("场景5(停用调度 + force):", mock5.renew_calls)
    assert mock5.renew_calls == [("example.com", False)], mock5.renew_calls

    # 场景6：ID=0 新建推送成功后，雷池返回的新 ID 自动回写配置（后续续签原地更新）
    cfg6 = ConfigManager()
    mock6 = MockAcme(datetime.now(timezone.utc) + timedelta(days=80), crt_p, key_p)
    runner6 = TaskRunner(cfg6, StateManager(), acme=mock6)
    runner6._safeline = lambda: FakeSafeline()
    assert cfg6.get_cert("example.com")["safeline_id"] == 0
    ok, msg, detail = runner6.push_to_safeline("example.com", "ec-256", 0, force=True)
    print("场景6(新建推送+ID回写):", ok, msg, detail)
    assert ok and detail.get("safeline_id") == 42, detail
    assert cfg6.get_cert("example.com")["safeline_id"] == 42
    # 再次推送仍走原地更新路径（不再新建）
    ok2, msg2, detail2 = runner6.push_to_safeline("example.com", "ec-256", None, force=True)
    print("场景6b(后续推送走原地更新):", ok2, msg2, detail2)
    assert detail2.get("safeline_id") == 42

    print("SCHEDULER LOGIC TESTS PASSED")


if __name__ == "__main__":
    main()