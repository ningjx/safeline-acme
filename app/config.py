"""配置管理：读取/保存 /data/config.json（挂载到宿主机，容器重建不丢失）"""
import json
import os
import threading
from copy import deepcopy

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/data/config.json")
STATE_PATH = os.environ.get("STATE_PATH", "/data/state.json")

DEFAULTS = {
    # ACME 配置（非敏感项仍在 Web 配置；敏感凭据见 secrets.py，来自环境变量）
    "acme": {
        "email": "",             # ACME 账号邮箱
        "ca_server": "letsencrypt",   # letsencrypt / zerossl
        "keylength": "ec-256",   # ec-256 / ec-384 / 2048
        "proxy": "",             # 可选 http 代理，如 http://proxy:7890
    },
    # 调度配置
    "schedule": {
        "enabled": True,         # 是否启用定时任务
        "check_interval_hours": 12,   # 定时检查间隔（小时）
        "renew_days_before_expiry": 30,  # 距到期不足多少天触发续期
    },
    # 托管证书列表
    # 敏感信息（雷池 API Token / Cloudflare 密钥）不在此存储，
    # 统一由 docker-compose 环境变量提供（见 secrets.py）
    "certs": [],
}


def deep_merge(base, override):
    """递归合并 override 到 base 的副本上"""
    result = deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = deepcopy(v)
    return result


class ConfigManager:
    def __init__(self, path=CONFIG_PATH):
        self.path = path
        # 注意：必须用可重入锁——load() 在缺失配置时会调用 save()，两者都会加锁
        self._lock = threading.RLock()
        self.data = deepcopy(DEFAULTS)
        self.load()

    def load(self):
        with self._lock:
            try:
                if os.path.exists(self.path):
                    with open(self.path, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                    self.data = deep_merge(DEFAULTS, self._sanitize(loaded))
                else:
                    self.data = deepcopy(DEFAULTS)
                    self.save()
            except Exception:
                # 配置文件损坏时回退默认，避免应用无法启动
                self.data = deepcopy(DEFAULTS)

    def save(self):
        with self._lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)

    @staticmethod
    def _sanitize(data):
        """只保留非敏感的已知字段。敏感凭据（雷池 Token、Cloudflare 密钥）
        只存在于环境变量，绝不从 Web/配置文件进入或落盘。"""
        if not isinstance(data, dict):
            return {}
        out = {}
        if isinstance(data.get("acme"), dict):
            out["acme"] = data["acme"]
        if isinstance(data.get("schedule"), dict):
            out["schedule"] = data["schedule"]
        if isinstance(data.get("certs"), list):
            out["certs"] = data["certs"]
        return out

    def get(self):
        with self._lock:
            return deepcopy(self.data)

    def update(self, new_data):
        """整体更新非敏感配置（new_data 为前端提交内容，会先做白名单过滤）"""
        with self._lock:
            merged = deep_merge(DEFAULTS, self._sanitize(new_data))
            # 清理非法证书条目（域名合法性在 main.py 用 utils.is_valid_cert_name 校验）
            merged["certs"] = [
                c for c in merged.get("certs", [])
                if isinstance(c, dict) and c.get("name")
            ]
            self.data = merged
            self.save()
        return self.data

    def get_cert(self, name):
        for c in self.data.get("certs", []):
            if c.get("name") == name:
                return c
        return None

    def remove_cert(self, name):
        """从配置中移除一个托管证书条目，返回是否真的移除过"""
        with self._lock:
            before = self.data.get("certs", [])
            self.data["certs"] = [c for c in before if c.get("name") != name]
            changed = len(self.data["certs"]) != len(before)
            if changed:
                self.save()
            return changed

    def set_cert_safeline_id(self, name, cert_id):
        """把新建推送后雷池返回的证书 ID 回写到托管条目（后续续签原地更新）"""
        cert_id_int = int(cert_id)
        with self._lock:
            for c in self.data.get("certs", []):
                if c.get("name") == name:
                    c["safeline_id"] = cert_id_int
                    self.save()
                    return True
        return False


class StateManager:
    """运行状态：记录每个托管证书最后一次推送的证书哈希、任务日志等"""

    def __init__(self, path=STATE_PATH):
        self.path = path
        # RLock：add_log 等内部互调时避免自锁死
        self._lock = threading.RLock()
        self.data = {"pushed_hashes": {}, "last_results": {}, "logs": []}
        self.load()

    def load(self):
        with self._lock:
            try:
                if os.path.exists(self.path):
                    with open(self.path, "r", encoding="utf-8") as f:
                        self.data = json.load(f)
                self.data.setdefault("pushed_hashes", {})
                self.data.setdefault("last_results", {})
                self.data.setdefault("logs", [])
            except Exception:
                pass

    def save(self):
        with self._lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)

    def get_pushed_hash(self, name):
        with self._lock:
            return self.data["pushed_hashes"].get(name)

    def set_pushed_hash(self, name, h):
        with self._lock:
            self.data["pushed_hashes"][name] = h
            self.save()

    def set_result(self, name, result):
        with self._lock:
            self.data["last_results"][name] = result
            self.save()

    def get_result(self, name):
        with self._lock:
            return self.data["last_results"].get(name)

    def remove_name(self, name):
        """清理某个域名的推送哈希与结果记录"""
        with self._lock:
            self.data["pushed_hashes"].pop(name, None)
            self.data["last_results"].pop(name, None)
            self.save()

    def get_results(self):
        with self._lock:
            return deepcopy(self.data["last_results"])

    def add_log(self, level, message):
        """记录一条任务日志，保留最近 500 条"""
        import time
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
        }
        with self._lock:
            self.data["logs"].append(entry)
            self.data["logs"] = self.data["logs"][-500:]
            self.save()

    def get_logs(self, limit=200):
        with self._lock:
            return list(self.data["logs"])[-limit:][::-1]
