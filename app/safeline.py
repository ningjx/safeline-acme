"""雷池 SafeLine OPEN API 客户端

基于官方 swagger 文档 (doc.json)：
  GET    /api/open/cert      列出证书
  POST   /api/open/cert      新增/更新证书（upsert）
  GET    /api/open/cert/{id} 证书详情
  DELETE /api/open/cert/{id} 删除证书
  GET    /api/open/system    系统信息

认证方式：请求头 X-SLCE-API-TOKEN: <token>
（参考官方文档 https://help.waf-ce.chaitin.cn 与官方仓库
 https://github.com/chaitin/SafeLine/discussions/1148）

证书类型：type=2 手动证书（manual: {crt, key}）
响应格式：{"data": ..., "err": null|string, "msg": ...}
"""
import json
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SafelineError(Exception):
    pass


class SafelineClient:
    def __init__(self, base_url, api_token, verify_ssl=False, timeout=15):
        self.base_url = (base_url or "").rstrip("/")
        self.api_token = api_token or ""
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl

    @property
    def configured(self):
        return bool(self.base_url and self.api_token)

    def _headers(self):
        return {
            "X-SLCE-API-TOKEN": self.api_token,
            "Content-Type": "application/json",
        }

    def _request(self, method, path, json_body=None):
        if not self.configured:
            raise SafelineError("雷池 API 地址或 Token 未配置")
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(
                method, url, headers=self._headers(),
                json=json_body, timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            raise SafelineError(f"请求雷池失败: {e}") from e
        try:
            body = resp.json()
        except ValueError:
            raise SafelineError(f"雷池返回非 JSON 内容 (HTTP {resp.status_code})")
        if body.get("err"):
            raise SafelineError(f"雷池返回错误: {body['err']} ({body.get('msg','')})")
        return body.get("data")

    # ---------- 证书 ----------

    def list_certs(self):
        """列出所有证书，返回 api.ListCertItem 数组"""
        return self._request("GET", "/api/open/cert") or {}

    def get_cert(self, cert_id):
        """证书详情"""
        return self._request("GET", f"/api/open/cert/{int(cert_id)}")

    def upsert_cert(self, cert_id, crt, key):
        """新增/更新证书。

        cert_id: 目标证书 ID。填入雷池中已存在的 ID 即为"更新"（站点继续引用，不中断）；
                 填 0 表示新建（自增 ID，需在站点上重新选择证书）。
        返回: 新证书 ID（更新时返回原 ID）
        """
        payload = {
            "manual": {
                "crt": crt,
                "key": key,
            },
            "type": 2,          # 2 = 手动证书
            "id": int(cert_id or 0),
        }
        return self._request("POST", "/api/open/cert", json_body=payload)

    def delete_cert(self, cert_id):
        """删除证书。证书被站点引用时会返回错误。"""
        return self._request("DELETE", f"/api/open/cert/{int(cert_id)}")

    # ---------- 系统 ----------

    def system_info(self):
        return self._request("GET", "/api/open/system")

    def test_connection(self):
        """测试连通性，返回系统信息"""
        info = self.system_info()
        return info
