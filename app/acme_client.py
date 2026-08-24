"""acme.sh 封装（官方 ACME 客户端 https://github.com/acmesh-official/acme.sh）

使用 DNS 验证（Cloudflare dns_cf 插件）申请证书，规避 HTTP-01 被防火墙拦截的问题。
官方文档参考：
  - 安装:   https://github.com/acmesh-official/acme.sh/wiki/%E8%AF%B4%E6%98%8E
  - DNS API: https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf
"""
import os
import re
import subprocess
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .utils import is_valid_cert_name, is_valid_domain

# acme.sh 的脚本与数据都放在挂载卷上，容器重建不丢失
DEFAULT_ACME_HOME = os.environ.get("ACME_HOME", "/data/acme.sh")


class AcmeError(Exception):
    pass


class AcmeClient:
    def __init__(self, acme_home=DEFAULT_ACME_HOME):
        self.acme_home = acme_home
        self.script = os.path.join(acme_home, "acme.sh")

    # ---------- 基础 ----------

    @property
    def installed(self):
        return os.path.exists(self.script)

    def _build_env(self, cf_cfg, proxy=""):
        env = dict(os.environ)
        env["LE_CONFIG_HOME"] = self.acme_home
        env["HOME"] = "/root"
        # dns_cf 官方支持的三种凭据方案（见 secrets.py）
        if cf_cfg.get("cf_token"):
            env["CF_Token"] = cf_cfg["cf_token"]
        if cf_cfg.get("cf_account_id"):
            env["CF_Account_ID"] = cf_cfg["cf_account_id"]
        if cf_cfg.get("cf_zone_id"):
            env["CF_Zone_ID"] = cf_cfg["cf_zone_id"]
        if cf_cfg.get("cf_key"):
            env["CF_Key"] = cf_cfg["cf_key"]
        if cf_cfg.get("cf_email"):
            env["CF_Email"] = cf_cfg["cf_email"]
        if proxy:
            env["http_proxy"] = proxy
            env["https_proxy"] = proxy
        return env

    def run(self, args, env=None, timeout=600):
        """执行 acme.sh，返回 (returncode, output)"""
        if not self.installed:
            raise AcmeError(f"acme.sh 未安装（预期路径 {self.script}），请重新构建容器")
        if env is None:
            # 始终指定 LE_CONFIG_HOME，避免 acme.sh 落到默认 ~/.acme.sh
            env = self._build_env({}, "")
        cmd = [self.script] + args
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")

    # ---------- 安装 / 默认 CA ----------

    def install(self, email=""):
        """通过官方脚本安装 acme.sh

        参考官方文档 https://github.com/acmesh-official/acme.sh/wiki/How-to-install
        使用 --home/--config-home 将脚本与数据都放在挂载卷（容器重建不丢），
        使用 --nocron 关闭 acme.sh 自带 cron（由本应用负责调度）。
        """
        if self.installed:
            return
        os.makedirs(self.acme_home, exist_ok=True)
        # 1. 下载官方脚本
        dl = subprocess.run(
            ["curl", "-fsSL",
             "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh",
             "-o", self.script],
            capture_output=True, text=True, timeout=300,
        )
        if dl.returncode != 0:
            raise AcmeError(f"下载 acme.sh 失败: {dl.stderr}")
        os.chmod(self.script, 0o700)
        # 2. 安装（记录 config-home、关闭 cron）
        args = ["--install", "--home", self.acme_home,
                "--config-home", self.acme_home, "--nocron"]
        if email:
            args += ["--accountemail", email]
        proc = subprocess.run(
            [self.script] + args, capture_output=True, text=True, timeout=300,
            env=self._build_env({}, ""),
        )
        if proc.returncode != 0:
            raise AcmeError(f"安装 acme.sh 失败: {proc.stdout} {proc.stderr}")

    def set_default_ca(self, server):
        """设置默认 CA，如 letsencrypt / zerossl"""
        if not server:
            return
        rc, out = self.run(["--set-default-ca", "--server", server])
        if rc != 0:
            raise AcmeError(f"设置默认 CA 失败: {out}")

    # ---------- 签发 / 续期 ----------

    def issue(self, main_domain, domains, keylength, server, email, cf_cfg, proxy="", force=False):
        """申请（或强制重新申请）证书

        domains: 证书覆盖的全部域名（第一个为 主域名）
        force: True 时加 --force 强制重新签发
        """
        if not is_valid_cert_name(main_domain):
            raise AcmeError("非法的域名格式")
        for d in domains or []:
            if not is_valid_domain(d):
                raise AcmeError(f"非法的域名格式: {d[:50]}")
        args = ["--issue", "--dns", "dns_cf", "-d", main_domain]
        for d in domains:
            if d != main_domain:
                args += ["-d", d]
        args += ["--keylength", keylength]
        if server:
            args += ["--server", server]
        if email:
            args += ["--email", email]
        if force:
            args += ["--force"]
        env = self._build_env(cf_cfg, proxy)
        rc, out = self.run(args, env=env)
        if rc != 0:
            raise AcmeError(f"申请证书失败:\n{out[-4000:]}")
        return out

    def renew(self, main_domain, server, cf_cfg, proxy="", force=False):
        """续期单个证书"""
        if not is_valid_cert_name(main_domain):
            raise AcmeError("非法的域名格式")
        args = ["--renew", "-d", main_domain]
        if server:
            args += ["--server", server]
        if force:
            args += ["--force"]
        env = self._build_env(cf_cfg, proxy)
        rc, out = self.run(args, env=env)
        if rc != 0:
            raise AcmeError(f"续期证书失败:\n{out[-4000:]}")
        return out

    def cron(self, cf_cfg, proxy=""):
        """按 acme.sh 自身的规则检测并续期所有到期证书"""
        env = self._build_env(cf_cfg, proxy)
        rc, out = self.run(["--cron"], env=env)
        return rc, out

    # ---------- 证书信息 / 文件 ----------

    def info(self, main_domain):
        """解析 acme.sh --info -d <domain> 输出"""
        try:
            rc, out = self.run(["--info", "-d", main_domain])
        except AcmeError:
            return {}
        info = {}
        if rc != 0:
            return info
        for line in out.splitlines():
            m = re.match(r"^(\w+)=(.*)$", line.strip())
            if m:
                info[m.group(1)] = m.group(2)
        return info

    def cert_dir(self, main_domain, keylength):
        """证书目录：ECC 证书存放在 <domain>_ecc 子目录

        做域名合法性校验（防路径穿越：域名不允许包含 / \\ .. 等）
        """
        if not is_valid_cert_name(main_domain):
            raise AcmeError("非法的域名格式")
        base = main_domain
        if keylength and keylength.startswith("ec-"):
            base = f"{main_domain}_ecc"
        return os.path.join(self.acme_home, base)

    def cert_files(self, main_domain, keylength):
        """返回 (fullchain路径, key路径)。文件不存在时返回 (None, None)"""
        try:
            d = self.cert_dir(main_domain, keylength)
        except AcmeError:
            return None, None
        fullchain = os.path.join(d, "fullchain.cer")
        key = os.path.join(d, f"{main_domain}.key")
        if os.path.exists(fullchain) and os.path.exists(key):
            return fullchain, key
        # 兼容：部分旧版本使用 .crt / .pem 后缀
        for fname in (f"{main_domain}.crt", "cert.pem", "fullchain.pem"):
            fc = os.path.join(d, fname)
            if os.path.exists(fc):
                return fc, key
        return None, None

    def read_cert(self, main_domain, keylength):
        """读取证书内容，返回 (fullchain_text, key_text)，失败抛 AcmeError"""
        if not is_valid_cert_name(main_domain):
            raise AcmeError("非法的域名格式")
        fc, key = self.cert_files(main_domain, keylength)
        if not fc or not key:
            raise AcmeError(f"未找到 {main_domain} 的证书文件，请先申请证书")
        with open(fc, "r", encoding="utf-8") as f:
            crt = f.read()
        with open(key, "r", encoding="utf-8") as f:
            key_text = f.read()
        return crt, key_text

    def remove(self, main_domain):
        """彻底删除一个 acme.sh 证书（conf 与证书文件），对应 acme.sh --remove -d"""
        if not is_valid_cert_name(main_domain):
            raise AcmeError("非法的域名格式")
        env = self._build_env({}, "")
        rc, out = self.run(["--remove", "-d", main_domain], env=env)
        if rc != 0:
            raise AcmeError(f"删除证书失败: {out[-2000:]}")

    def cert_expiry(self, cert_path):
        """解析证书到期时间，返回 (expiry_dt, not_before_dt) 或 None"""
        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            return cert.not_valid_after_utc, cert.not_valid_before_utc
        except Exception:
            return None

    def cert_sans(self, cert_path):
        """解析证书 SAN 中的 DNS 域名集合（不含通配符前缀），失败返回 None

        用于比对「配置的域名列表」与「现有证书实际覆盖的域名」是否一致
        """
        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return {name.lstrip("*.") for name in ext.value.get_values_for_type(x509.DNSName)}
        except Exception:
            return None

    def cert_mtime(self, main_domain, keylength):
        fc, _ = self.cert_files(main_domain, keylength)
        if fc:
            return os.path.getmtime(fc)
        return 0

    # ---------- 列表 ----------

    def list_certs(self):
        """扫描 acme.sh 目录，列出所有托管证书信息"""
        certs = []
        if not os.path.isdir(self.acme_home):
            return certs
        for entry in os.listdir(self.acme_home):
            # entry 形如 example.com 或 example.com_ecc（acme.sh 存放证书的目录）
            if entry.startswith(".") or not os.path.isdir(os.path.join(self.acme_home, entry)):
                continue
            main_domain = entry[:-4] if entry.endswith("_ecc") else entry
            # acme.sh 的 domain conf 文件名为主域名（如 example.com/example.com.conf）
            conf = os.path.join(self.acme_home, entry, f"{main_domain}.conf")
            if not os.path.isfile(conf):
                continue
            keylength = "ec-256" if entry.endswith("_ecc") else "2048"
            info = self.info(main_domain)
            fc, key = self.cert_files(main_domain, keylength)
            expiry = None
            if fc:
                parsed = self.cert_expiry(fc)
                expiry = parsed[0] if parsed else None
            certs.append({
                "name": main_domain,
                "ecc": bool(entry.endswith("_ecc")),
                "dir": entry,
                "next_renew": info.get("Le_NextRenewTimeStr", ""),
                "created": info.get("Le_CertCreateTimeStr", ""),
                "expiry": expiry.isoformat() if expiry else "",
                "real_path": fc or "",
            })
        return certs


def days_until(expiry_dt):
    """距到期天数（负数为已过期）"""
    if not expiry_dt:
        return None
    now = datetime.now(timezone.utc)
    return (expiry_dt - now).days
