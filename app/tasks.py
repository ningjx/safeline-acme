"""核心任务逻辑：申请/续期证书 -> 推送/同步到雷池；以及后台定时调度"""
import hashlib
import os
import threading
import time

from .acme_client import AcmeClient, days_until, AcmeError
from .safeline import SafelineClient, SafelineError
from .secrets import get_cloudflare, get_safeline


class TaskRunner:
    def __init__(self, config, state, acme=None, log=None):
        self.config = config
        self.state = state
        self.acme = acme or AcmeClient()
        self._log = log or state.add_log
        self._lock = threading.Lock()    # 全局锁：只用于互斥「整轮调度」，不保护单个域名任务
        self._stop = threading.Event()
        self._wake = threading.Event()   # 配置保存后唤醒调度，立刻处理新域名
        self._thread = None
        self._last_run = None
        self._running = False
        # 按托管域名的可重入锁：同域名的手动续期/定时续期/删除互相串行，
        # 不同域名仍可并行（acme.sh 对同一域名并发操作会竞争证书目录与状态文件）
        self._domain_locks = {}
        self._domain_locks_guard = threading.Lock()

    # ---------- 日志 ----------

    def _info(self, msg):
        self._log("info", msg)

    def _error(self, msg):
        self._log("error", msg)

    # ---------- 工具 ----------

    def _safeline(self):
        """雷池凭据只从环境变量读取（见 secrets.py），绝不落盘"""
        sl = get_safeline()
        return SafelineClient(
            base_url=sl.get("base_url", ""),
            api_token=sl.get("api_token", ""),
            verify_ssl=bool(sl.get("verify_ssl", False)),
        )

    def _file_hash(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _domain_lock(self, name):
        """获取某托管域名的可重入锁。同域名任务互斥，不同域名互不影响。"""
        with self._domain_locks_guard:
            lock = self._domain_locks.get(name)
            if lock is None:
                lock = threading.RLock()
                self._domain_locks[name] = lock
            return lock

    def _drop_domain_lock(self, name):
        """域名被删除后清理其锁对象，避免配置反复增删时锁表无限增长"""
        with self._domain_locks_guard:
            self._domain_locks.pop(name, None)

    # ---------- 单个证书：申请/续期 + 推送 ----------

    def renew_and_push(self, cert, force=False):
        """对单个托管证书执行 申请/续期 -> 推送雷池。

        同一托管域名在任意路径（手动续期 / 后台调度 / run-all）下都串行执行，
        防止与 acme.sh 并发操作同一证书目录。返回 (ok, message, detail)。
        """
        with self._domain_lock(cert["name"]):
            return self._renew_and_push(cert, force=force)

    def _renew_and_push(self, cert, force=False):
        """renew_and_push 的实际执行体；调用方必须已持有该域名的 _domain_lock"""
        name = cert["name"]
        domains = cert.get("domains") or [name]
        cfg = self.config.get()
        acme_cfg = cfg["acme"]
        cf_cfg = get_cloudflare()   # 环境变量
        keylength = acme_cfg.get("keylength", "ec-256")
        server = acme_cfg.get("ca_server", "letsencrypt")
        email = acme_cfg.get("email", "")
        proxy = acme_cfg.get("proxy", "")
        safeline_id = cert.get("safeline_id")

        cf_ready = bool(cf_cfg.get("cf_token")) or bool(cf_cfg.get("cf_key") and cf_cfg.get("cf_email"))
        if not cf_ready:
            return False, "未配置 Cloudflare 凭据（CF_TOKEN 或 CF_KEY+CF_EMAIL）", {}
        if not email:
            return False, "未配置 ACME 账号邮箱", {}

        # 1. 检查是否已存在证书 & 是否需要续期
        fc_path, _ = self.acme.cert_files(name, keylength)
        need_issue = fc_path is None          # 从未签发过 -> 必须走 issue
        need_renew = force or need_issue
        domains_changed = False               # 配置域名列表与现有证书 SAN 不一致
        if fc_path:
            parsed = self.acme.cert_expiry(fc_path)
            days = days_until(parsed[0]) if parsed else None
            renew_days = cfg["schedule"].get("renew_days_before_expiry", 30)
            if days is not None and days < renew_days:
                need_renew = True
            # 域名变更检测：SAN 不一致时必须按新列表重新签发（否则永远拿不到新增的泛域名等）。
            # 必须精确比对（不剥 *. 前缀）：example.com 与 *.example.com 是不同的覆盖集合，
            # 否则「给只有 example.com 的证书新增 *.example.com」会被误判为一致而跳过。
            if not need_renew:
                actual = self.acme.cert_sans(fc_path)
                if actual is not None:
                    wanted = set(domains)
                    if actual != wanted:
                        domains_changed = True
                        need_renew = True

        # 2. 申请或续期
        try:
            if need_renew:
                if need_issue:
                    self._info(f"[{name}] 首次申请证书 (DNS: dns_cf, CA: {server}, 密钥: {keylength})")
                    self.acme.issue(name, domains, keylength, server, email, cf_cfg, proxy, force=False)
                elif domains_changed:
                    self._info(f"[{name}] 域名列表已变更（含新增泛域名等），按新列表重新签发")
                    # 变更 SAN 必须用 --issue 传新的完整 -d 列表 + --force（--renew 沿用旧列表）
                    self.acme.issue(name, domains, keylength, server, email, cf_cfg, proxy, force=True)
                else:
                    self._info(f"[{name}] 证书即将到期（{'手动强制' if force else '自动'}），开始续期")
                    self.acme.renew(name, server, cf_cfg, proxy, force=force)
            else:
                self._info(f"[{name}] 证书尚未到期，跳过续期")
        except AcmeError as e:
            self._error(f"[{name}] {'申请' if need_issue else '续期'}失败: {e}")
            return False, f"{'申请' if need_issue else '续期'}失败: " + str(e), {}

        # 3. 读取证书并推送
        return self.push_to_safeline(name, keylength, safeline_id)

    def push_to_safeline(self, name, keylength=None, safeline_id=None, force=False):
        """把 acme.sh 已签发的证书推送到雷池。

        默认仅在证书内容变化时推送（避免重复写入）。force=True 强制推送。
        """
        cfg = self.config.get()
        cert = self.config.get_cert(name)
        if cert is None:
            return False, f"托管证书 {name} 不存在", {}
        keylength = keylength or cfg["acme"].get("keylength", "ec-256")
        safeline_id = safeline_id if safeline_id is not None else cert.get("safeline_id")

        try:
            crt, key = self.acme.read_cert(name, keylength)
        except AcmeError as e:
            self._error(f"[{name}] 读取证书失败: {e}")
            return False, str(e), {}

        fc_path, _ = self.acme.cert_files(name, keylength)
        new_hash = self._file_hash(fc_path) if fc_path else hashlib.sha256(crt.encode()).hexdigest()
        prev_hash = self.state.get_pushed_hash(name)
        if prev_hash == new_hash and not force:
            self._info(f"[{name}] 证书未变化，跳过推送")
            return True, "证书未变化，跳过推送", {"pushed": False}

        # 推送
        sl = self._safeline()
        try:
            if safeline_id:
                new_id = sl.upsert_cert(safeline_id, crt, key)
                msg = f"已更新雷池证书 #{safeline_id}"
            else:
                new_id = sl.upsert_cert(0, crt, key)
                msg = f"已在雷池新建证书 #{new_id}（请到站点重新选择该证书）"
                # 把雷池返回的新 ID 回写配置：后续续签自动原地更新，不再新建重复证书
                try:
                    if int(new_id) > 0 and self.config.set_cert_safeline_id(name, new_id):
                        self._info(f"[{name}] 已将雷池证书 ID 回写为 #{new_id}")
                except (TypeError, ValueError):
                    pass
        except SafelineError as e:
            self._error(f"[{name}] 推送雷池失败: {e}")
            return False, "推送雷池失败: " + str(e), {}

        self.state.set_pushed_hash(name, new_hash)
        self._info(f"[{name}] {msg}")
        return True, msg, {"pushed": True, "safeline_id": new_id}

    # ---------- 调度 ----------

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._info("定时调度已启动")

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._info("定时调度已停止")

    def wake(self):
        """唤醒调度线程：保存配置后立即执行一次检查（无需等下一个周期）"""
        if self._thread and self._thread.is_alive():
            self._wake.set()

    def _loop(self):
        while not self._stop.is_set():
            # wake() 触发的（保存配置/手动触发）即使定时调度停用也要执行一次
            woken = self._wake.is_set()
            self._wake.clear()
            try:
                self.check_all(force=woken)
            except Exception as e:
                self._error(f"定时任务异常: {e}")
            # 等待下个周期；配置变化时由 wake() 提前唤醒
            cfg = self.config.get()
            interval = max(1, int(cfg["schedule"].get("check_interval_hours", 12))) * 3600
            self._wake.wait(interval)

    def check_all(self, force=False):
        """一次完整检查：对每个启用且配置了雷池的证书执行续期+推送

        force=True 时忽略「定时调度停用」开关（用于保存配置后的立即执行）
        """
        cfg = self.config.get()
        if not force and not cfg["schedule"].get("enabled", True):
            return
        sl = self._safeline()
        if not sl.configured:
            self._info("定时任务跳过：未配置雷池 API")
            return
        with self._lock:
            if self._running:
                return
            self._running = True
        try:
            self._last_run = time.strftime("%Y-%m-%d %H:%M:%S")
            self._info("开始定时检查...")
            for cert in cfg.get("certs", []):
                if not cert.get("enabled", True):
                    continue
                name = cert["name"]
                try:
                    ok, msg, _ = self.renew_and_push(cert)
                    self.state.set_result(name, {
                        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "ok": ok,
                        "message": msg,
                    })
                except Exception as e:
                    self._error(f"[{name}] 任务异常: {e}")
                    self.state.set_result(name, {
                        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "ok": False,
                        "message": str(e),
                    })
            self._info("定时检查完成")
        finally:
            self._running = False

    def run_all_now(self, force=False):
        """立即对全部启用的托管证书执行一次续期+推送（供页面按钮调用）"""
        with self._lock:
            if self._running:
                return [{"name": "", "ok": False, "message": "已有任务在执行中，请稍后再试"}]
            self._running = True
        try:
            cfg = self.config.get()
            results = []
            for cert in cfg.get("certs", []):
                if not cert.get("enabled", True):
                    continue
                ok, msg, detail = self.renew_and_push(cert, force=force)
                self.state.set_result(cert["name"], {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "ok": ok,
                    "message": msg,
                })
                results.append({"name": cert["name"], "ok": ok, "message": msg, **detail})
            return results
        finally:
            self._running = False

    # ---------- 删除域名（托管条目 + acme.sh 证书文件） ----------

    def delete_cert(self, name):
        """删除一个托管域名：移除配置条目，并删除 acme.sh 本地证书。

        注意：不会删除雷池中已推送的证书（需在雷池后台手动删除）。
        """
        with self._domain_lock(name):
            from .utils import is_valid_cert_name
            if not is_valid_cert_name(name):
                return False, "非法的域名格式"
            cert = self.config.get_cert(name)
            if cert is None:
                return False, f"托管证书 {name} 不存在"

            # 1. 删除 acme.sh 本地证书（含 conf 与证书文件）；从未签发过则直接跳过
            keylength = self.config.get()["acme"].get("keylength", "ec-256")
            fc, _ = self.acme.cert_files(name, keylength)
            acme_error = None
            if fc:
                try:
                    self.acme.remove(name)
                    self._info(f"[{name}] 已删除 acme.sh 本地证书")
                except AcmeError as e:
                    acme_error = str(e)
                    self._error(f"[{name}] 删除 acme.sh 证书失败: {e}")
            else:
                self._info(f"[{name}] 本地无证书文件，跳过 acme.sh 删除")

            # 2. 从配置移除
            self.config.remove_cert(name)

            # 3. 清理运行状态（推送哈希与结果）与该域名的锁对象
            self.state.remove_name(name)
            self._drop_domain_lock(name)

            if acme_error:
                return False, f"配置已移除，但删除 acme.sh 证书失败: {acme_error}"
            self._info(f"[{name}] 托管域名已删除")
            return True, f"已删除托管域名 {name}"

    # ---------- 状态 ----------

    def status(self):
        """汇总状态，供页面展示"""
        cfg = self.config.get()
        acme_cfg = cfg["acme"]
        keylength = acme_cfg.get("keylength", "ec-256")
        rows = []
        for cert in cfg.get("certs", []):
            name = cert["name"]
            fc, _ = self.acme.cert_files(name, keylength)
            expiry = None
            days = None
            if fc:
                parsed = self.acme.cert_expiry(fc)
                if parsed:
                    expiry = parsed[0].strftime("%Y-%m-%d %H:%M:%S")
                    days = days_until(parsed[0])
            result = self.state.get_result(name) or {}
            rows.append({
                "name": name,
                "domains": cert.get("domains", []),
                "safeline_id": cert.get("safeline_id"),
                "enabled": cert.get("enabled", True),
                "has_cert": bool(fc),
                "expiry": expiry,
                "days_left": days,
                "last_result": result,
            })
        return {
            "scheduler_running": bool(self._thread and self._thread.is_alive()),
            "last_run": self._last_run,
            "running": self._running,
            "certs": rows,
        }
