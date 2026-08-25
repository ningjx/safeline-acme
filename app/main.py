"""safeline-acme Web 管理界面 + 后台任务入口

安全模型：
- 敏感凭据（雷池 API Token、Cloudflare 密钥）只从环境变量读取（secrets.py），
  Web 无法查看/修改，也绝不写入磁盘配置
- Web 为局域网只读展示，仅允许三个写操作：新增域名（保存配置）、续期、删除域名
- 所有域名类输入均做严格格式校验，杜绝路径穿越读取容器内文件
"""
import hmac
import os
import threading
import time

from flask import Flask, render_template, request, jsonify, Response

from .config import ConfigManager, StateManager
from .acme_client import AcmeClient
from .cloudflare import test_connection as test_cloudflare_connection
from .safeline import SafelineClient, SafelineError
from .secrets import get_safeline, get_cloudflare, cloudflare_configured, secrets_configured
from .tasks import TaskRunner
from .utils import is_valid_cert_name, is_valid_domain, sanitize_domains

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "safeline-acme")

# ---------- 可选 Web 鉴权（HTTP Basic Auth） ----------
# 默认不开启，保持局域网免登录体验；设置 WEB_AUTH_ENABLED=1 后，除 /health、/ready
# 之外的所有页面与 API 都要求 Basic Auth（凭据走环境变量，不落盘）。
# 注意：Basic Auth 开启后同源页面也会自动带凭据访问 /static 资源，属正常行为。
WEB_AUTH_ENABLED = os.environ.get("WEB_AUTH_ENABLED", "0") == "1"
WEB_AUTH_USERNAME = os.environ.get("WEB_AUTH_USERNAME", "")
WEB_AUTH_PASSWORD = os.environ.get("WEB_AUTH_PASSWORD", "")
_AUTH_FREE_PATHS = {"/health", "/ready"}


def _auth_ok(user, password):
    """常数时间比对用户名/密码，避免时序侧信道"""
    if not (WEB_AUTH_USERNAME and WEB_AUTH_PASSWORD):
        return False
    return (hmac.compare_digest(user or "", WEB_AUTH_USERNAME)
            and hmac.compare_digest(password or "", WEB_AUTH_PASSWORD))


@app.before_request
def _check_web_auth():
    """启用鉴权时，除健康检查路径外所有请求都要求 Basic Auth"""
    if not WEB_AUTH_ENABLED:
        return None
    if request.path in _AUTH_FREE_PATHS:
        return None
    auth = request.authorization
    if not auth or not _auth_ok(auth.username, auth.password):
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="Safeline ACME"'},
        )
    return None


config = ConfigManager()
state = StateManager()
acme = AcmeClient()
runner = TaskRunner(config, state, acme=acme)


@app.context_processor
def inject_globals():
    """把配置与凭据状态注入所有模板"""
    cfg = config.get()
    sl = get_safeline()
    return {
        "cfg": cfg,
        "sl_env": sl,
        "credentials_ok": secrets_configured(),
    }


# ---------- 健康检查（给 Docker healthcheck / Uptime Kuma / K8s 探针使用） ----------
# 这两个接口始终免鉴权（见 _AUTH_FREE_PATHS），且不含任何敏感信息

@app.route("/health")
def health():
    """存活探针：进程活着即返回 ok"""
    return jsonify({"status": "ok"})


@app.route("/ready")
def ready():
    """就绪探针：返回组件配置状态供观测。

    注意「未配置」也算 ready——探针缺配置就报不健康会导致容器反复重启，
    是否配置齐全应由监控侧（日志/告警）判断，而不是让容器进入 crash loop。
    """
    cfg = config.get()
    sl = get_safeline()
    return jsonify({
        "status": "ok",
        "acme_installed": acme.installed,
        "safeline_configured": bool(sl.get("base_url") and sl.get("api_token")),
        "cloudflare_configured": cloudflare_configured(),
        "schedule_enabled": cfg["schedule"].get("enabled", True),
    })


# ---------- 状态缓存（主页秒开：远程检测放在后台线程，60 秒内复用结果） ----------

STATUS_CACHE_TTL = 60            # 秒
_status_cache = {"safeline": {"data": None, "check_time": 0},
                 "cloudflare": {"data": None, "check_time": 0}}
_status_lock = threading.Lock()
_refreshing = threading.Event()


def _safeline_client():
    sl = get_safeline()
    return SafelineClient(
        base_url=sl.get("base_url", ""),
        api_token=sl.get("api_token", ""),
        verify_ssl=bool(sl.get("verify_ssl", False)),
    )


def _detect_safeline():
    sl = _safeline_client()
    status = {"ok": False, "message": "未配置", "version": "", "configured": False}
    if sl.configured:
        status["configured"] = True
        try:
            info = sl.test_connection()
            status.update({"ok": True, "message": "连接正常", "version": info.get("version", "")})
        except SafelineError as e:
            status.update({"ok": False, "message": str(e)})
    return status


def _detect_cloudflare():
    cf = get_cloudflare()
    status = {
        "configured": bool(cf.get("cf_token") or (cf.get("cf_key") and cf.get("cf_email"))),
        "ok": False,
        "message": "未配置",
    }
    if status["configured"]:
        ok, msg = test_cloudflare_connection(config.get()["acme"].get("proxy", ""))
        status.update({"ok": ok, "message": msg})
    return status


def _refresh_status_async():
    """后台线程刷新雷池/Cloudflare 检测结果（页面渲染绝不阻塞等待网络）"""
    if _refreshing.is_set():
        return
    _refreshing.set()

    def _run():
        try:
            for key, fn in (("safeline", _detect_safeline), ("cloudflare", _detect_cloudflare)):
                try:
                    data = fn()
                    with _status_lock:
                        _status_cache[key] = {"data": data, "check_time": time.time()}
                except Exception:
                    pass
        finally:
            _refreshing.clear()

    threading.Thread(target=_run, daemon=True).start()


def _status_with_age(key):
    """取缓存状态并附「多久前检测」提示；过期则触发后台刷新"""
    with _status_lock:
        entry = dict(_status_cache[key])
    data, check_time = entry["data"], entry["check_time"]
    age = None
    if data is not None:
        age = int(time.time() - check_time)
    if data is None or age >= STATUS_CACHE_TTL:
        _refresh_status_async()
    status = data if data is not None else {
        "ok": False, "message": "正在后台检测，稍后刷新页面可见结果", "configured": False,
    }
    status = dict(status)
    status["age"] = age
    return status


# ---------- 页面（全部只读展示） ----------

@app.route("/")
def index():
    cfg = config.get()
    return render_template(
        "index.html",
        cfg=cfg,
        sl_status=_status_with_age("safeline"),
        cf_status=_status_with_age("cloudflare"),
        acme_installed=acme.installed,
        certs_status=runner.status(),
    )


@app.route("/config", methods=["GET", "POST"])
def config_page():
    """仅保存非敏感配置（ACME、调度、托管域名列表）。凭据永远来自环境变量。"""
    if request.method == "POST":
        certs = []
        names = request.form.getlist("cert_name")
        domain_lists = request.form.getlist("cert_domains")
        safeline_ids = request.form.getlist("cert_safeline_id")
        enables = request.form.getlist("cert_enabled")
        for i, name in enumerate(names):
            name = (name or "").strip()
            if not is_valid_cert_name(name):
                continue    # 非法域名直接拒绝，防路径穿越
            domains = sanitize_domains(domain_lists[i] if i < len(domain_lists) else "")
            if name not in domains:
                domains.insert(0, name)
            rid = (safeline_ids[i] if i < len(safeline_ids) else "0") or "0"
            if not rid.lstrip("-").isdigit():
                continue
            certs.append({
                "name": name,
                "domains": domains,
                "safeline_id": int(rid),
                "enabled": (enables[i] == "on") if i < len(enables) else True,
            })
        new_cfg = {
            "acme": {
                "email": (request.form.get("acme_email") or "").strip(),
                "ca_server": (request.form.get("acme_ca_server") or "letsencrypt").strip(),
                "keylength": (request.form.get("acme_keylength") or "ec-256").strip(),
                "proxy": (request.form.get("acme_proxy") or "").strip(),
            },
            "schedule": {
                "enabled": request.form.get("schedule_enabled") == "on",
                "check_interval_hours": min(24 * 7, max(1, int(request.form.get("schedule_interval", 12) or 12))),
                "renew_days_before_expiry": min(90, max(1, int(request.form.get("schedule_renew_days", 30) or 30))),
            },
            "certs": certs,
        }
        config.update(new_cfg)   # 白名单过滤在 ConfigManager._sanitize 内
        state.add_log("info", "配置已保存，正在后台申请未签发的证书...")
        runner.wake()            # 立刻唤醒后台任务处理新域名，无需等下一个周期
        return jsonify({"ok": True})
    return render_template("config.html", cfg=config.get())


@app.route("/certs")
def certs_page():
    managed = runner.status()
    sl = _safeline_client()
    sl_certs = []
    sl_error = ""
    if sl.configured:
        try:
            data = sl.list_certs()
            sl_certs = (data or {}).get("nodes", [])
        except SafelineError as e:
            sl_error = str(e)
    return render_template("certs.html", managed=managed, sl_certs=sl_certs, sl_error=sl_error)


@app.route("/logs")
def logs_page():
    return render_template("logs.html", logs=state.get_logs(300))


# ---------- API ----------
# 允许的写操作只有三种：新增域名（POST /config）、续期（renew / run-all）、删除域名（delete）
# 其余接口均为只读；不存在任何读取文件内容 / 环境变量的接口

@app.route("/api/status")
def api_status():
    return jsonify(runner.status())


@app.route("/api/safeline/test", methods=["POST"])
def api_safeline_test():
    """只读：测试雷池连通性（凭据来自环境变量，不回显任何敏感值）"""
    sl = _safeline_client()
    if not sl.configured:
        return jsonify({"ok": False, "message": "未在环境变量中配置 SAFELINE_BASE_URL / SAFELINE_API_TOKEN"})
    try:
        info = sl.test_connection()
        return jsonify({"ok": True, "message": "连接正常", "version": info.get("version", "")})
    except SafelineError as e:
        return jsonify({"ok": False, "message": str(e)})


@app.route("/api/cloudflare/test", methods=["POST"])
def api_cloudflare_test():
    """只读：测试 Cloudflare 凭据有效性与该 Token 的 Zone 访问权限（不回显密钥）"""
    proxy = config.get()["acme"].get("proxy", "")
    ok, msg = test_cloudflare_connection(proxy)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/logs")
def api_logs():
    return jsonify(state.get_logs(300))


def _guard_name(name):
    """域名参数双重校验：既是合法域名格式，也必须是已配置的托管证书"""
    if not is_valid_cert_name(name):
        return None, "非法的域名格式"
    cert = config.get_cert(name)
    if cert is None:
        return None, f"托管证书 {name} 不存在"
    return cert, None


@app.route("/api/certs/<name>/renew", methods=["POST"])
def api_renew(name):
    """续期并推送雷池（写操作之一）"""
    cert, err = _guard_name(name)
    if err:
        return jsonify({"ok": False, "message": err}), 404
    ok, msg, detail = runner.renew_and_push(cert, force=True)
    return jsonify({"ok": ok, "message": msg, **detail})


@app.route("/api/certs/<name>/delete", methods=["POST"])
def api_delete(name):
    """删除托管域名（写操作之二：移除配置条目与 acme.sh 本地证书）"""
    cert, err = _guard_name(name)
    if err:
        return jsonify({"ok": False, "message": err}), 404
    ok, msg = runner.delete_cert(name)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/run-all", methods=["POST"])
def api_run_all():
    """对全部启用域名执行一次续期+推送（写操作之三）"""
    force = request.json.get("force", False) if request.is_json else False
    results = runner.run_all_now(force=force)
    return jsonify({"ok": True, "results": results})


if __name__ == "__main__":
    runner.start()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, threaded=True)