// Safeline ACME - 前端交互
// 允许的写操作只有三种：新增域名（保存配置）、续期、删除域名；其余全部只读

function showResult(msg, ok) {
  const el = document.getElementById("result");
  if (!el) return;
  el.style.display = "block";
  el.className = "alert " + (ok ? "alert-ok" : "alert-error");
  el.textContent = (ok ? "✅ " : "❌ ") + msg;
}

// ---------- 配置页 ----------

function testSafeline() {
  const btn = event.target;
  btn.disabled = true;
  const out = document.getElementById("sl-test-result");
  out.textContent = "测试中...";
  fetch("/api/safeline/test", { method: "POST" })
    .then(r => r.json())
    .then(d => {
      out.textContent = d.ok ? "✅ " + d.message + " (版本 " + d.version + ")" : "❌ " + d.message;
      out.className = d.ok ? "ok" : "err";
    })
    .catch(e => { out.textContent = "❌ " + e; out.className = "err"; })
    .finally(() => { btn.disabled = false; });
}

function testCloudflare() {
  const btn = event.target;
  btn.disabled = true;
  const out = document.getElementById("cf-test-result");
  out.textContent = "测试中...";
  fetch("/api/cloudflare/test", { method: "POST" })
    .then(r => r.json())
    .then(d => {
      out.textContent = (d.ok ? "✅ " : "❌ ") + d.message;
      out.className = d.ok ? "ok" : "err";
    })
    .catch(e => { out.textContent = "❌ " + e; out.className = "err"; })
    .finally(() => { btn.disabled = false; });
}

function addCertRow() {
  const rows = document.getElementById("cert-rows");
  const div = document.createElement("div");
  div.className = "cert-row";
  div.innerHTML = `
    <input type="text" name="cert_name" placeholder="主域名（如 example.com）" class="w1"
           pattern="[a-zA-Z0-9][a-zA-Z0-9-]*(\\.[a-zA-Z0-9][a-zA-Z0-9-]*)+">
    <input type="text" name="cert_domains" placeholder="证书覆盖域名，逗号分隔（如 example.com,*.example.com）" class="w2">
    <input type="number" name="cert_safeline_id" placeholder="雷池证书ID(0=新建)" class="w3" value="0" min="0">
    <label class="checkbox"><input type="checkbox" name="cert_enabled" checked>启用</label>
    <button type="button" class="btn btn-danger btn-sm" onclick="removeCertRow(this)">移除本行</button>`;
  rows.appendChild(div);
}

function removeCertRow(btn) {
  btn.closest(".cert-row").remove();
}

// 保存配置：走 fetch，避免页面直接显示 JSON
document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("config-form");
  if (!form) return;
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    const res = document.getElementById("result");
    res.style.display = "block";
    res.className = "alert";
    res.textContent = "正在保存...";
    fetch("/config", { method: "POST", body: new FormData(form) })
      .then(r => r.json())
      .then(d => {
        if (d.ok) {
          res.className = "alert alert-ok";
          res.textContent = "✅ 配置已保存";
          setTimeout(() => location.reload(), 800);
        } else {
          res.className = "alert alert-error";
          res.textContent = "❌ 保存失败: " + d.message;
        }
      })
      .catch(err => {
        res.className = "alert alert-error";
        res.textContent = "❌ " + err;
      });
  });
});

// ---------- 总览页 ----------

function runAll(force) {
  const res = document.getElementById("run-all-result");
  res.style.display = "block";
  res.className = "alert";
  res.textContent = force ? "正在强制续期并推送，请稍候（可能需要几分钟）..." : "正在检查并续期，请稍候...";
  fetch("/api/run-all", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ force: force })
  })
    .then(r => r.json())
    .then(d => {
      if (!d.ok) { res.className = "alert alert-error"; res.textContent = "❌ 执行失败"; return; }
      let lines = ["执行结果："];
      d.results.forEach(x => lines.push(`- ${x.name || ''}: ${x.ok ? "✅ " : "❌ "} ${x.message}`));
      res.textContent = lines.join("\n");
      setTimeout(() => location.reload(), 1500);
    })
    .catch(e => { res.className = "alert alert-error"; res.textContent = "❌ " + e; });
}

// ---------- 证书管理页 ----------

function renewCert(name) {
  if (!confirm(`确定对 ${name} 申请/续期证书并推送到雷池吗？`)) return;
  showResult(`正在处理 ${name} ...`, true);
  fetch(`/api/certs/${encodeURIComponent(name)}/renew`, { method: "POST" })
    .then(r => r.json())
    .then(d => { showResult(d.message, d.ok); if (d.ok) setTimeout(() => location.reload(), 1500); })
    .catch(e => showResult(e, false));
}

function deleteCertEntry(name) {
  if (!confirm(`确定删除托管域名 ${name} 吗？\n将删除本地 acme.sh 证书并从托管列表移除。\n（雷池中已推送的证书不会被删除，需在雷池后台手动处理）`)) return;
  showResult(`正在删除 ${name} ...`, true);
  fetch(`/api/certs/${encodeURIComponent(name)}/delete`, { method: "POST" })
    .then(r => r.json())
    .then(d => { showResult(d.message, d.ok); if (d.ok) setTimeout(() => location.reload(), 1200); })
    .catch(e => showResult(e, false));
}

// ---------- 日志页 ----------

function refreshLogs() {
  fetch("/api/logs")
    .then(r => r.json())
    .then(logs => {
      const el = document.getElementById("log-view");
      el.textContent = logs.map(l => `[${l.time}] [${l.level}] ${l.message}`).join("\n");
    });
}