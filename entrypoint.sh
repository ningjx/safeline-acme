#!/bin/sh
# 容器启动入口：确保 acme.sh 已安装（数据目录在挂载卷上），再启动 Web 服务
set -e

ACME_HOME="${ACME_HOME:-/data/acme.sh}"

# 确保数据目录存在（挂载卷）
mkdir -p "$ACME_HOME"

# 首次启动时安装 acme.sh（脚本与数据均保存在挂载卷，容器重建不丢）
# 参考官方 Docker 镜像的安装方式：
#   - --install-online 会一并下载 dnsapi/deploy 等插件（--dns dns_cf 需要 dnsapi/dns_cf.sh）
#   - --nocron 关闭 acme.sh 自带 cron（由本应用负责调度）
if [ ! -f "$ACME_HOME/acme.sh" ]; then
  echo "[entrypoint] 未检测到 acme.sh，开始安装..."
  STAGE=/tmp/acme-stage
  mkdir -p "$STAGE"
  curl -fsSL "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh" \
    -o "$STAGE/acme.sh"
  cd "$STAGE"
  sh acme.sh --install-online --home "$ACME_HOME" --config-home "$ACME_HOME" --nocron
  cd /
  rm -rf "$STAGE"
  echo "[entrypoint] acme.sh 安装完成"
fi

echo "[entrypoint] 启动 Safeline ACME Web 服务..."
cd /app && exec python -m app.main