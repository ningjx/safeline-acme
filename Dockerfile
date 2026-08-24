# Safeline ACME 证书助手
# 使用 acme.sh（官方 ACME 客户端）+ Cloudflare DNS 验证申请证书，并通过雷池 OPEN API 同步证书
FROM python:3.12-slim

LABEL maintainer="safeline-acme"

# acme.sh 运行需要 curl/openssl；时区设置为 Asia/Shanghai 便于日志
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        openssl \
        ca-certificates \
        tzdata \
    && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 应用源码
COPY app/ ./app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 数据挂载目录（config.json / state.json / acme.sh 数据）
RUN mkdir -p /data

ENV ACME_HOME=/data/acme.sh \
    CONFIG_PATH=/data/config.json \
    STATE_PATH=/data/state.json \
    PORT=8080

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
