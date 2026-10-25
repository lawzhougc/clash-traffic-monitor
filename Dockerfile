FROM python:3.11-alpine

WORKDIR /app

# 安装时区支持
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

# 安装运行依赖
RUN pip install --no-cache-dir fastapi uvicorn websockets

# 复制代码与离线 GeoIP 数据库
COPY server.py /app/server.py
COPY index.html /app/index.html
COPY GeoLite2-Country.mmdb /app/GeoLite2-Country.mmdb

EXPOSE 8099

CMD ["python", "/app/server.py"]
