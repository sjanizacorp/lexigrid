FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt VERSION ./
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 lexigrid
COPY app ./app
COPY web ./web
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
COPY scripts ./scripts
COPY config ./config
RUN mkdir -p /app/logs && chown -R lexigrid:lexigrid /app/logs
USER 10001
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
