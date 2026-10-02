FROM python:3.11-slim

WORKDIR /app

# 仅使用标准库，无第三方依赖
COPY app/ ./app/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD python3 -c "import json,urllib.request,sys; \
r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3); \
sys.exit(0 if r.status==200 and json.load(r)['status']=='ok' else 1)"

CMD ["python3", "app/server.py"]
