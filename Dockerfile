FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EHF_HOST=0.0.0.0 \
    EHF_PORT=8080

WORKDIR /srv

# The analyzer uses the Python standard library only — no pip install.
COPY app /srv/app

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2); sys.exit(0 if r.status==200 else 1)"

CMD ["python", "-m", "app.server"]
